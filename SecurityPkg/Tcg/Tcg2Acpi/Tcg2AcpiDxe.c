#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Library/PcdLib.h>
#include <Library/DxeServicesLib.h>
#include <Protocol/Tcg2Protocol.h>
#include <Protocol/AcpiTable.h>
#include <Protocol/AcpiSystemDescriptionTable.h>
#include <IndustryStandard/Tpm2Acpi.h>

#define TPM_BASE_ADDRESS 0x7ddf0000
#define TPM_SMC_ID 0x8400eded

#pragma pack (1)
typedef struct {
  EFI_ACPI_DESCRIPTION_HEADER Header;
  // Flags field is replaced in version 4 and above
  //    BIT0~15:  PlatformClass      This field is only valid for version 4 and above
  //    BIT16~31: Reserved
  UINT32                      Flags;
  UINT64                      AddressOfControlArea;
  UINT32                      StartMethod;
  UINT32                      Interrupt;
  UINT32                      Flags2;
  UINT32                      SmcFunctionId;
  UINT32                      TpmLogAreaLength;
  UINT64                      TpmLogPhysicalAddress;
} EFI_TPM2_ACPI_TABLE_SMC;
#pragma pack ()

EFI_TPM2_ACPI_TABLE_SMC  mTpm2AcpiTemplate = {
  {
    EFI_ACPI_5_0_TRUSTED_COMPUTING_PLATFORM_2_TABLE_SIGNATURE,
    sizeof (mTpm2AcpiTemplate),
    EFI_TPM2_ACPI_TABLE_REVISION,
  },
  1,
  TPM_BASE_ADDRESS + 0x40,
  EFI_TPM2_ACPI_TABLE_START_METHOD_COMMAND_RESPONSE_BUFFER_INTERFACE_WITH_SMC,
  0,
  0,
  TPM_SMC_ID,
  0,
  0,
};


STATIC
EFI_STATUS
Tcg2AcpiPublishSsdt (
  VOID
  )
{
  EFI_STATUS                     Status;
  EFI_ACPI_DESCRIPTION_HEADER    *Table;
  UINTN                          SectionInstance;
  UINTN                          TableSize;
  UINTN                          TableKey;
  EFI_ACPI_TABLE_PROTOCOL        *AcpiTableProtocol = NULL;

  Status          = EFI_SUCCESS;
  SectionInstance = 0;

  Status = gBS->LocateProtocol (
                  &gEfiAcpiTableProtocolGuid,
                  NULL,
                  (VOID **)&AcpiTableProtocol
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: ACPI protocol not found\n", __func__));
    return EFI_NOT_FOUND;
  }

  while (TRUE) {
    Status = GetSectionFromFv (
               &gEfiCallerIdGuid,
               EFI_SECTION_RAW,
               SectionInstance,
               (VOID **) &Table,
               &TableSize
               );
    if (EFI_ERROR (Status)) {
      break;
    }

    if (Table->OemTableId == SIGNATURE_64 ('T', 'p', 'm', 'T', 'a', 'b', 'l', 'e')) {
      Status = AcpiTableProtocol->InstallAcpiTable (
                                     AcpiTableProtocol,
                                     Table,
                                     TableSize,
                                     &TableKey
                                     );
      ASSERT_EFI_ERROR (Status);
      DEBUG((DEBUG_ERROR, "%a: Installed TPM SSDT table!\n", __func__));

      FreePool (Table);
      return Status;
    } else {
      FreePool (Table);
      SectionInstance++;
    }
  }

  return Status;
}

STATIC
EFI_STATUS
Tcg2AcpiPublishTpm (
  VOID
  )
{
  EFI_ACPI_TABLE_PROTOCOL *AcpiTableProtocol;
  EFI_TCG2_PROTOCOL *Tcg2Protocol;
  EFI_PHYSICAL_ADDRESS EventLogLocation, EventLogLastEntry;
  EFI_PHYSICAL_ADDRESS CrbBase = TPM_BASE_ADDRESS;
  BOOLEAN EventLogTruncated;
  EFI_STATUS Status;
  UINT64 OemTableId;
  UINTN TableKey;

  Status = gBS->LocateProtocol (
                  &gEfiAcpiTableProtocolGuid,
                  NULL,
                  (VOID **)&AcpiTableProtocol
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: ACPI protocol not found\n", __func__));
    return EFI_NOT_FOUND;
  }

  Status = gBS->LocateProtocol (
                  &gEfiTcg2ProtocolGuid,
                  NULL,
                  (VOID **)&Tcg2Protocol
                  );
  if (EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: TCG2 protocol not found\n", __func__));
    return EFI_NOT_FOUND;
  }

  Status = Tcg2Protocol->GetEventLog(
              Tcg2Protocol,
              EFI_TCG2_EVENT_LOG_FORMAT_TCG_2,
              &EventLogLocation,
              &EventLogLastEntry,
              &EventLogTruncated);
  if(EFI_ERROR (Status)) {
    DEBUG ((DEBUG_ERROR, "%a: TCG2 event log not found\n", __func__));
    return EFI_NOT_FOUND;
  }

  mTpm2AcpiTemplate.Header.Revision = EFI_TPM2_ACPI_TABLE_REVISION_4;
  CopyMem (mTpm2AcpiTemplate.Header.OemId, PcdGetPtr (PcdAcpiDefaultOemId), sizeof (mTpm2AcpiTemplate.Header.OemId));
  OemTableId = PcdGet64 (PcdAcpiDefaultOemTableId);
  CopyMem (&mTpm2AcpiTemplate.Header.OemTableId, &OemTableId, sizeof (UINT64));
  mTpm2AcpiTemplate.Header.OemRevision      = PcdGet32 (PcdAcpiDefaultOemRevision);
  mTpm2AcpiTemplate.Header.CreatorId        = PcdGet32 (PcdAcpiDefaultCreatorId);
  mTpm2AcpiTemplate.Header.CreatorRevision  = PcdGet32 (PcdAcpiDefaultCreatorRevision);

  mTpm2AcpiTemplate.TpmLogPhysicalAddress = (UINT64)(EventLogLocation);
  mTpm2AcpiTemplate.TpmLogAreaLength      = PcdGet32 (PcdTcgLogAreaMinLen);
  DEBUG ((DEBUG_ERROR, "%a: log at 0x%lx, length 0x%x\n",
        __func__,
        (UINT64) EventLogLocation,
        PcdGet32 (PcdTcgLogAreaMinLen)
        ));
  DEBUG ((DEBUG_ERROR, "%a: buffer at 0x%llx\n", __func__,
        (UINT64) mTpm2AcpiTemplate.AddressOfControlArea));

  Status = AcpiTableProtocol->InstallAcpiTable (
                        AcpiTableProtocol,
                        &mTpm2AcpiTemplate,
                        sizeof(mTpm2AcpiTemplate),
                        &TableKey
                        );

  if (!EFI_ERROR (Status))
    DEBUG ((DEBUG_ERROR, "%a: Installed TPM table!\n", __func__));

  Status = gBS->AllocatePages (AllocateAddress,
                               EfiACPIMemoryNVS,
                               EFI_SIZE_TO_PAGES(0x1000),
                               &CrbBase);

  return Status;
}

EFI_STATUS
EFIAPI
Tcg2AcpiDxeEntryPoint (
  IN EFI_HANDLE                   ImageHandle,
  IN EFI_SYSTEM_TABLE             *SystemTable
  )
{

  Tcg2AcpiPublishSsdt ();
  Tcg2AcpiPublishTpm ();
  return EFI_SUCCESS;
}

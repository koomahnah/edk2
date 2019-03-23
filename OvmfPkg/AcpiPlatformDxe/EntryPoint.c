/** @file
  Entry point of OVMF ACPI Platform Driver

  Copyright (C) 2015, Red Hat, Inc.
  Copyright (c) 2008 - 2015, Intel Corporation. All rights reserved.<BR>

  This program and the accompanying materials are licensed and made available
  under the terms and conditions of the BSD License which accompanies this
  distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS, WITHOUT
  WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#include <Guid/RootBridgesConnectedEventGroup.h>
#include "AcpiPlatform.h"

STATIC
EFI_ACPI_TABLE_PROTOCOL *
FindAcpiTableProtocol (
  VOID
  )
{
  EFI_STATUS              Status;
  EFI_ACPI_TABLE_PROTOCOL *AcpiTable;

  Status = gBS->LocateProtocol (
                  &gEfiAcpiTableProtocolGuid,
                  NULL,
                  (VOID**)&AcpiTable
                  );
  ASSERT_EFI_ERROR (Status);
  return AcpiTable;
}


STATIC
VOID
EFIAPI
OnRootBridgesConnected (
  IN EFI_EVENT Event,
  IN VOID      *Context
  )
{
  EFI_STATUS Status;

  DEBUG ((EFI_D_INFO,
    "%a: root bridges have been connected, installing ACPI tables\n",
    __FUNCTION__));
  Status = InstallAcpiTables (FindAcpiTableProtocol ());
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "%a: InstallAcpiTables: %r\n", __FUNCTION__, Status));
  }
  gBS->CloseEvent (Event);
}


EFI_STATUS
EFIAPI
AcpiPlatformEntryPoint (
  IN EFI_HANDLE         ImageHandle,
  IN EFI_SYSTEM_TABLE   *SystemTable
  )
{
  EFI_STATUS Status;
  EFI_EVENT  RootBridgesConnected;

  UINT8 *ptr = (UINT8 *) 0x7ddffff0;
  DEBUG((DEBUG_ERROR, "ptr val: %d\n", *ptr));

  //
  // If the platform doesn't support PCI, or PCI enumeration has been disabled,
  // install the tables at once, and let the entry point's return code reflect
  // the full functionality.
  //
  if (PcdGetBool (PcdPciDisableBusEnumeration)) {
    DEBUG ((EFI_D_INFO, "%a: PCI or its enumeration disabled, installing "
      "ACPI tables\n", __FUNCTION__));
    return InstallAcpiTables (FindAcpiTableProtocol ());
  }

  //
  // Otherwise, delay installing the ACPI tables until root bridges are
  // connected. The entry point's return status will only reflect the callback
  // setup. (Note that we're a DXE_DRIVER; our entry point function is invoked
  // strictly before BDS is entered and can connect the root bridges.)
  //
  Status = gBS->CreateEventEx (EVT_NOTIFY_SIGNAL, TPL_CALLBACK,
                  OnRootBridgesConnected, NULL /* Context */,
                  &gRootBridgesConnectedEventGroupGuid, &RootBridgesConnected);
  if (!EFI_ERROR (Status)) {
    DEBUG ((EFI_D_INFO,
      "%a: waiting for root bridges to be connected, registered callback\n",
      __FUNCTION__));
  }

  return Status;
}

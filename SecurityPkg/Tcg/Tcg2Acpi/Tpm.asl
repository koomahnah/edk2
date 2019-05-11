DefinitionBlock (
    "Ssdt-tpm.aml",
    "SSDT",
    2,
    "INTEL ",
    "TpmTable",
    0x1000
    )
{
  Scope (\_SB)
  {
    Device(TPM0) {
      Name (_HID, "OEM01011")
      Name (_CID, "MSFT0101")
      Name (_UID, 0)
      Method (_CRS, 0x0, Serialized) {
        Name (RBUF, ResourceTemplate ()
            {
            Memory32Fixed (ReadWrite, 0x7ddf0000, 0x1000, TCRB)
            })
        Return (RBUF)
      }

      Method(_STR,0)
      {
        Return (Unicode ("TPM 2.0 Device"))
      }

      Method (_STA, 0)
      {
        Return (0x0f)
      }

      Method (_DSM, 4, Serialized, 0, UnknownObj, {BuffObj, IntObj, IntObj, PkgObj})
      {
        Return (Buffer () {0})
      }
    }
  }
}

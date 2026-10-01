/* nRF52840 without a SoftDevice: the whole flash and RAM belong to the application. */
MEMORY
{
  FLASH : ORIGIN = 0x00000000, LENGTH = 1024K
  RAM : ORIGIN = 0x20000000, LENGTH = 256K
}

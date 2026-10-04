/* nRF52840 embassy-boot layout (docs/embassy.md): the bootloader at 0, its state page,
 * the active slot and the DFU slot (one page larger than the active slot, as embassy-boot
 * swaps through it). keelsign images are MCUboot images with a 0x200-byte header, so the
 * application is linked 0x200 past the start of the active slot and the bootloader jumps
 * to ACTIVE + 0x200.
 *
 *   BOOTLOADER        0x00000000   24K
 *   BOOTLOADER_STATE  0x00006000    4K
 *   ACTIVE            0x00007000  256K  (header 0x00007000, application 0x00007200)
 *   DFU               0x00047000  260K
 */
MEMORY
{
  BOOTLOADER       : ORIGIN = 0x00000000, LENGTH = 24K
  BOOTLOADER_STATE : ORIGIN = 0x00006000, LENGTH = 4K
  FLASH            : ORIGIN = 0x00007200, LENGTH = 256K - 0x200
  DFU              : ORIGIN = 0x00047000, LENGTH = 260K
  RAM              : ORIGIN = 0x20000000, LENGTH = 256K
}

/* embassy-boot's FirmwareUpdaterConfig::from_linkerfile_blocking reads these, as
 * offsets from the start of the flash. */
__bootloader_state_start = ORIGIN(BOOTLOADER_STATE) - ORIGIN(BOOTLOADER);
__bootloader_state_end = ORIGIN(BOOTLOADER_STATE) + LENGTH(BOOTLOADER_STATE) - ORIGIN(BOOTLOADER);

__bootloader_dfu_start = ORIGIN(DFU) - ORIGIN(BOOTLOADER);
__bootloader_dfu_end = ORIGIN(DFU) + LENGTH(DFU) - ORIGIN(BOOTLOADER);

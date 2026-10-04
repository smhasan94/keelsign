/* RP2350 (Pico 2 W, 2 MiB used of 4 MiB) embassy-boot layout (docs/embassy.md): the
 * bootloader at the start of flash, its state page, the active slot and the DFU slot
 * (one page larger than the active slot, as embassy-boot swaps through it). keelsign
 * images are MCUboot images with a 0x200-byte header, so the application is linked 0x200
 * past the start of the active slot and the bootloader jumps to ACTIVE + 0x200.
 *
 *   BOOTLOADER        0x10000000   24K
 *   BOOTLOADER_STATE  0x10006000    4K
 *   ACTIVE            0x10007000  512K  (header 0x10007000, application 0x10007200)
 *   DFU               0x10087000  516K
 *
 * The SECTIONS below are the upstream embassy rp235x example's (as in
 * examples/rp2350-hello/memory.x): the boot ROM blocks and picotool entries.
 */

MEMORY {
    BOOTLOADER       : ORIGIN = 0x10000000, LENGTH = 24K
    BOOTLOADER_STATE : ORIGIN = 0x10006000, LENGTH = 4K
    FLASH            : ORIGIN = 0x10007200, LENGTH = 512K - 0x200
    DFU              : ORIGIN = 0x10087000, LENGTH = 516K
    RAM              : ORIGIN = 0x20000000, LENGTH = 512K
    SRAM8            : ORIGIN = 0x20080000, LENGTH = 4K
    SRAM9            : ORIGIN = 0x20081000, LENGTH = 4K
}

/* embassy-boot's FirmwareUpdaterConfig::from_linkerfile reads these, as offsets from
 * the start of the flash. */
__bootloader_state_start = ORIGIN(BOOTLOADER_STATE) - ORIGIN(BOOTLOADER);
__bootloader_state_end = ORIGIN(BOOTLOADER_STATE) + LENGTH(BOOTLOADER_STATE) - ORIGIN(BOOTLOADER);

__bootloader_dfu_start = ORIGIN(DFU) - ORIGIN(BOOTLOADER);
__bootloader_dfu_end = ORIGIN(DFU) + LENGTH(DFU) - ORIGIN(BOOTLOADER);

SECTIONS {
    /* ### Boot ROM info
     *
     * Goes after .vector_table, to keep it in the first 4K of flash
     * where the Boot ROM (and picotool) can find it
     */
    .start_block : ALIGN(4)
    {
        __start_block_addr = .;
        KEEP(*(.start_block));
        KEEP(*(.boot_info));
    } > FLASH

} INSERT AFTER .vector_table;

/* move .text to start /after/ the boot info */
_stext = ADDR(.start_block) + SIZEOF(.start_block);

SECTIONS {
    /* ### Picotool 'Binary Info' Entries
     *
     * Picotool looks through this block (as we have pointers to it in our
     * header) to find interesting information.
     */
    .bi_entries : ALIGN(4)
    {
        /* We put this in the header */
        __bi_entries_start = .;
        /* Here are the entries */
        KEEP(*(.bi_entries));
        /* Keep this block a nice round size */
        . = ALIGN(4);
        /* We put this in the header */
        __bi_entries_end = .;
    } > FLASH
} INSERT AFTER .text;

SECTIONS {
    /* ### Boot ROM extra info
     *
     * Goes after everything in our program, so it can contain a signature.
     */
    .end_block : ALIGN(4)
    {
        __end_block_addr = .;
        KEEP(*(.end_block));
    } > FLASH

} INSERT AFTER .uninit;

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);

/*
 * Host port flash area IDs of MCUboot for the keelsign hook harness (SHA-62): image 0
 * only.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#ifndef KEELSIGN_HOOKTEST_SYSFLASH_H
#define KEELSIGN_HOOKTEST_SYSFLASH_H

#define FLASH_AREA_BOOTLOADER 0
#define FLASH_AREA_IMAGE_0 1
#define FLASH_AREA_IMAGE_1 2
#define FLASH_AREA_IMAGE_SCRATCH 3

#define FLASH_AREA_IMAGE_PRIMARY(x) (((x) == 0) ? FLASH_AREA_IMAGE_0 : 255)
#define FLASH_AREA_IMAGE_SECONDARY(x) (((x) == 0) ? FLASH_AREA_IMAGE_1 : 255)

#endif /* KEELSIGN_HOOKTEST_SYSFLASH_H */

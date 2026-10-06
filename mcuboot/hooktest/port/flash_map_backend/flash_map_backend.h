/*
 * Host port flash map of MCUboot for the keelsign hook harness (SHA-62): the flash
 * area API of MCUboot's docs/PORTING.md, implemented over files by flash_stub.c.
 * Image 0 has the primary (slot 0) and secondary (slot 1) areas.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#ifndef KEELSIGN_HOOKTEST_FLASH_MAP_BACKEND_H
#define KEELSIGN_HOOKTEST_FLASH_MAP_BACKEND_H

#include <stdint.h>

struct flash_area {
    uint8_t fa_id;
    uint8_t fa_device_id;
    uint16_t pad16;
    uint32_t fa_off;
    uint32_t fa_size;
};

struct flash_sector {
    uint32_t fs_off;
    uint32_t fs_size;
};

int flash_area_open(uint8_t id, const struct flash_area **fa);
void flash_area_close(const struct flash_area *fa);
int flash_area_read(const struct flash_area *fa, uint32_t off, void *dst, uint32_t len);
int flash_area_write(const struct flash_area *fa, uint32_t off, const void *src, uint32_t len);
int flash_area_erase(const struct flash_area *fa, uint32_t off, uint32_t len);
uint32_t flash_area_align(const struct flash_area *fa);
uint8_t flash_area_erased_val(const struct flash_area *fa);
int flash_area_id_from_multi_image_slot(int image_index, int slot);
int flash_area_id_to_multi_image_slot(int image_index, int area_id);

static inline uint32_t flash_area_get_off(const struct flash_area *fa)
{
    return fa->fa_off;
}

static inline uint32_t flash_area_get_size(const struct flash_area *fa)
{
    return fa->fa_size;
}

static inline uint8_t flash_area_get_id(const struct flash_area *fa)
{
    return fa->fa_id;
}

static inline uint8_t flash_area_get_device_id(const struct flash_area *fa)
{
    return fa->fa_device_id;
}

static inline uint32_t flash_sector_get_off(const struct flash_sector *fs)
{
    return fs->fs_off;
}

static inline uint32_t flash_sector_get_size(const struct flash_sector *fs)
{
    return fs->fs_size;
}

#endif /* KEELSIGN_HOOKTEST_FLASH_MAP_BACKEND_H */

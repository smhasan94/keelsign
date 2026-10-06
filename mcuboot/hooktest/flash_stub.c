/*
 * File-backed flash areas and log capture for the keelsign hook harness (SHA-62).
 *
 * Image 0's primary (slot 0, area 1) and secondary (slot 1, area 2) slots are files set
 * with hooktest_map_slot(), at an offset into the area (0, or one sector in for the
 * secondary slot under swap using offset); the area reads 0xFF (erased) before the
 * offset and past the file's end. Reads outside a slot fail. flash_area_open() counts
 * opens so the harness can check that every open was closed. Writes and erases fail: the
 * hook never writes.
 *
 * boot_get_loader_state() and boot_get_state_secondary_offset() stand in for MCUboot's
 * loader.c (bootutil/bootutil.h) when the glue is built with MCUBOOT_SWAP_USING_OFFSET:
 * like MCUboot's, the offset is the secondary slot's mapping offset for that slot's
 * flash area of this loader state, and 0 for any other area or state.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "flash_map_backend/flash_map_backend.h"

/* Used by harness.c (declared there) and by the port's mcuboot_logging.h. */
int hooktest_map_slot(int slot, const char *path, uint32_t slot_size, uint32_t offset);
int hooktest_open_count(void);
const char *hooktest_last_log(void);
void hooktest_log(const char *level, const char *fmt, ...);

#define HOOKTEST_AREAS 2

static struct hooktest_area {
    struct flash_area fa;
    FILE *file;
    long file_size;
    uint32_t offset;
} areas[HOOKTEST_AREAS];

static int open_count;
static char last_log[512];

int hooktest_map_slot(int slot, const char *path, uint32_t slot_size, uint32_t offset)
{
    struct hooktest_area *a;
    uint32_t end;
    if (slot < 0 || slot >= HOOKTEST_AREAS) {
        return -1;
    }
    a = &areas[slot];
    a->file = fopen(path, "rb");
    if (a->file == NULL || fseek(a->file, 0, SEEK_END) != 0 || (a->file_size = ftell(a->file)) < 0) {
        return -1;
    }
    if ((unsigned long)a->file_size > 0xFFFFFFFFul - offset) {
        return -1;
    }
    end = offset + (uint32_t)a->file_size;
    a->offset = offset;
    a->fa.fa_id = (uint8_t)(slot + 1);
    a->fa.fa_device_id = 0;
    a->fa.fa_off = (uint32_t)slot * 0x80000u;
    a->fa.fa_size = slot_size > end ? slot_size : end;
    return 0;
}

int hooktest_open_count(void)
{
    return open_count;
}

const char *hooktest_last_log(void)
{
    return last_log;
}

void hooktest_log(const char *level, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(last_log, sizeof last_log, fmt, ap);
    va_end(ap);
    printf("log: %s %s\n", level, last_log);
}

int flash_area_id_from_multi_image_slot(int image_index, int slot)
{
    if (image_index != 0 || slot < 0 || slot >= HOOKTEST_AREAS) {
        return -1;
    }
    return slot + 1;
}

int flash_area_id_to_multi_image_slot(int image_index, int area_id)
{
    if (image_index != 0 || area_id < 1 || area_id > HOOKTEST_AREAS) {
        return -1;
    }
    return area_id - 1;
}

int flash_area_open(uint8_t id, const struct flash_area **fa)
{
    if (id < 1 || id > HOOKTEST_AREAS || areas[id - 1].file == NULL) {
        return -1;
    }
    open_count++;
    *fa = &areas[id - 1].fa;
    return 0;
}

void flash_area_close(const struct flash_area *fa)
{
    (void)fa;
    open_count--;
}

int flash_area_read(const struct flash_area *fa, uint32_t off, void *dst, uint32_t len)
{
    const struct hooktest_area *a;
    uint8_t *out = (uint8_t *)dst;
    uint32_t done = 0;
    uint32_t from_file;
    if (fa == NULL || fa->fa_id < 1 || fa->fa_id > HOOKTEST_AREAS) {
        return -1;
    }
    a = &areas[fa->fa_id - 1];
    if (off > fa->fa_size || len > fa->fa_size - off) {
        return -1;
    }
    /* Erased before the image's offset. */
    if (off < a->offset) {
        done = a->offset - off < len ? a->offset - off : len;
        memset(out, 0xFF, done);
    }
    /* The file, then erased past its end. */
    if (done < len && (long)(off + done - a->offset) < a->file_size) {
        from_file = (uint32_t)(a->file_size - (long)(off + done - a->offset));
        if (from_file > len - done) {
            from_file = len - done;
        }
        if (fseek(a->file, (long)(off + done - a->offset), SEEK_SET) != 0 ||
            fread(out + done, 1, from_file, a->file) != from_file) {
            return -1;
        }
        done += from_file;
    }
    memset(out + done, 0xFF, len - done);
    return 0;
}

int flash_area_write(const struct flash_area *fa, uint32_t off, const void *src, uint32_t len)
{
    (void)fa;
    (void)off;
    (void)src;
    (void)len;
    return -1;
}

int flash_area_erase(const struct flash_area *fa, uint32_t off, uint32_t len)
{
    (void)fa;
    (void)off;
    (void)len;
    return -1;
}

uint32_t flash_area_align(const struct flash_area *fa)
{
    (void)fa;
    return 1;
}

uint8_t flash_area_erased_val(const struct flash_area *fa)
{
    (void)fa;
    return 0xFF;
}

/* MCUboot's loader state stands in as one static object; its contents are never read. */
struct boot_loader_state {
    int unused;
};

static struct boot_loader_state loader_state;

struct boot_loader_state *boot_get_loader_state(void);
uint32_t boot_get_state_secondary_offset(struct boot_loader_state *state,
                                         const struct flash_area *fap);

struct boot_loader_state *boot_get_loader_state(void)
{
    return &loader_state;
}

uint32_t boot_get_state_secondary_offset(struct boot_loader_state *state,
                                         const struct flash_area *fap)
{
    if (state == &loader_state && fap == &areas[1].fa) {
        return areas[1].offset;
    }
    return 0;
}

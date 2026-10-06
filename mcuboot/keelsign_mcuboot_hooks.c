/*
 * keelsign MCUboot image-access hooks (SHA-62): verify keelsign's post-quantum TLVs of
 * every image MCUboot validates, through libkeelsign.a, before MCUboot's own checks.
 *
 * boot_image_check_hook() is MCUboot's extension point for this (boot_hooks.h; called
 * from boot_validate_slot() after the header check and before bootutil_img_validate(),
 * and from serial recovery). It reads the slot through keelsign_verify_cb() and
 *   - on KEELSIGN_OK logs "keelsign: image I slot S verified (...)" and returns
 *     FIH_BOOT_HOOK_REGULAR, so MCUboot still checks the SHA256 TLV, its own
 *     classical signature (ECDSA, Ed25519, RSA), the security counter and the
 *     dependencies: keelsign is an additional gate, never a replacement;
 *   - on any error, including a flash area it cannot open or read, logs
 *     "keelsign: image I slot S rejected: status N" (N a keelsign_status_t) and
 *     returns FIH_FAILURE (fail closed).
 * It never returns FIH_SUCCESS, which would skip MCUboot's own validation.
 *
 * Swap using offset (MCUBOOT_SWAP_USING_OFFSET, Zephyr: CONFIG_BOOT_SWAP_USING_OFFSET,
 * sysbuild's default MCUboot mode in Zephyr v4.4.2): the image in the secondary slot
 * starts one sector into the area. The hook reads the slot from
 * boot_get_state_secondary_offset(), the offset MCUboot's own bootutil_img_validate()
 * reads it from (image_validate.c), which is 0 for every other area and in every other
 * swap mode. An offset at or past the end of the area is rejected with
 * KEELSIGN_ERR_READ_OUT_OF_BOUNDS (fail closed).
 *
 * MCUBOOT_IMAGE_ACCESS_HOOKS (Zephyr: CONFIG_BOOT_IMAGE_ACCESS_HOOKS=y) makes MCUboot
 * call every hook of that set, so the others are defined here too and keep MCUboot's
 * normal path. MCUBOOT_USE_CUSTOM_CRYPTO is unrelated: it swaps MCUboot's crypto
 * backend (docs/mcuboot.md). keelsign TLVs are unprotected TLVs 0x4BA0-0x4BA3, so
 * MCUboot's TLV allow list (CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST) must be off.
 *
 * Written for keelsign; MCUboot's boot/zephyr/hooks_sample.c (Apache-2.0) was read
 * as the reference for the hook set, nothing is copied from it.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "bootutil/boot_hooks.h"
#include "bootutil/boot_public_hooks.h"
#include "bootutil/bootutil.h"
#include "bootutil/bootutil_log.h"
#include "bootutil/fault_injection_hardening.h"
#include "bootutil/image.h"
#include "flash_map_backend/flash_map_backend.h"

#include "keelsign.h"
#include "keelsign_mcuboot.h"

BOOT_LOG_MODULE_DECLARE(mcuboot);

int32_t keelsign_mcuboot_read(void *ctx, uint32_t offset, uint8_t *buf, size_t len)
{
    const keelsign_mcuboot_slot *slot = (const keelsign_mcuboot_slot *)ctx;

    if (slot == NULL || slot->fap == NULL || offset > UINT32_MAX - slot->start_off) {
        return -1;
    }
    return flash_area_read(slot->fap, slot->start_off + offset, buf, len) == 0 ? 0 : -1;
}

fih_ret boot_image_check_hook(int img_index, int slot)
{
    keelsign_mcuboot_slot ctx;
    keelsign_reader_t reader;
    keelsign_result_t result;
    keelsign_status_t status;
    uint32_t size;
    int area_id;

    ctx.fap = NULL;
    ctx.start_off = 0;
    area_id = flash_area_id_from_multi_image_slot(img_index, slot);
    if (area_id < 0 || flash_area_open((uint8_t)area_id, &ctx.fap) != 0 || ctx.fap == NULL) {
        BOOT_LOG_ERR("keelsign: image %d slot %d rejected: status %d", img_index, slot,
                     (int)KEELSIGN_ERR_READ_OTHER);
        FIH_RET(FIH_FAILURE);
    }

#if defined(MCUBOOT_SWAP_USING_OFFSET)
    /* Where MCUboot itself reads this slot's image: one sector in for the secondary
     * slot of the image being validated, else 0. The match is by flash area pointer,
     * which flash_area_open() returns from the static flash map. */
    ctx.start_off = boot_get_state_secondary_offset(boot_get_loader_state(), ctx.fap);
#endif
    size = (uint32_t)flash_area_get_size(ctx.fap);
    if (ctx.start_off >= size) {
        flash_area_close(ctx.fap);
        BOOT_LOG_ERR("keelsign: image %d slot %d rejected: status %d", img_index, slot,
                     (int)KEELSIGN_ERR_READ_OUT_OF_BOUNDS);
        FIH_RET(FIH_FAILURE);
    }

    reader.ctx = &ctx;
    reader.len = size - ctx.start_off;
    reader.read = keelsign_mcuboot_read;
    status = keelsign_verify_cb(&reader, keelsign_mcuboot_keys, keelsign_mcuboot_n_keys,
                                keelsign_mcuboot_policy, &result);
    flash_area_close(ctx.fap);

    if (status != KEELSIGN_OK) {
        BOOT_LOG_ERR("keelsign: image %d slot %d rejected: status %d", img_index, slot,
                     (int)status);
        FIH_RET(FIH_FAILURE);
    }
    BOOT_LOG_INF("keelsign: image %d slot %d verified (pq key %u, ed25519 key %u)", img_index,
                 slot, (unsigned)result.pq_key_index, (unsigned)result.ed25519_key_index);
    FIH_RET(FIH_BOOT_HOOK_REGULAR);
}

/* The rest of the MCUBOOT_IMAGE_ACCESS_HOOKS set: MCUboot's normal path. */

int boot_read_image_header_hook(int img_index, int slot, struct image_header *img_head)
{
    (void)img_index;
    (void)slot;
    (void)img_head;
    return BOOT_HOOK_REGULAR;
}

int boot_perform_update_hook(int img_index, struct image_header *img_head,
                             const struct flash_area *area)
{
    (void)img_index;
    (void)img_head;
    (void)area;
    return BOOT_HOOK_REGULAR;
}

int boot_read_swap_state_primary_slot_hook(int image_index, struct boot_swap_state *state)
{
    (void)image_index;
    (void)state;
    return BOOT_HOOK_REGULAR;
}

int boot_copy_region_post_hook(int img_index, const struct flash_area *area, size_t size)
{
    (void)img_index;
    (void)area;
    (void)size;
    return 0;
}

#if defined(MCUBOOT_SERIAL) || defined(CONFIG_MCUBOOT_SERIAL)
int boot_serial_uploaded_hook(int img_index, const struct flash_area *area, size_t size)
{
    (void)img_index;
    (void)area;
    (void)size;
    return 0;
}

int boot_img_install_stat_hook(int image_index, int slot, int *img_install_stat)
{
    (void)image_index;
    (void)slot;
    (void)img_install_stat;
    return BOOT_HOOK_REGULAR;
}

int boot_reset_request_hook(bool force)
{
    (void)force;
    return 0;
}
#endif /* MCUBOOT_SERIAL || CONFIG_MCUBOOT_SERIAL */

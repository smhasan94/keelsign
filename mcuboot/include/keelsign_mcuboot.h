/*
 * keelsign MCUboot image-check hook (SHA-62): the key table the hook trusts and the
 * flash reader it hands to keelsign_verify_cb. See docs/mcuboot.md.
 *
 * The key table is generated, never written by hand:
 *   python3 scripts/keelsign_embed_keys.py --policy pq_only --out keelsign_mcuboot_keys.c keelsign.pub.pem
 * (the Zephyr module runs it at configure time from CONFIG_KEELSIGN_PUBLIC_KEY_FILE).
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#ifndef KEELSIGN_MCUBOOT_H
#define KEELSIGN_MCUBOOT_H

#include <stddef.h>
#include <stdint.h>

#include "keelsign.h"

#ifdef __cplusplus
extern "C" {
#endif

struct flash_area;

/* The trusted public keys (raw, as keelsign_verify_cb takes them) and how many. */
extern const keelsign_key_t keelsign_mcuboot_keys[];
extern const size_t keelsign_mcuboot_n_keys;

/* KEELSIGN_POLICY_PQ_ONLY or KEELSIGN_POLICY_HYBRID. */
extern const keelsign_policy_t keelsign_mcuboot_policy;

/* The read context of keelsign_mcuboot_read: one open MCUboot flash area. */
typedef struct keelsign_mcuboot_slot {
  const struct flash_area *fap;
} keelsign_mcuboot_slot;

/* keelsign_reader_t.read over flash_area_read(): ctx is a keelsign_mcuboot_slot.
 * Returns 0 when all len bytes were read, -1 otherwise. */
int32_t keelsign_mcuboot_read(void *ctx, uint32_t offset, uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* KEELSIGN_MCUBOOT_H */

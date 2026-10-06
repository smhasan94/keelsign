/*
 * Host port configuration of MCUboot for the keelsign hook harness (SHA-62,
 * docs/mcuboot.md#host-hook-harness): one image, image-access hooks on, logging on,
 * fault-injection hardening off unless the compiler line selects a profile
 * (-DMCUBOOT_FIH_PROFILE_LOW / _MEDIUM). Every MCUboot port provides this header.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#ifndef KEELSIGN_HOOKTEST_MCUBOOT_CONFIG_H
#define KEELSIGN_HOOKTEST_MCUBOOT_CONFIG_H

#define MCUBOOT_IMAGE_NUMBER 1
#define MCUBOOT_IMAGE_ACCESS_HOOKS
#define MCUBOOT_HAVE_LOGGING 1

#if !defined(MCUBOOT_FIH_PROFILE_LOW) && !defined(MCUBOOT_FIH_PROFILE_MEDIUM) && \
    !defined(MCUBOOT_FIH_PROFILE_HIGH)
#define MCUBOOT_FIH_PROFILE_OFF
#endif

#endif /* KEELSIGN_HOOKTEST_MCUBOOT_CONFIG_H */

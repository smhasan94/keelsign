/*
 * keelsign_hello (SHA-62): prints that it runs and where it was linked (the start of
 * its ROM region: slot 0, where the image header is), then ticks.
 * MCUboot only gets here after keelsign verified the image's LMS/HSS signature and
 * MCUboot verified its own (docs/mcuboot.md).
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#include <zephyr/kernel.h>
#include <zephyr/linker/linker-defs.h>
#include <zephyr/sys/printk.h>

int main(void)
{
	unsigned int tick = 0;

	printk("hello from keelsign_hello on %s, linked at %p\n", CONFIG_BOARD,
	       (void *)__rom_region_start);
	for (;;) {
		k_sleep(K_SECONDS(1));
		printk("keelsign_hello tick %u\n", ++tick);
	}
	return 0;
}

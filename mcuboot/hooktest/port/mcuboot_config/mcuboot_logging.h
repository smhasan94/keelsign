/*
 * Host port logging of MCUboot for the keelsign hook harness (SHA-62): every
 * BOOT_LOG_* line goes to hooktest_log() (flash_stub.c), which prints it to stdout
 * as "log: <level> <message>" so the harness and its tests see what MCUboot would
 * print on the board.
 *
 * SPDX-License-Identifier: MIT OR Apache-2.0
 */
#ifndef KEELSIGN_HOOKTEST_MCUBOOT_LOGGING_H
#define KEELSIGN_HOOKTEST_MCUBOOT_LOGGING_H

void hooktest_log(const char *level, const char *fmt, ...);

#define MCUBOOT_LOG_MODULE_DECLARE(domain)
#define MCUBOOT_LOG_MODULE_REGISTER(domain)

#define MCUBOOT_LOG_ERR(...) hooktest_log("ERR", __VA_ARGS__)
#define MCUBOOT_LOG_WRN(...) hooktest_log("WRN", __VA_ARGS__)
#define MCUBOOT_LOG_INF(...) hooktest_log("INF", __VA_ARGS__)
#define MCUBOOT_LOG_DBG(...) hooktest_log("DBG", __VA_ARGS__)
#define MCUBOOT_LOG_SIM(...) hooktest_log("SIM", __VA_ARGS__)

#endif /* KEELSIGN_HOOKTEST_MCUBOOT_LOGGING_H */

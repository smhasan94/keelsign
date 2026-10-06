# keelsign_hello (SHA-62): an application MCUboot boots only after keelsign verified its
# LMS/HSS signature. docs/mcuboot.md.
#
# SPDX-License-Identifier: MIT OR Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(keelsign_hello)

# Built through sysbuild only, so MCUboot (with keelsign) is part of the build.
test_sysbuild()

target_sources(app PRIVATE src/main.c)

# keelsign_rust_target(<out-var>): the Rust target triple libkeelsign.a is built for in
# this Zephyr image (SHA-62, docs/mcuboot.md#kconfig-reference).
#
# CONFIG_KEELSIGN_RUST_TARGET if set, else from the CPU: Cortex-M0/M0+
# thumbv6m-none-eabi, M3 thumbv7m-none-eabi, M4/M7 thumbv7em-none-eabi, M23
# thumbv8m.base-none-eabi, M33/M55 thumbv8m.main-none-eabi, with `hf` appended (M4, M7,
# M33, M55) exactly when the image uses the hard-float ABI (CONFIG_FP_HARDABI): a
# soft-float MCUboot (the default; boot/zephyr/prj.conf sets no FPU) cannot link an
# `eabihf` archive.
#
# SPDX-License-Identifier: MIT OR Apache-2.0

function(keelsign_rust_target out)
  if(NOT "${CONFIG_KEELSIGN_RUST_TARGET}" STREQUAL "")
    set(${out} "${CONFIG_KEELSIGN_RUST_TARGET}" PARENT_SCOPE)
    return()
  endif()
  set(hf "")
  if(CONFIG_FP_HARDABI)
    set(hf "hf")
  endif()
  if(CONFIG_CPU_CORTEX_M0 OR CONFIG_CPU_CORTEX_M0PLUS)
    set(triple thumbv6m-none-eabi)
  elseif(CONFIG_CPU_CORTEX_M3)
    set(triple thumbv7m-none-eabi)
  elseif(CONFIG_CPU_CORTEX_M4 OR CONFIG_CPU_CORTEX_M7)
    set(triple thumbv7em-none-eabi${hf})
  elseif(CONFIG_CPU_CORTEX_M23)
    set(triple thumbv8m.base-none-eabi)
  elseif(CONFIG_CPU_CORTEX_M33 OR CONFIG_CPU_CORTEX_M55)
    set(triple thumbv8m.main-none-eabi${hf})
  else()
    message(FATAL_ERROR
      "keelsign: no Rust target for this CPU; set CONFIG_KEELSIGN_RUST_TARGET "
      "(or CONFIG_KEELSIGN_LIBRARY to a prebuilt libkeelsign.a)")
  endif()
  set(${out} ${triple} PARENT_SCOPE)
endfunction()

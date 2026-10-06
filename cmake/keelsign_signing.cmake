# keelsign signing script of a Zephyr application (SHA-62, docs/mcuboot.md#signing):
# zephyr/CMakeLists.txt sets it as the SIGNING_SCRIPT when CONFIG_KEELSIGN_SIGN_IMAGE=y.
#
# Runs Zephyr's own cmake/mcuboot.cmake first (imgtool writes zephyr.signed.bin/.hex
# with MCUboot's classical signature, unchanged), then appends to the post-build
# commands:
#
#   keelsign sign --key <CONFIG_KEELSIGN_SIGNATURE_KEY_FILE> --force \
#       zephyr.signed.bin zephyr.signed.keelsign.bin
#   objcopy -I binary -O ihex --change-addresses <code partition address> \
#       zephyr.signed.keelsign.bin zephyr.signed.keelsign.hex
#
# and makes those two the files `west flash` programs. keelsign signs the unpadded
# imgtool output (it refuses padded images). The commands run when the application
# relinks, and each run uses up one leaf of the stateful LMS/HSS key (docs/lms.md).
#
# SPDX-License-Identifier: MIT OR Apache-2.0

include(${ZEPHYR_BASE}/cmake/mcuboot.cmake)

function(keelsign_signing_tasks)
  set(keelsign_dir ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/..)
  cmake_path(NORMAL_PATH keelsign_dir)

  if("${CONFIG_MCUBOOT_SIGNATURE_KEY_FILE}" STREQUAL "" OR CONFIG_MCUBOOT_GENERATE_UNSIGNED_IMAGE)
    message(FATAL_ERROR
      "keelsign: CONFIG_KEELSIGN_SIGN_IMAGE signs imgtool's zephyr.signed.bin; set "
      "CONFIG_MCUBOOT_SIGNATURE_KEY_FILE (sysbuild: SB_CONFIG_BOOT_SIGNATURE_KEY_FILE)")
  endif()
  if(NOT CONFIG_BUILD_OUTPUT_BIN)
    message(FATAL_ERROR "keelsign: CONFIG_KEELSIGN_SIGN_IMAGE needs CONFIG_BUILD_OUTPUT_BIN=y")
  endif()

  set(key "${CONFIG_KEELSIGN_SIGNATURE_KEY_FILE}")
  if("${key}" STREQUAL "")
    message(FATAL_ERROR "keelsign: CONFIG_KEELSIGN_SIGNATURE_KEY_FILE is empty")
  endif()
  if(NOT IS_ABSOLUTE "${key}")
    set(key "${APPLICATION_CONFIG_DIR}/${key}")
  endif()
  if(NOT EXISTS "${key}")
    message(FATAL_ERROR
      "keelsign: signing key ${key} does not exist; make one with "
      "`keelsign keygen --alg lms-sha256-m32-h10 --out ${key}` (docs/mcuboot.md)")
  endif()

  set(cli "${CONFIG_KEELSIGN_CLI}")
  if("${cli}" STREQUAL "")
    find_program(KEELSIGN_CARGO cargo HINTS "$ENV{CARGO_HOME}/bin" "$ENV{HOME}/.cargo/bin")
    if(NOT KEELSIGN_CARGO)
      message(FATAL_ERROR "keelsign: cargo not found; set CONFIG_KEELSIGN_CLI to the keelsign CLI")
    endif()
    set(host_dir ${CMAKE_BINARY_DIR}/keelsign-cargo-host)
    message(STATUS "keelsign: building the keelsign CLI (cargo build -p keelsign --release)")
    execute_process(
      COMMAND ${KEELSIGN_CARGO} build -p keelsign --release --locked --target-dir ${host_dir}
      WORKING_DIRECTORY ${keelsign_dir}
      RESULT_VARIABLE rc
    )
    if(NOT rc EQUAL 0)
      message(FATAL_ERROR "keelsign: cargo build -p keelsign failed")
    endif()
    set(cli ${host_dir}/release/keelsign${CMAKE_EXECUTABLE_SUFFIX})
  endif()

  set(output ${ZEPHYR_BINARY_DIR}/${KERNEL_NAME})
  # Where the image is programmed: the code partition (zephyr,code-partition; Zephyr
  # 4.4's mapped partitions have no CONFIG_FLASH_LOAD_OFFSET), else the load offset.
  dt_chosen(code_partition PROPERTY "zephyr,code-partition")
  if(DEFINED code_partition)
    dt_reg_addr(load PATH "${code_partition}")
  else()
    math(EXPR load "${CONFIG_FLASH_BASE_ADDRESS} + ${CONFIG_FLASH_LOAD_OFFSET}" OUTPUT_FORMAT HEXADECIMAL)
  endif()
  set_property(GLOBAL APPEND PROPERTY extra_post_build_commands
    COMMAND ${cli} sign --key ${key} --force ${output}.signed.bin ${output}.signed.keelsign.bin
    COMMAND ${CMAKE_OBJCOPY} -I binary -O ihex --change-addresses ${load}
            ${output}.signed.keelsign.bin ${output}.signed.keelsign.hex
  )
  set_property(GLOBAL APPEND PROPERTY extra_post_build_byproducts
    ${output}.signed.keelsign.bin ${output}.signed.keelsign.hex)
  zephyr_runner_file(bin ${output}.signed.keelsign.bin)
  zephyr_runner_file(hex ${output}.signed.keelsign.hex)
endfunction()

keelsign_signing_tasks()

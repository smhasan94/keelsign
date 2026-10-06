# keelsign sysbuild module (SHA-62, docs/mcuboot.md): with SB_CONFIG_KEELSIGN=y, before
# the images are configured,
#   - builds the keelsign CLI (unless SB_CONFIG_KEELSIGN_CLI) and exports the public key
#     of SB_CONFIG_KEELSIGN_SIGNATURE_KEY_FILE (and, for the hybrid policy, of
#     SB_CONFIG_BOOT_SIGNATURE_KEY_FILE) into the build directory, as MCUboot's own
#     build exports its imgtool key;
#   - configures the mcuboot image: CONFIG_KEELSIGN, the policy, the public key files,
#     CONFIG_BOOT_IMAGE_ACCESS_HOOKS=y and CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST=n (keelsign
#     TLVs are not on MCUboot's allow list);
#   - configures the application image to be signed with keelsign after imgtool.
#
# SPDX-License-Identifier: MIT OR Apache-2.0

function(${SYSBUILD_CURRENT_MODULE_NAME}_pre_cmake)
  cmake_parse_arguments(PRE_CMAKE "" "" "IMAGES" ${ARGN})
  if(NOT SB_CONFIG_KEELSIGN)
    return()
  endif()
  set(keelsign_dir ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/..)
  cmake_path(NORMAL_PATH keelsign_dir)

  if(NOT "mcuboot" IN_LIST PRE_CMAKE_IMAGES)
    message(FATAL_ERROR "keelsign: SB_CONFIG_KEELSIGN needs the mcuboot image (SB_CONFIG_BOOTLOADER_MCUBOOT)")
  endif()

  set(key "${SB_CONFIG_KEELSIGN_SIGNATURE_KEY_FILE}")
  if(NOT IS_ABSOLUTE "${key}")
    set(key "${APP_DIR}/${key}")
  endif()
  if(NOT EXISTS "${key}")
    message(FATAL_ERROR
      "keelsign: signing key ${key} does not exist; make one with "
      "`keelsign keygen --alg lms-sha256-m32-h10 --out ${key}` (docs/mcuboot.md)")
  endif()

  set(cli "${SB_CONFIG_KEELSIGN_CLI}")
  if("${cli}" STREQUAL "")
    find_program(KEELSIGN_CARGO cargo HINTS "$ENV{CARGO_HOME}/bin" "$ENV{HOME}/.cargo/bin")
    if(NOT KEELSIGN_CARGO)
      message(FATAL_ERROR "keelsign: cargo not found; set SB_CONFIG_KEELSIGN_CLI to the keelsign CLI")
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

  # What the bootloader trusts: the public key of the signing key (imgtool getpub ->
  # autogen-pubkey.c is MCUboot's equivalent).
  set(pub ${CMAKE_BINARY_DIR}/keelsign.pub.pem)
  execute_process(
    COMMAND ${cli} pubkey --key ${key} --out ${pub} --force
    RESULT_VARIABLE rc
    OUTPUT_QUIET
  )
  if(NOT rc EQUAL 0)
    message(FATAL_ERROR "keelsign: keelsign pubkey --key ${key} failed")
  endif()
  set(pubs "${pub}")
  if(SB_CONFIG_KEELSIGN_POLICY_HYBRID)
    set(ed_key "${SB_CONFIG_BOOT_SIGNATURE_KEY_FILE}")
    string(CONFIGURE "${ed_key}" ed_key)
    set(ed_pub ${CMAKE_BINARY_DIR}/keelsign.ed25519.pub.pem)
    execute_process(
      COMMAND ${cli} pubkey --key ${ed_key} --alg ed25519 --out ${ed_pub} --force
      RESULT_VARIABLE rc
      OUTPUT_QUIET
    )
    if(NOT rc EQUAL 0)
      message(FATAL_ERROR "keelsign: keelsign pubkey --key ${ed_key} --alg ed25519 failed")
    endif()
    set(pubs "${pub} ${ed_pub}")
  endif()
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${key})

  set_config_bool(mcuboot CONFIG_KEELSIGN y)
  if(SB_CONFIG_KEELSIGN_POLICY_HYBRID)
    set_config_bool(mcuboot CONFIG_KEELSIGN_POLICY_HYBRID y)
  else()
    set_config_bool(mcuboot CONFIG_KEELSIGN_POLICY_PQ_ONLY y)
  endif()
  set_config_string(mcuboot CONFIG_KEELSIGN_PUBLIC_KEY_FILE "${pubs}")
  set_config_bool(mcuboot CONFIG_BOOT_IMAGE_ACCESS_HOOKS y)
  set_config_bool(mcuboot CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST n)
  if(NOT "${SB_CONFIG_KEELSIGN_LIBRARY}" STREQUAL "")
    set_config_string(mcuboot CONFIG_KEELSIGN_LIBRARY "${SB_CONFIG_KEELSIGN_LIBRARY}")
  endif()

  set_config_bool(${DEFAULT_IMAGE} CONFIG_KEELSIGN_SIGN_IMAGE y)
  set_config_string(${DEFAULT_IMAGE} CONFIG_KEELSIGN_SIGNATURE_KEY_FILE "${key}")
  set_config_string(${DEFAULT_IMAGE} CONFIG_KEELSIGN_CLI "${cli}")
endfunction(${SYSBUILD_CURRENT_MODULE_NAME}_pre_cmake)

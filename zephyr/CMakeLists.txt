# keelsign Zephyr module (SHA-62, docs/mcuboot.md).
#
# MCUboot image (CONFIG_KEELSIGN): MCUboot's image-access hooks from
# mcuboot/keelsign_mcuboot_hooks.c, the trusted key table generated from
# CONFIG_KEELSIGN_PUBLIC_KEY_FILE by scripts/keelsign_embed_keys.py, and libkeelsign.a
# (CONFIG_KEELSIGN_LIBRARY, or cargo-built for the image's CPU).
#
# Application image (CONFIG_KEELSIGN_SIGN_IMAGE): cmake/keelsign_signing.cmake signs
# the imgtool output with keelsign.
#
# SPDX-License-Identifier: MIT OR Apache-2.0

set(KEELSIGN_DIR ${CMAKE_CURRENT_LIST_DIR}/..)
cmake_path(NORMAL_PATH KEELSIGN_DIR)

# A relative path of the image configuration resolved against the application
# configuration directory.
function(keelsign_resolve_path path out)
  if(NOT IS_ABSOLUTE "${path}")
    set(path "${APPLICATION_CONFIG_DIR}/${path}")
  endif()
  set(${out} "${path}" PARENT_SCOPE)
endfunction()

if(CONFIG_KEELSIGN)
  if(NOT CONFIG_MCUBOOT)
    message(FATAL_ERROR
      "keelsign: CONFIG_KEELSIGN is for the MCUboot image (it adds MCUboot's "
      "boot_image_check_hook); an application uses CONFIG_KEELSIGN_SIGN_IMAGE, and with "
      "sysbuild SB_CONFIG_KEELSIGN sets both (docs/mcuboot.md)")
  endif()
  if(CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST)
    message(FATAL_ERROR "keelsign: CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST=y rejects keelsign TLVs 0x4BA0-0x4BA3 (image_validate.c allowed_unprot_tlvs); set it to n")
  endif()
  if(NOT CONFIG_BOOT_IMAGE_ACCESS_HOOKS)
    message(FATAL_ERROR
      "keelsign: CONFIG_BOOT_IMAGE_ACCESS_HOOKS=n: MCUboot would never call keelsign's "
      "boot_image_check_hook; set it to y")
  endif()
  if(CONFIG_MAIN_STACK_SIZE LESS CONFIG_KEELSIGN_MIN_MAIN_STACK)
    message(WARNING
      "keelsign: CONFIG_MAIN_STACK_SIZE=${CONFIG_MAIN_STACK_SIZE} is below "
      "CONFIG_KEELSIGN_MIN_MAIN_STACK=${CONFIG_KEELSIGN_MIN_MAIN_STACK}; keelsign verifies "
      "on MCUboot's main thread (docs/mcuboot.md#stack)")
  endif()

  if(CONFIG_KEELSIGN_POLICY_HYBRID)
    set(keelsign_policy hybrid)
    set(keelsign_features --features ed25519)
  else()
    set(keelsign_policy pq_only)
    set(keelsign_features)
  endif()

  # The trusted keys, as a C key table, generated at configure time (a bad key set
  # stops the configuration) and again whenever a key file changes.
  separate_arguments(keelsign_key_args UNIX_COMMAND "${CONFIG_KEELSIGN_PUBLIC_KEY_FILE}")
  if(NOT keelsign_key_args)
    message(FATAL_ERROR "keelsign: CONFIG_KEELSIGN_PUBLIC_KEY_FILE is empty")
  endif()
  set(keelsign_key_files)
  foreach(key ${keelsign_key_args})
    keelsign_resolve_path("${key}" key)
    if(NOT EXISTS "${key}")
      message(FATAL_ERROR "keelsign: public key file ${key} does not exist")
    endif()
    list(APPEND keelsign_key_files "${key}")
  endforeach()
  set(keelsign_keys_c ${CMAKE_CURRENT_BINARY_DIR}/keelsign_mcuboot_keys.c)
  execute_process(
    COMMAND ${PYTHON_EXECUTABLE} ${KEELSIGN_DIR}/scripts/keelsign_embed_keys.py
            --policy ${keelsign_policy} --out ${keelsign_keys_c} ${keelsign_key_files}
    RESULT_VARIABLE keelsign_rc
  )
  if(NOT keelsign_rc EQUAL 0)
    message(FATAL_ERROR "keelsign: scripts/keelsign_embed_keys.py failed (see above)")
  endif()
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    ${keelsign_key_files} ${KEELSIGN_DIR}/scripts/keelsign_embed_keys.py)

  # libkeelsign.a: prebuilt, or cargo-built for this CPU on every build (cargo is a
  # no-op when nothing changed).
  if(NOT "${CONFIG_KEELSIGN_LIBRARY}" STREQUAL "")
    keelsign_resolve_path("${CONFIG_KEELSIGN_LIBRARY}" keelsign_lib)
    if(NOT EXISTS "${keelsign_lib}")
      message(FATAL_ERROR "keelsign: CONFIG_KEELSIGN_LIBRARY ${keelsign_lib} does not exist")
    endif()
  else()
    include(${KEELSIGN_DIR}/cmake/keelsign_rust_target.cmake)
    keelsign_rust_target(keelsign_triple)
    find_program(KEELSIGN_CARGO cargo HINTS "$ENV{CARGO_HOME}/bin" "$ENV{HOME}/.cargo/bin")
    if(NOT KEELSIGN_CARGO)
      message(FATAL_ERROR
        "keelsign: cargo not found; install Rust with the ${keelsign_triple} target or set "
        "CONFIG_KEELSIGN_LIBRARY")
    endif()
    set(keelsign_target_dir ${CMAKE_BINARY_DIR}/keelsign-cargo)
    set(keelsign_lib ${keelsign_target_dir}/${keelsign_triple}/ffi/libkeelsign.a)
    message(STATUS "keelsign: libkeelsign.a for ${keelsign_triple} (${keelsign_policy})")
    add_custom_target(keelsign_cargo
      COMMAND ${KEELSIGN_CARGO} build -p keelsign-ffi --profile ffi --locked
              --target ${keelsign_triple} ${keelsign_features}
              --target-dir ${keelsign_target_dir}
      WORKING_DIRECTORY ${KEELSIGN_DIR}
      BYPRODUCTS ${keelsign_lib}
      COMMENT "keelsign: cargo build -p keelsign-ffi --profile ffi (${keelsign_triple})"
      USES_TERMINAL
    )
  endif()
  add_library(keelsign_ffi STATIC IMPORTED GLOBAL)
  set_target_properties(keelsign_ffi PROPERTIES IMPORTED_LOCATION ${keelsign_lib})
  if(TARGET keelsign_cargo)
    add_dependencies(keelsign_ffi keelsign_cargo)
  endif()

  zephyr_library_named(keelsign_mcuboot)
  zephyr_library_sources(
    ${KEELSIGN_DIR}/mcuboot/keelsign_mcuboot_hooks.c
    ${keelsign_keys_c}
  )
  zephyr_library_include_directories(
    ${KEELSIGN_DIR}/mcuboot/include
    ${KEELSIGN_DIR}/keelsign-ffi/include
  )
  zephyr_library_link_libraries(MCUBOOT_BOOTUTIL)
  target_link_libraries(app PRIVATE keelsign_ffi)
endif()

if(CONFIG_KEELSIGN_SIGN_IMAGE)
  set_property(TARGET zephyr_property_target
    PROPERTY SIGNING_SCRIPT ${KEELSIGN_DIR}/cmake/keelsign_signing.cmake)
endif()

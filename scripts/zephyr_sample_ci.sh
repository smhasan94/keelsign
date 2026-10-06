#!/usr/bin/env bash
# Build and check the keelsign_hello MCUboot sample (SHA-62): the command sequence of
# docs/mcuboot.md, run by the CI job `zephyr-sample`, the verifier and the ignored
# repo-checks in tools/repo-checks/tests/mcuboot.rs.
#
#   scripts/zephyr_sample_ci.sh STEP...      (from anywhere; runs in the repository)
#
# Steps, in the order `all` runs them:
#   setup-key           build the keelsign CLI; make samples/keelsign_hello/keelsign-dev.pem
#                       (+ .state, .journal) unless it exists
#   build               west build of MCUboot + the keelsign-signed application (build/);
#                       checks the outputs, their TLVs (keelsign 0x4BA0/0x4BA3 and
#                       imgtool's ECDSA 0x22), MCUboot's .config, and both signatures
#   variants            tampered, wrong-key and bad-ECDSA images for the on-board
#                       checks (build/variants/, scripts/mcuboot_variants.py)
#   ed25519-build       west build with MCUboot's Ed25519 signature and
#                       KEELSIGN_POLICY_PQ_ONLY (build-ed25519/): links into the 64 KB
#                       boot partition; checks MCUboot's .config, the TLVs (imgtool's
#                       Ed25519 0x24, keelsign 0x4BA0/0x4BA3) and both signatures
#   hybrid-build        MCUboot with Ed25519 + KEELSIGN_POLICY_HYBRID: configure, then
#                       compile the hook and libkeelsign.a (ed25519) (build-hybrid/;
#                       compile-only: it does not fit the 64 KB boot partition)
#   allow-list-refused  an MCUboot build with keelsign and MCUboot's TLV allow list on
#                       must stop at configure time with keelsign's message
#   stock-build         the same sample without keelsign (build-stock/)
#   sizes               MCUboot flash/RAM, stock vs keelsign (scripts/mcuboot_sizes.py)
#   all                 everything above
#
# The lines between `# doc:` and `# end doc` are the commands docs/mcuboot.md shows
# (repo_checks::mcuboot::doc_commands_match_scripts keeps the two equal). Needs the
# workspace of scripts/zephyr-setup.sh: its .venv and .zephyr-sdk-1.0.1 are used when
# PATH has no west and ZEPHYR_SDK_INSTALL_DIR is unset.
#
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
topdir="$(cd "${KEELSIGN_WORKSPACE:-$(dirname "$repo")}" && pwd -P)"
cd "$repo"

if ! command -v west >/dev/null 2>&1 && [ -x "$topdir/.venv/bin/west" ]; then
  export PATH="$topdir/.venv/bin:$PATH"
fi
if [ -z "${ZEPHYR_SDK_INSTALL_DIR:-}" ] && [ -f "$topdir/.zephyr-sdk-1.0.1/sdk_version" ]; then
  export ZEPHYR_SDK_INSTALL_DIR="$topdir/.zephyr-sdk-1.0.1"
fi
export ZEPHYR_TOOLCHAIN_VARIANT="${ZEPHYR_TOOLCHAIN_VARIANT:-zephyr}"

fail() {
  echo "zephyr_sample_ci: FAIL: $*" >&2
  exit 1
}

pass() {
  echo "zephyr_sample_ci: ok: $*"
}

# `$1` holds the line `$2` (fixed string).
has_line() {
  grep -qxF -- "$2" "$1" || fail "$1 lacks \`$2\`"
}

step_setup_key() {
  if [ ! -f samples/keelsign_hello/keelsign-dev.pem ]; then
    # doc: setup-key
    cargo build -p keelsign --release --locked
    target/release/keelsign keygen --alg lms-sha256-m32-h10 --out samples/keelsign_hello/keelsign-dev.pem
    # end doc
  else
    cargo build -p keelsign --release --locked
  fi
  pass "keelsign CLI and samples/keelsign_hello/keelsign-dev.pem"
}

step_build() {
  # doc: build
  west build -b nrf52840dk/nrf52840 samples/keelsign_hello --sysbuild -d build
  # end doc
  local app=build/keelsign_hello/zephyr mcuboot=build/mcuboot/zephyr
  for f in "$mcuboot/zephyr.hex" "$app/zephyr.signed.bin" "$app/zephyr.signed.keelsign.bin" "$app/zephyr.signed.keelsign.hex"; do
    [ -s "$f" ] || fail "$f was not built"
  done
  has_line "$mcuboot/.config" "CONFIG_KEELSIGN=y"
  has_line "$mcuboot/.config" "CONFIG_KEELSIGN_POLICY_PQ_ONLY=y"
  has_line "$mcuboot/.config" "CONFIG_BOOT_IMAGE_ACCESS_HOOKS=y"
  has_line "$mcuboot/.config" "# CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST is not set"
  has_line "$mcuboot/.config" "CONFIG_BOOT_SIGNATURE_TYPE_ECDSA_P256=y"
  has_line "$app/.config" "CONFIG_KEELSIGN_SIGN_IMAGE=y"
  local tlvs
  tlvs="$(target/release/keelsign inspect --json "$app/zephyr.signed.keelsign.bin" |
    python3 -c 'import json, sys; print(" ".join("%#06x" % t["type"] for t in json.load(sys.stdin)["unprotected"]["tlvs"]))')"
  for tlv in 0x0022 0x4ba0 0x4ba3; do
    case " $tlvs " in *" $tlv "*) ;; *) fail "zephyr.signed.keelsign.bin has no TLV $tlv (has: $tlvs)" ;; esac
  done
  # doc: verify
  imgtool verify --key ../bootloader/mcuboot/root-ec-p256.pem build/keelsign_hello/zephyr/zephyr.signed.keelsign.bin
  target/release/keelsign verify --pub build/keelsign.pub.pem build/keelsign_hello/zephyr/zephyr.signed.keelsign.bin
  # end doc
  pass "build: MCUboot with keelsign, application signed by imgtool (ECDSA P-256) and keelsign (TLVs $tlvs)"
}

step_variants() {
  # doc: variants
  python3 scripts/mcuboot_variants.py --keelsign target/release/keelsign build
  # end doc
  local out
  if out="$(target/release/keelsign verify --pub build/keelsign.pub.pem build/variants/tampered.bin 2>&1)"; then
    fail "the tampered image verified"
  fi
  case "$out" in *"image digest does not match"*) ;; *) fail "tampered image: unexpected error: $out" ;; esac
  if out="$(target/release/keelsign verify --pub build/keelsign.pub.pem build/variants/wrong-key.bin 2>&1)"; then
    fail "the wrong-key image verified"
  fi
  case "$out" in *"key ID is not in the trusted key set"*) ;; *) fail "wrong-key image: unexpected error: $out" ;; esac
  target/release/keelsign verify --pub build/keelsign.pub.pem build/variants/bad-ecdsa.bin >/dev/null ||
    fail "keelsign rejected the bad-ECDSA image (its signature does not cover the ECDSA TLV)"
  if imgtool verify --key ../bootloader/mcuboot/root-ec-p256.pem build/variants/bad-ecdsa.bin >/dev/null 2>&1; then
    fail "imgtool verified the bad-ECDSA image"
  fi
  pass "variants: tampered and wrong-key images rejected by keelsign verify; bad-ECDSA image passes keelsign, fails imgtool"
}

step_ed25519_build() {
  # doc: ed25519-build
  west build -b nrf52840dk/nrf52840 samples/keelsign_hello --sysbuild -d build-ed25519 -- -DSB_CONFIG_BOOT_SIGNATURE_TYPE_ED25519=y
  # end doc
  local app=build-ed25519/keelsign_hello/zephyr mcuboot=build-ed25519/mcuboot/zephyr
  for f in "$mcuboot/zephyr.hex" "$app/zephyr.signed.keelsign.bin" "$app/zephyr.signed.keelsign.hex"; do
    [ -s "$f" ] || fail "$f was not built"
  done
  has_line "$mcuboot/.config" "CONFIG_KEELSIGN=y"
  has_line "$mcuboot/.config" "CONFIG_KEELSIGN_POLICY_PQ_ONLY=y"
  has_line "$mcuboot/.config" "CONFIG_BOOT_SIGNATURE_TYPE_ED25519=y"
  has_line "$mcuboot/.config" "CONFIG_BOOT_IMAGE_ACCESS_HOOKS=y"
  has_line "$mcuboot/.config" "# CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST is not set"
  local tlvs
  tlvs="$(target/release/keelsign inspect --json "$app/zephyr.signed.keelsign.bin" |
    python3 -c 'import json, sys; print(" ".join("%#06x" % t["type"] for t in json.load(sys.stdin)["unprotected"]["tlvs"]))')"
  for tlv in 0x0024 0x4ba0 0x4ba3; do
    case " $tlvs " in *" $tlv "*) ;; *) fail "the Ed25519 build's zephyr.signed.keelsign.bin has no TLV $tlv (has: $tlvs)" ;; esac
  done
  imgtool verify --key ../bootloader/mcuboot/root-ed25519.pem "$app/zephyr.signed.keelsign.bin" >/dev/null ||
    fail "imgtool did not verify the Ed25519 signature"
  target/release/keelsign verify --pub build-ed25519/keelsign.pub.pem "$app/zephyr.signed.keelsign.bin" >/dev/null ||
    fail "keelsign did not verify the Ed25519 build's image"
  pass "ed25519-build: MCUboot with Ed25519 + keelsign PQ_ONLY links into the 64 KB boot partition (TLVs $tlvs)"
}

step_hybrid_build() {
  # doc: hybrid-build
  west build -b nrf52840dk/nrf52840 samples/keelsign_hello --sysbuild -d build-hybrid --cmake-only -- -DSB_CONFIG_BOOT_SIGNATURE_TYPE_ED25519=y -DSB_CONFIG_KEELSIGN_POLICY_HYBRID=y
  cmake --build build-hybrid/mcuboot --target keelsign_mcuboot keelsign_cargo
  # end doc
  local mcuboot=build-hybrid/mcuboot
  has_line "$mcuboot/zephyr/.config" "CONFIG_KEELSIGN_POLICY_HYBRID=y"
  has_line "$mcuboot/zephyr/.config" "CONFIG_BOOT_SIGNATURE_TYPE_ED25519=y"
  [ -s "$mcuboot/modules/keelsign/libkeelsign_mcuboot.a" ] || fail "the hybrid hook library was not built"
  grep -qF "KEELSIGN_ALG_ED25519" "$mcuboot/modules/keelsign/keelsign_mcuboot_keys.c" ||
    fail "the hybrid key table has no Ed25519 key"
  python3 scripts/staticlib_sizes.py --check --features ed25519 "$mcuboot/keelsign-cargo/thumbv7em-none-eabi/ffi/libkeelsign.a"
  pass "hybrid-build: hook and libkeelsign.a (ed25519) compile for the Ed25519 + LMS/HSS policy"
}

step_allow_list_refused() {
  local log=target/allow-list-refused.log rc
  set +e
  (
    # doc: allow-list-refused
    target/release/keelsign pubkey --key samples/keelsign_hello/keelsign-dev.pem --out target/keelsign-dev.pub.pem --force
    west build -b nrf52840dk/nrf52840 ../bootloader/mcuboot/boot/zephyr -d build-allow-list -p always --cmake-only -- -DCONFIG_KEELSIGN=y -DCONFIG_BOOT_IMAGE_ACCESS_HOOKS=y -DCONFIG_KEELSIGN_PUBLIC_KEY_FILE=\"$PWD/target/keelsign-dev.pub.pem\"
    # end doc
  ) >"$log" 2>&1
  rc=$?
  set -e
  [ "$rc" != 0 ] || fail "MCUboot with keelsign and the TLV allow list on configured (see $log)"
  tr -s ' \n' ' ' <"$log" | grep -qF "keelsign: CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST=y rejects keelsign TLVs 0x4BA0-0x4BA3 (image_validate.c allowed_unprot_tlvs); set it to n" ||
    fail "the allow-list build failed without keelsign's message (see $log)"
  pass "allow-list-refused: CONFIG_MCUBOOT_USE_TLV_ALLOW_LIST=y is refused at configure time"
}

step_stock_build() {
  # doc: stock-build
  west build -b nrf52840dk/nrf52840 samples/keelsign_hello --sysbuild -d build-stock -- -DSB_CONFIG_KEELSIGN=n
  # end doc
  grep -q "^CONFIG_KEELSIGN=y" build-stock/mcuboot/zephyr/.config && fail "the stock MCUboot has keelsign"
  pass "stock-build: the sample without keelsign"
}

step_sizes() {
  # doc: sizes
  python3 scripts/mcuboot_sizes.py build-stock/mcuboot/zephyr/zephyr.elf build/mcuboot/zephyr/zephyr.elf
  # end doc
}

[ $# -gt 0 ] || {
  sed -n '2,/^set -euo/p' "$0" | sed '$d'
  exit 2
}
for arg in "$@"; do
  case "$arg" in
    all) set -- setup-key build variants ed25519-build hybrid-build allow-list-refused stock-build sizes ;;
  esac
done
for step in "$@"; do
  case "$step" in
    setup-key) step_setup_key ;;
    build) step_build ;;
    variants) step_variants ;;
    ed25519-build) step_ed25519_build ;;
    hybrid-build) step_hybrid_build ;;
    allow-list-refused) step_allow_list_refused ;;
    stock-build) step_stock_build ;;
    sizes) step_sizes ;;
    *) fail "unknown step $step (see the header of $0)" ;;
  esac
done

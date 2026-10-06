#!/usr/bin/env bash
# Pinned Zephyr workspace for keelsign's MCUboot sample (SHA-62, docs/mcuboot.md#setup).
#
#   mkdir keelsign-ws && cd keelsign-ws
#   git clone https://github.com/smhasan94/keelsign
#   keelsign/scripts/zephyr-setup.sh
#
# Turns the directory that holds this repository (the "workspace", or
# $KEELSIGN_WORKSPACE) into a west workspace with keelsign as its manifest repository
# (west.yml) and installs, all inside the workspace and nothing system-wide:
#
#   .venv/              Python venv: west 1.5.0, imgtool 2.4.0, Zephyr's
#                       scripts/requirements-base.txt, MCUboot's zephyr/requirements.txt
#   zephyr/ bootloader/mcuboot/ modules/...
#                       Zephyr v4.4.2 (dccb0959) and the modules the sample needs, among
#                       them MCUboot v2.4.0 (6d3b3d2c); `west update --narrow`, depth 1
#   .zephyr-sdk-1.0.1/  Zephyr SDK 1.0.1 minimal + the arm-zephyr-eabi GNU toolchain
#                       (arm-zephyr-eabi-gcc 14.3.0), each archive SHA256-checked against
#                       the values below (sdk-ng v1.0.1 sha256.sum)
#
# Each step is skipped when its result is already there, so the script can be re-run:
# the venv and west when west is at the pin, `west init` when .west exists, `west update`
# when zephyr and bootloader/mcuboot are at their pins and every other project of the
# manifest is checked out, pip's requirements when they are installed (pip checks), the
# SDK download when the SDK is there.
# With ZEPHYR_SDK_INSTALL_DIR pointing to an existing SDK 1.0.1 with arm-zephyr-eabi,
# the SDK is not downloaded; with `west` already on PATH (and no .venv), no venv is
# created and no Python package is installed (your environment must then have Zephyr's
# requirements and imgtool 2.4.0). The workspace directory must not be a git work tree
# and may hold nothing but the entries above, so a directory like ~/code can never be
# turned into a west workspace by accident. The SDK's setup.sh is not run: nothing is
# registered in ~/.cmake; builds find the SDK through ZEPHYR_SDK_INSTALL_DIR.
#
# Needs: bash, git, curl, tar with xz, python3 >= 3.12, cmake >= 3.20, ninja; Rust with
# the thumbv7em-none-eabi target for the sample build (`rustup target add
# thumbv7em-none-eabi`). Hosts: macOS arm64, Linux x86_64.
#
# SPDX-License-Identifier: MIT OR Apache-2.0
set -euo pipefail

WEST_VERSION=1.5.0
IMGTOOL_VERSION=2.4.0
ZEPHYR_REV=dccb09599635bdff17633fa7e9dab014b91dce90
MCUBOOT_REV=6d3b3d2c38ab20c242e5b9abb04d050086383eb2
SDK_VERSION=1.0.1
SDK_URL=https://github.com/zephyrproject-rtos/sdk-ng/releases/download/v${SDK_VERSION}
# sdk-ng v1.0.1 sha256.sum
SDK_SHA256_macos_aarch64_minimal=867063901f39528a6175a80ebc20367bd6cb440593e7e2650eda30392f1f6b65
SDK_SHA256_macos_aarch64_arm=4008edb5d4840cd994aedd7f1309bfb63e7243729d57839ebf1cc83c1f17c886
SDK_SHA256_linux_x86_64_minimal=ca9bc0ff66fafca1dac9d592a36d953cf16d096a9d09b1c0357f021cf9f6a7eb
SDK_SHA256_linux_x86_64_arm=21b85981cb5a1818d9bc53d82af80f208946ec038b982ff1907287572ed3a634

die() {
  echo "zephyr-setup: $*" >&2
  exit 1
}

step() {
  echo "zephyr-setup: $*"
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# Download $1 into $2 and check it against SHA256 $3.
fetch_checked() {
  curl -fsSL --retry 3 -o "$2" "$1" || die "download failed: $1"
  local got
  got="$(sha256_of "$2")"
  [ "$got" = "$3" ] || die "SHA256 mismatch for $1: got $got, expected $3"
}

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
topdir="$(cd "${KEELSIGN_WORKSPACE:-$(dirname "$repo")}" && pwd -P)"

# ---- workspace guard -----------------------------------------------------------------
[ "$(dirname "$repo")" = "$topdir" ] ||
  die "the repository ($repo) must be directly inside the workspace ($topdir)"
[ "$(basename "$repo")" = keelsign ] ||
  die "check the repository out as \`keelsign\` (west.yml self: path), not $(basename "$repo")"
if git -C "$topdir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  die "$topdir is inside a git work tree; use a new, empty directory as the workspace"
fi
for entry in "$topdir"/* "$topdir"/.[!.]*; do
  [ -e "$entry" ] || continue
  case "$(basename "$entry")" in
    keelsign | zephyr | bootloader | modules | .west | .venv | ".zephyr-sdk-$SDK_VERSION" | .DS_Store) ;;
    *) die "$topdir holds $(basename "$entry"); the workspace may hold only keelsign and what this script installs" ;;
  esac
done

for tool in git curl tar python3 cmake ninja; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is not on PATH"
done
python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))' || die "python3 >= 3.12 is needed (Zephyr v4.4.2)"

# ---- west (venv) ---------------------------------------------------------------------
venv="$topdir/.venv"
manage_venv=1
if [ ! -x "$venv/bin/west" ] && command -v west >/dev/null 2>&1; then
  manage_venv=0
  step "using west from PATH ($(command -v west)); no venv"
fi
if [ "$manage_venv" = 1 ]; then
  if [ ! -x "$venv/bin/python" ]; then
    step "creating $venv"
    python3 -m venv "$venv"
  fi
  if [ "$("$venv/bin/python" -c 'import importlib.metadata as m; print(m.version("west"))' 2>/dev/null || true)" != "$WEST_VERSION" ]; then
    step "installing west $WEST_VERSION"
    "$venv/bin/python" -m pip install --quiet --disable-pip-version-check "west==$WEST_VERSION"
  fi
  export PATH="$venv/bin:$PATH"
fi

# ---- west workspace ------------------------------------------------------------------
if [ ! -d "$topdir/.west" ]; then
  step "west init -l keelsign in $topdir"
  (cd "$topdir" && west init -l keelsign)
fi
[ "$(cd "$topdir" && west config manifest.path)" = keelsign ] ||
  die "$topdir/.west belongs to another manifest repository"
# The west projects are there when zephyr and MCUboot are at their pins and every
# project of the manifest (west list, read locally) is a checkout.
projects_ok() {
  [ "$(git -C "$topdir/zephyr" rev-parse HEAD 2>/dev/null)" = "$ZEPHYR_REV" ] &&
    [ "$(git -C "$topdir/bootloader/mcuboot" rev-parse HEAD 2>/dev/null)" = "$MCUBOOT_REV" ] || return 1
  local paths path
  paths="$(cd "$topdir" && west list -f '{abspath}' 2>/dev/null)" || return 1
  while IFS= read -r path; do
    [ -z "$path" ] || [ "$path" = "$repo" ] || [ -e "$path/.git" ] || return 1
  done <<<"$paths"
}
if projects_ok; then
  step "west projects already at the pins (Zephyr $ZEPHYR_REV, MCUboot $MCUBOOT_REV); no west update"
else
  step "west update (Zephyr $ZEPHYR_REV and modules)"
  (cd "$topdir" && west update --narrow -o=--depth=1)
fi
[ "$(git -C "$topdir/zephyr" rev-parse HEAD)" = "$ZEPHYR_REV" ] || die "zephyr is not at $ZEPHYR_REV"
[ "$(git -C "$topdir/bootloader/mcuboot" rev-parse HEAD)" = "$MCUBOOT_REV" ] ||
  die "bootloader/mcuboot is not at $MCUBOOT_REV"

if [ "$manage_venv" = 1 ]; then
  step "installing Zephyr and MCUboot Python requirements, imgtool $IMGTOOL_VERSION"
  "$venv/bin/python" -m pip install --quiet --disable-pip-version-check \
    -r "$topdir/zephyr/scripts/requirements-base.txt" \
    "imgtool==$IMGTOOL_VERSION" \
    -r "$topdir/bootloader/mcuboot/zephyr/requirements.txt"
fi

# ---- Zephyr SDK ----------------------------------------------------------------------
sdk="${ZEPHYR_SDK_INSTALL_DIR:-$topdir/.zephyr-sdk-$SDK_VERSION}"
sdk_ok() {
  [ -f "$sdk/sdk_version" ] && [ "$(cat "$sdk/sdk_version")" = "$SDK_VERSION" ] &&
    [ -x "$sdk/gnu/arm-zephyr-eabi/bin/arm-zephyr-eabi-gcc" ]
}
if sdk_ok; then
  step "Zephyr SDK $SDK_VERSION with arm-zephyr-eabi already in $sdk"
elif [ -n "${ZEPHYR_SDK_INSTALL_DIR:-}" ] && [ -e "$sdk" ]; then
  die "ZEPHYR_SDK_INSTALL_DIR=$sdk is not a Zephyr SDK $SDK_VERSION with arm-zephyr-eabi; unset it to install one in the workspace"
else
  case "$(uname -s)/$(uname -m)" in
    Darwin/arm64) host=macos-aarch64 min_sha=$SDK_SHA256_macos_aarch64_minimal arm_sha=$SDK_SHA256_macos_aarch64_arm ;;
    Linux/x86_64) host=linux-x86_64 min_sha=$SDK_SHA256_linux_x86_64_minimal arm_sha=$SDK_SHA256_linux_x86_64_arm ;;
    *) die "no pinned Zephyr SDK $SDK_VERSION for $(uname -s)/$(uname -m) in this script" ;;
  esac
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  minimal="zephyr-sdk-${SDK_VERSION}_${host}_minimal.tar.xz"
  arm="toolchain_gnu_${host}_arm-zephyr-eabi.tar.xz"
  step "downloading $minimal and $arm (SHA256-checked)"
  fetch_checked "$SDK_URL/$minimal" "$tmp/$minimal" "$min_sha"
  fetch_checked "$SDK_URL/$arm" "$tmp/$arm" "$arm_sha"
  mkdir "$tmp/x"
  tar -xJf "$tmp/$minimal" -C "$tmp/x"
  mkdir -p "$tmp/x/zephyr-sdk-$SDK_VERSION/gnu"
  tar -xJf "$tmp/$arm" -C "$tmp/x/zephyr-sdk-$SDK_VERSION/gnu"
  rm -rf "$sdk"
  mkdir -p "$(dirname "$sdk")"
  mv "$tmp/x/zephyr-sdk-$SDK_VERSION" "$sdk"
  sdk_ok || die "the SDK in $sdk is incomplete"
  step "Zephyr SDK $SDK_VERSION installed in $sdk"
fi
"$sdk/gnu/arm-zephyr-eabi/bin/arm-zephyr-eabi-gcc" --version | head -n 1

if command -v rustup >/dev/null 2>&1 && ! rustup target list --installed 2>/dev/null | grep -qx thumbv7em-none-eabi; then
  echo "zephyr-setup: note: the sample builds libkeelsign.a for thumbv7em-none-eabi; run \`rustup target add thumbv7em-none-eabi\`" >&2
fi

echo
echo "keelsign Zephyr workspace ready in $topdir. In each shell:"
echo
echo "  export ZEPHYR_SDK_INSTALL_DIR=\"$sdk\" ZEPHYR_TOOLCHAIN_VARIANT=zephyr"
if [ "$manage_venv" = 1 ]; then
  echo "  export PATH=\"$venv/bin:\$PATH\""
fi
echo "  cd \"$repo\""

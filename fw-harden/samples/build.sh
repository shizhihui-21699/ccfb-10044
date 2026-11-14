#!/usr/bin/env bash
#
# Build the simulated IoT firmware sample trees.
#
# Produces two firmware roots (firmware_v1, firmware_v2) containing ELF
# executables and shared libraries across 32/64-bit, little/big-endian
# architectures, with deliberately different hardening profiles so that
# `fw-harden scan` and `fw-harden diff` have realistic material.
#
# Storyline encoded in the flags:
#   * libmgmt.so  : weak vendor build in v1, fully remediated in v2.
#   * gatewayd    : v1 was fully hardened; v2's build-system overhaul
#                   dropped the hardening linker/compile flags (NX, RELRO
#                   and stack canary regress) even though the C source was
#                   remediated (dangerous calls mostly removed).
#   * agentd      : fully static, then stripped — exercises the analyzer's
#                   no-symbol-table "unknown" path.
#   * libwatchdog : new in v2 (new binary + new DT_NEEDED in gatewayd).
#   * factory-tool: present only in v1 (removed binary in the diff).
#
# Requirements: homebrew LLVM (clang + lld + llvm-strip), i.e.
#   brew install llvm lld
#
# Usage: ./build.sh [out_dir]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$SCRIPT_DIR/src"
OUT_DIR="${1:-$SCRIPT_DIR/build}"
LLVM_BIN="${LLVM_BIN:-/opt/homebrew/opt/llvm/bin}"
CLANG="$LLVM_BIN/clang"
STRIP="$LLVM_BIN/llvm-strip"

# tag | clang triple. Covers 32/64-bit and all four width/endianness combos.
TARGETS=(
    "x86_64|x86_64-linux-gnu"
    "i386|i386-linux-gnu"
    "aarch64|aarch64-linux-gnu"
    "armv7|arm-linux-gnueabihf"
    "mips32-be|mips-linux-gnu"
    "mips32-le|mipsel-linux-gnu"
    "mips64-be|mips64-linux-gnuabi64"
    "mips64-le|mips64el-linux-gnuabi64"
    "ppc32-be|powerpc-linux-gnu"
    "ppc64-le|powerpc64le-linux-gnu"
    "riscv32|riscv32-linux-gnu"
    "riscv64|riscv64-linux-gnu"
)

COMMON=(-nostdlib -ffreestanding -fuse-ld=lld)

# Shared flag arrays, filled per artifact/version below.
declare -a cflags ldflags

# --- libmgmt.so profiles ---------------------------------------------------
libmgmt_flags() {
    if [[ "$1" == v1 ]]; then
        cflags=(-O1 -fno-stack-protector -fPIC)
        ldflags=(-Wl,-z,relro -Wl,-z,execstack -Wl,-z,undefs)
    else
        cflags=(-O2 -fstack-protector-strong -fPIC -DFW_V2)
        ldflags=(-Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,-z,undefs)
    fi
}

# --- gatewayd profiles (v1 strong, v2 regressed build flags) ---------------
gateway_flags() {
    if [[ "$1" == v1 ]]; then
        # Source is the legacy variant (no FW_V2) but the toolchain was
        # configured correctly.
        cflags=(-O2 -fstack-protector-strong -fPIE)
        ldflags=(-Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,-z,undefs)
    else
        # Remediated source (FW_V2), but the new build system lost the
        # hardening flags: no canary, executable stack, lazy binding.
        cflags=(-O2 -fno-stack-protector -fPIE -DFW_V2)
        ldflags=(-Wl,-z,relro -Wl,-z,execstack -Wl,-z,undefs)
    fi
}

# --- agentd static profiles ------------------------------------------------
agent_flags() {
    if [[ "$1" == v1 ]]; then
        cflags=(-O1 -fno-stack-protector -fPIC)
    else
        cflags=(-O2 -fstack-protector-strong -fPIC -DFW_V2)
    fi
    ldflags=(-Wl,-z,undefs)
}

build_tree() {
    local version="$1" tag="$2" triple="$3"
    local out="$OUT_DIR/firmware_$version/arch/$tag"
    mkdir -p "$out"

    # --- shared library libmgmt.so -----------------------------------------
    libmgmt_flags "$version"
    "$CLANG" --target="$triple" "${COMMON[@]}" \
        "${cflags[@]}" -shared -Wl,-soname,libmgmt.so.1 \
        "${ldflags[@]}" \
        "$SRC_DIR/libmgmt.c" -o "$out/libmgmt.so.1"
    ln -sf libmgmt.so.1 "$out/libmgmt.so"

    # --- v2-only libwatchdog.so + gatewayd DT_NEEDED on it -----------------
    local -a extra_libs=()
    if [[ "$version" == v2 ]]; then
        "$CLANG" --target="$triple" "${COMMON[@]}" \
            -O2 -fstack-protector-strong -fPIC -DFW_V2 -shared \
            -Wl,-soname,libwatchdog.so.1 \
            -Wl,-z,relro,-z,now -Wl,-z,noexecstack -Wl,-z,undefs \
            "$SRC_DIR/libwatchdog.c" -o "$out/libwatchdog.so.1"
        ln -sf libwatchdog.so.1 "$out/libwatchdog.so"
        extra_libs=(-lwatchdog)
    fi

    # --- gatewayd: dynamic PIE executable -----------------------------------
    gateway_flags "$version"
    "$CLANG" --target="$triple" "${COMMON[@]}" \
        "${cflags[@]}" -pie \
        -Wl,-rpath,/opt/firmware/lib -Wl,--allow-shlib-undefined \
        "${ldflags[@]}" \
        "$SRC_DIR/gatewayd.c" -L"$out" -lmgmt ${extra_libs[@]+"${extra_libs[@]}"} \
        -o "$out/gatewayd"

    # --- agentd: fully static, then stripped -------------------------------
    agent_flags "$version"
    "$CLANG" --target="$triple" "${COMMON[@]}" \
        "${cflags[@]}" -static "${ldflags[@]}" \
        "$SRC_DIR/agentd.c" -o "$out/agentd"
    "$STRIP" "$out/agentd"

    # --- v1-only factory diagnostic ----------------------------------------
    if [[ "$version" == v1 ]]; then
        "$CLANG" --target="$triple" "${COMMON[@]}" \
            -O1 -fno-stack-protector -fPIE -pie \
            -Wl,-z,relro -Wl,-z,execstack -Wl,-z,undefs \
            "$SRC_DIR/factory_tool.c" -o "$out/factory-tool"
    fi
}

# A legacy non-PIE ET_EXEC build for one target, so the PIE-disabled path
# is exercised by an actual executable rather than only by unit fixtures.
build_legacy_exec() {
    local version="$1"
    local out="$OUT_DIR/firmware_$version/arch/x86_64"
    "$CLANG" --target=x86_64-linux-gnu "${COMMON[@]}" \
        -O1 -fno-stack-protector -fno-pie -no-pie \
        -Wl,-z,execstack -Wl,-z,undefs -Wl,--allow-shlib-undefined \
        "$SRC_DIR/gatewayd.c" -L"$out" -lmgmt \
        -Wl,-rpath,/opt/firmware/lib \
        -o "$out/legacy-flasher"
}

main() {
    command -v "$CLANG" >/dev/null || { echo "clang not found at $CLANG (brew install llvm)" >&2; exit 1; }
    rm -rf "$OUT_DIR/firmware_v1" "$OUT_DIR/firmware_v2"

    for spec in "${TARGETS[@]}"; do
        tag="${spec%%|*}"
        triple="${spec##*|}"
        for version in v1 v2; do
            echo "== $version $tag ($triple) =="
            build_tree "$version" "$tag" "$triple"
        done
    done

    build_legacy_exec v1
    build_legacy_exec v2

    # non-ELF files to prove the walker skips them
    for version in v1 v2; do
        echo '{"manifest":"sample"}' > "$OUT_DIR/firmware_$version/manifest.json"
        printf 'not an elf\n' > "$OUT_DIR/firmware_$version/README.txt"
    done

    echo
    echo "done. sample trees under $OUT_DIR"
}

main "$@"

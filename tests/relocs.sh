#!/bin/sh
# Check the base relocations that "dumpPE -r" reports for an ARM64 PE32+ image
# against llvm-readobj --coff-basereloc: the same DIR64 (and HIGHLOW) entries
# with the same RVAs, and the same DIR64 count.
#
# Usage: relocs.sh <dumpPE> [<a64.exe>]
#
# Without an image, the test builds tests/fixture-a64.c (no libc, pointers in
# .data, so the linker emits DIR64 relocations) with clang and lld-link.
# Prints "relocs: OK <n>" on success. Prints "SKIP: <reason>" and exits 0 when
# clang, lld-link or llvm-readobj is missing.
set -e

here=$(cd "$(dirname "$0")" && pwd)
dump="$1"
pe="$2"

if ! command -v llvm-readobj >/dev/null 2>&1; then
    echo "SKIP: llvm-readobj not found"
    exit 0
fi

tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT

if [ -z "$pe" ]; then
    if ! command -v clang >/dev/null 2>&1 || ! command -v lld-link >/dev/null 2>&1; then
        echo "SKIP: clang or lld-link not found, cannot build tests/fixture-a64.c"
        exit 0
    fi
    clang --target=aarch64-pc-windows-msvc -O1 -ffreestanding -fno-builtin \
        -c "$here/fixture-a64.c" -o "$tmp/fixture-a64.obj"
    lld-link /machine:arm64 /subsystem:console /entry:mainCRTStartup /nodefaultlib \
        "/out:$tmp/fixture-a64.exe" "$tmp/fixture-a64.obj" >/dev/null
    pe="$tmp/fixture-a64.exe"
fi

# Normalize "0x00002010" (dumpPE) and "0x2010" (llvm-readobj) to "0x2010"
norm='s/0x0*\([0-9a-f]\)/0x\1/'

# Ours: "RELOC <type> 0x<rva>"
"$dump" -r "$pe" | awk '$1 == "RELOC" { print $2, $3 }' | sed "$norm" | sort > "$tmp/ours"

# Reference: llvm-readobj prints "Type: <T>" then "Address: 0x<rva>" per entry.
# ABSOLUTE padding entries are not reported by dumpPE, so they are left out.
llvm-readobj --coff-basereloc "$pe" |
    awk '/Type:/ { t = $2 } /Address:/ { if (t == "DIR64" || t == "HIGHLOW") print t, $2 }' |
    sed "$norm" | sort > "$tmp/ref"

dir64=$(grep -c '^DIR64 ' "$tmp/ours" || true)
ref_dir64=$(llvm-readobj --coff-basereloc "$pe" | grep -c 'Type: DIR64' || true)

if [ "$dir64" -eq 0 ]; then
    echo "FAIL: no DIR64 relocations in $pe"
    exit 1
fi
if [ "$dir64" -ne "$ref_dir64" ]; then
    echo "FAIL: DIR64 count $dir64, llvm-readobj reports $ref_dir64"
    exit 1
fi
if ! diff "$tmp/ref" "$tmp/ours" > "$tmp/diff"; then
    echo "FAIL: relocation entries differ from llvm-readobj (< llvm-readobj, > dumpPE)"
    cat "$tmp/diff"
    exit 1
fi

echo "relocs: OK $dir64"

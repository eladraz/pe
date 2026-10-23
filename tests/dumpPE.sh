#!/bin/sh
# Run dumpPE on a PE file and verify its exit code and expected export names.
# Usage: dumpPE.sh <dumpPE> <pe-file> <export-name>...
set -e

dump="$1"
pefile="$2"
shift 2

out=$("$dump" "$pefile")
echo "$out"

for name in "$@"; do
    echo "$out" | grep -qw "$name" || { echo "FAIL: export $name not found"; exit 1; }
done
echo "PASS"

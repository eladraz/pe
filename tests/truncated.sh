#!/bin/sh
# Truncate a PE file at several sizes and verify dumpPE rejects each copy with
# a clean error (exit code 1): no crash (signal) and no hang.
# Usage: truncated.sh <dumpPE> <pe-file>
dump="$1"
pefile="$2"
tmp=$(mktemp) || exit 1
trap 'rm -f "$tmp"' EXIT
for n in 1 64 100 200 400 600; do
    head -c "$n" "$pefile" > "$tmp"
    timeout 20 "$dump" "$tmp" > /dev/null 2>&1
    rc=$?
    if [ "$rc" -ne 1 ]; then
        echo "FAIL: truncated to $n bytes, exit code $rc (expected 1)"
        exit 1
    fi
done
echo "PASS"

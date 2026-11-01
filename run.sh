#!/bin/bash
set -eo pipefail
idx=$1; span=${2:-27000000}; total=4294967296
lo=$(( idx * span )); hi=$(( lo + span ))
[ "$hi" -gt "$total" ] && hi=$total
echo "shard $idx range [$lo,$hi) threads=${TW_THREADS:-4}"
gcc -O3 -march=native -pthread twmt.c -o twmt -lsecp256k1 -lcrypto
TW_WORDS=words.txt TW_ORACLE=oracle.bin TW_THREADS=${TW_THREADS:-4} ./twmt --range "$lo" "$hi" cur.txt hits.tsv

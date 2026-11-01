#!/bin/bash
set -eo pipefail
idx=$1; base=1517788800; span=4276800; total=1534896000
lo=$(( base + idx * span )); hi=$(( lo + span ))
[ "$hi" -gt "$total" ] && hi=$total
echo "shard $idx range [$lo,$hi) = $(date -u -d @$lo +%F) .. $(date -u -d @$hi +%F)"
gcc -O3 -march=native -pthread twmob.c -o twmob -lsecp256k1 -lcrypto
TW_RANDS=darwin TW_NWORDS=12 TW_WORDS=words.txt TW_VICTIMS=oracle.bin TW_THREADS=${TW_THREADS:-4} ./twmob --range "$lo" "$hi" cur2.$idx.txt hits2.$idx.tsv

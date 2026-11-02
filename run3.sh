#!/bin/bash
set -eo pipefail
idx=$(( ${1:-0} + ${START:-0} ))
line=$(sed -n "$((idx+1))p" months.tsv || true)
if [ -z "$line" ]; then echo "no month index $idx"; exit 0; fi
mid=$(echo "$line"|cut -f1); lo=$(echo "$line"|cut -f2); hi=$(echo "$line"|cut -f3); tag=$(echo "$line"|cut -f4)
echo "month#$mid $tag range [$lo,$hi) = $(date -u -d @$lo +%F) .. $(date -u -d @$hi +%F)"
gcc -O3 -march=native -pthread twmob.c -o twmob -lsecp256k1 -lcrypto
TW_RANDS=darwin TW_NWORDS=12 TW_WORDS=words.txt TW_ORACLE=oracle.bin TW_THREADS=${TW_THREADS:-4} ./twmob --range "$lo" "$hi" cur3.$mid.txt hits3.$mid.tsv
echo "month#$mid done hits=$(wc -l < hits3.$mid.tsv 2>/dev/null || echo 0)"

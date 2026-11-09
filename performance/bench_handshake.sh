#!/bin/bash
# bench_handshake.sh — Part D handshake timing, end-to-end, >=30 runs each.
# Times a full minimal session (TCP connect -> greeting decrypted -> STATUS,
# UNLOCK, LOCK, QUIT) for v1 and v2. Both run the same record sequence, so the
# v2 - v1 delta is the handshake security cost (2048-bit ephemeral DH + RSA
# verify + HKDF) rather than the records.
#
# Usage: ./bench_handshake.sh <smartlock_dir> <v2_skeleton_dir> <instance.txt> [runs]
# Example (from the course tree):
#   ./bench_handshake.sh ../../extracted/smartlock ../../extracted/v2_skeleton \
#                        ../../extracted/smartlock/instance.txt 30
set -u
SM="$1"; V2="$2"; INST="$3"; RUNS="${4:-30}"; PORT=9094
OUT="${OUT:-handshake.csv}"

bench() {  # $1=label $2=lockbin $3=hubbin $4=lockdir
  local label="$1" lockbin="$2" hubbin="$3" lockdir="$4"
  pkill -f "$lockbin" 2>/dev/null; sleep 0.3
  ( cd "$lockdir" && "./$lockbin" "$INST" >/tmp/bh_lock.txt 2>&1 ) &
  sleep 0.6
  for i in $(seq 1 "$RUNS"); do
    local t0 t1
    t0=$(date +%s.%N)
    ( cd "$lockdir" && "./$hubbin" "$INST" 127.0.0.1 $PORT >/dev/null 2>&1 )
    t1=$(date +%s.%N)
    awk "BEGIN{printf \"$label,%.6f\n\", $t1-$t0}"
  done
  pkill -f "$lockbin" 2>/dev/null
}

echo "version,seconds" > "$OUT"
bench v1 lock_server hub_client  "$SM" >> "$OUT"
bench v2 lock_server2 hub_client2 "$V2" >> "$OUT"

python3 - "$OUT" <<'PY'
import sys, statistics as st
rows = {}
for ln in open(sys.argv[1]).read().splitlines()[1:]:
    v, s = ln.split(','); rows.setdefault(v, []).append(float(s))
print(f"Handshake / full-session wall-clock, {len(next(iter(rows.values())))} runs each:")
for v, xs in rows.items():
    print(f"  {v}: mean {st.mean(xs)*1000:7.2f} ms  sd {st.pstdev(xs)*1000:6.2f} ms")
if 'v1' in rows and 'v2' in rows:
    print(f"  v2 - v1 (handshake security cost): {(st.mean(rows['v2'])-st.mean(rows['v1']))*1000:.2f} ms")
print(f"[wrote {sys.argv[1]}]")
PY

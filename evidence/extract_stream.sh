#!/bin/bash
# extract_stream.sh <pcap> <out.txt>  — reassemble TCP stream 0 to wire text
tshark -r "$1" -q -z follow,tcp,raw,0 2>/dev/null > /tmp/_follow.txt
python3 - "$2" <<'PY'
import re,sys
out=sys.argv[1]
lines=open('/tmp/_follow.txt').read().splitlines()
blob=b''.join(bytes.fromhex(l.strip()) for l in lines if re.fullmatch(r'[0-9a-fA-F]+',l.strip()) and len(l.strip())>=2)
open(out,'wb').write(blob)
print("wrote",out,len(blob),"bytes")
PY

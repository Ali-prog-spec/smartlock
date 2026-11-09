SmartLock Assignment 2 — Muhammad Ali, 23i-0008, Section E
==========================================================

Toolchain: g++ 11+ (C++17), OpenSSL libcrypto (dev headers). Built/tested on Kali
Linux with g++ 15.2 and OpenSSL 3.6.  sudo apt install build-essential libssl-dev

SUBMISSION LAYOUT
-----------------
  23i-0008-E-REPORT.pdf        full report (Parts A-D), evidence inline
  answers.txt                  Part A recovered secrets (key = value)
  securelink2.cpp              completed Part C module (top level, exact name)
  exploits/                    the five Part A exploits + one shared header
  performance/                 Part D benchmark, raw CSV data, chart
  evidence/                    captures (.pcap), reassembled streams, tool output
  v2_changes/                  (empty — the provided scaffold was NOT modified)

------------------------------------------------------------------
PART A — build the v1 system and generate MY instance (what I attack)
------------------------------------------------------------------
  make -C smartlock
  cd smartlock && ./instance_generator 23i-0008      # writes instance.txt
  ./lock_server instance.txt                         # terminal 1 (the lock)
  ./hub_client  instance.txt 127.0.0.1               # terminal 2 (a normal hub)

CAPTURE + REASSEMBLE (how the stream files in evidence/ were made)
  dumpcap -i lo -f "tcp port 9094" -w session.pcap   # capture a session
  evidence/extract_stream.sh session.pcap stream.txt # pcap -> wire-text stream
  # (equivalently: Wireshark -> right click -> Follow TCP Stream -> Save As)

BUILD + RUN THE EXPLOITS (each builds standalone; shared header auto-included)
  cd exploits
  g++ -std=c++17 -O2 -Wall 23i-0008-E-TASKA1-V1.cpp -o taska1 -lcrypto   # downgrade
  g++ -std=c++17 -O2 -Wall 23i-0008-E-TASKA2-V1.cpp -o taska2 -lcrypto   # MITM
  g++ -std=c++17 -O2 -Wall 23i-0008-E-TASKA3-V1.cpp -o taska3 -lcrypto   # keying
  g++ -std=c++17 -O2 -Wall 23i-0008-E-TASKA4-V1.cpp -o taska4 -lcrypto   # nonce reuse
  g++ -std=c++17 -O2 -Wall 23i-0008-E-TASKA5-V1.cpp -o taska5 -lcrypto   # replay

  # TASKA1 downgrade (on-path relay; point the hub at the relay's port):
  ./taska1 8888 127.0.0.1 9094   &    ./hub_client instance.txt 127.0.0.1 8888
  # TASKA2 MITM (add --tamper to forge an UNLOCK the hub never sent):
  ./taska2 8889 127.0.0.1 9094 [--tamper]  &  ./hub_client instance.txt 127.0.0.1 8889
  # TASKA3 keying recovery (reads a captured stream -> b and the flag):
  ./taska3 ../evidence/v1_stream.txt
  # TASKA4 nonce reuse (two-time pad -> STATUS reply + nonce_xor_hex):
  ./taska4 ../evidence/v1_stream.txt
  # TASKA5 replay (reconnect + resend the captured UNLOCK; re-run to see the counter climb):
  ./taska5 ../evidence/v1_stream.txt 127.0.0.1 9094

PIN crack (A.1): feed the captured MD5 pinhash to John (or hashcat with a GPU):
  john --format=raw-md5 --mask='?w?d?d?d' --wordlist=smartlock/pin_wordlist.txt pin.hash
  # -> violet102      (see evidence/A3-pin_crack_john.txt)

------------------------------------------------------------------
PART C — build and run v2 (my securelink2.cpp in the provided scaffold)
------------------------------------------------------------------
  cp securelink2.cpp v2_skeleton/          # top-level module -> scaffold
  make -C v2_skeleton
  ./v2_skeleton/lock_server2 smartlock/instance.txt
  ./v2_skeleton/hub_client2  smartlock/instance.txt 127.0.0.1
  # self-check of the six C.1 properties:
  cd v2_skeleton && cp ../evidence/securelink2_selfcheck.cpp .
  g++ -std=c++17 -O2 -Wall securelink2_selfcheck.cpp securelink2.cpp -o selfcheck -lcrypto && ./selfcheck

------------------------------------------------------------------
PART D — performance
------------------------------------------------------------------
  # record layer (self-contained within the submission):
  cd performance
  g++ -std=c++17 -O2 -Wall 23i-0008-E-TASKD-V1.cpp ../securelink2.cpp -I. -o taskd -lcrypto
  ./taskd --csv perf.csv
  # handshake wall-clock (needs both built systems):
  ./bench_handshake.sh ../smartlock ../v2_skeleton ../smartlock/instance.txt 30
  # chart:
  python3 make_chart.py        # writes perf_chart.png

NOTES
-----
- All exploits read values from a capture; no instance value is hard-coded.
- answers.txt values were recovered on the wire, not read from instance.txt.
- All interception/spoofing was done inside an isolated host-only lab (see the
  report's "Scope and ethics"). No build output (binaries/.o) is included.
- The RSA keypair in instance.txt is not seeded from the roll (OpenSSL RNG), so a
  regenerated instance will match on every value except rsa_priv_b64/rsa_pub_b64;
  all attacked values (p, g, b, B, pin, nonce, flag, port) are reproducible.

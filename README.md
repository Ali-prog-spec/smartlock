# SmartLock — Break It, Then Build It

CS3002 Information Security · Assignment 2 · **Muhammad Ali (23i-0008, Section E)**

A security engagement on *SmartLock*, a toy smart-door-lock protocol (a lock server and a
home hub talking over plain TCP). The work has two halves: first I take the shipped version
(**v1**) apart stage by stage and prove each weakness with a working exploit, then I design and
build a fixed version (**v2**) and show the same attacks no longer work.

> ⚠️ Everything here was run in an isolated lab against my own instance. The exploits are for
> coursework and defensive learning only — don't point them at anything you don't own.

## The five stages, and how v1 fails at each

| Stage | v1 weakness | My exploit | Property broken |
|-------|-------------|-----------|-----------------|
| Negotiation | suite list unauthenticated, `NULL` offered | `TASKA1` downgrade relay | confidentiality |
| Authentication | self-signed cert never checked, DH unsigned | `TASKA2` MITM relay | authentication |
| Keying | ~40-bit DH prime, static exponent, no KDF | `TASKA3` baby-step giant-step | key confidentiality + forward secrecy |
| Message protection | same (key, nonce) every record | `TASKA4` two-time pad | confidentiality + integrity |
| Teardown | no sequence numbers, unauthenticated close | `TASKA5` replay | integrity / freshness |

## What v2 fixes

Strong-only suite negotiation (no `NULL`, fail-closed) · pinned + verified certificate ·
fresh 2048-bit **ephemeral** DH with a **signed** transcript · **HKDF-SHA256** key derivation
(per direction) · a **unique nonce per record** · and a **sequence-bound AEAD** so replays,
reorders and tampering are rejected. All of this lives in `securelink2.cpp`.

## Layout

```
securelink2.cpp         the v2 security core (the graded module)
answers.txt             recovered secrets (flag, DH exponent, PIN, nonce-XOR)
exploits/               the five Part A exploits + a shared capture-parser header
performance/            benchmark tool, raw CSV data, and the cost-of-security chart
evidence/               packet captures, reassembled streams, and tool output
23i-0008-E-REPORT.pdf   full write-up (Parts A–D)
README.txt              detailed build & run instructions
```

## Quick start

```bash
# build the v1 system and generate the instance
make -C smartlock
cd smartlock && ./instance_generator 23i-0008

# build and run an exploit (keying recovery -> the flag)
g++ -std=c++17 -O2 -Wall exploits/23i-0008-E-TASKA3-V1.cpp -o taska3 -lcrypto
./taska3 evidence/v1_stream.txt

# build v2 and self-check the six fixes
make -C v2_skeleton
```

See `README.txt` for the full command list for every exploit and for Parts C and D.

## Note on tools & AI use

The assignment permits AI assistance for drafting code; I'm responsible for all of it and
defend it in the oral viva. The crypto is OpenSSL (`libcrypto`); captures use
tshark/dumpcap; the PIN was cracked with John the Ripper.

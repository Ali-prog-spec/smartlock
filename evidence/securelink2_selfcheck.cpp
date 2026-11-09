// securelink2_selfcheck.cpp — exercises the six Part C.1 checks on securelink2.cpp
// Muhammad Ali, 23i-0008, Section E
// Build (from v2_skeleton/, with your securelink2.cpp beside it):
//   g++ -std=c++17 -O2 -Wall securelink2_selfcheck.cpp securelink2.cpp -o selfcheck -lcrypto
//   ./selfcheck
#include "securelink2.hpp"
#include <cstdio>
#include <string>
#include <vector>
#include <stdexcept>
using namespace sl2;

static int pass = 0, fail = 0;
static void check(const char* name, bool ok) {
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (ok) pass++; else fail++;
}

int main() {
    printf("securelink2 self-check (Part C.1)\n");

    // 1. never selects NULL, never downgrades
    auto ss = strong_suites();
    bool noNull = true; for (auto& s : ss) if (s == "NULL") noNull = false;
    check("1a strong_suites() excludes NULL", noNull && !ss.empty());
    check("1b choose_suite picks strongest common (AES256 over AES128)",
          choose_suite({"AES128-GCM","AES256-GCM"}) == "AES256-GCM");
    check("1c choose_suite aborts (\"\") on a NULL-only offer (no downgrade)",
          choose_suite({"NULL"}) == "");
    check("1d choose_suite never returns NULL",
          choose_suite({"NULL","AES128-GCM"}) == "AES128-GCM");

    // 2. KDF, not the raw secret
    std::vector<uint8_t> secret(256, 0x11);
    auto k = derive_key(secret, "AES256-GCM", "c2s");
    bool rightLen = (k.size() == 32);
    bool notRaw = (k != std::vector<uint8_t>(secret.begin(), secret.begin() + 32));
    auto k2 = derive_key(secret, "AES256-GCM", "s2c");
    check("2a derive_key returns 32 bytes for AES256-GCM", rightLen);
    check("2b derive_key output != raw secret", notRaw);
    check("2c derive_key gives different keys per direction (c2s != s2c)", k != k2);

    // 3. unique nonce per record
    bool uniq = (make_nonce(0) != make_nonce(1)) && (make_nonce(1) != make_nonce(2))
             && (make_nonce(5) == make_nonce(5)) && (make_nonce(0).size() == 12);
    check("3 make_nonce unique per seqno and 12 bytes", uniq);

    // 4. AEAD seals and opens correctly
    std::string pt = "DOOR OPENED (unlock #7)";
    auto rec = seal(k, 0, pt);
    bool roundtrip = false;
    try { roundtrip = (open_record(k, rec, 0) == pt); } catch (...) {}
    check("4 seal then open at same seqno round-trips", roundtrip);

    // 5. rejects replay / out-of-order / tamper
    bool rejReplay = false, rejReorder = false, rejTamper = false;
    auto r0 = seal(k, 0, "UNLOCK");
    auto r1 = seal(k, 1, "STATUS");
    try { open_record(k, r0, 1); } catch (...) { rejReplay = true; }   // record#0 opened as #1
    try { open_record(k, r1, 0); } catch (...) { rejReorder = true; }  // record#1 opened as #0
    auto bad = r0; bad[0] ^= 0xff;
    try { open_record(k, bad, 0); } catch (...) { rejTamper = true; }  // flipped byte
    check("5a replayed record (wrong seqno) rejected", rejReplay);
    check("5b out-of-order record rejected", rejReorder);
    check("5c tampered record rejected", rejTamper);

    printf("\nTOTAL: %d passed, %d failed\n", pass, fail);
    return fail == 0 ? 0 : 1;
}

// 23i-0008-E-TASKD-V1.cpp  —  Part D: performance tooling (record layer)
// SmartLock Assignment 2 — Muhammad Ali, 23i-0008, Section E
//
// Measures the cost of v2's record protection against the v1 AES256-GCM baseline,
// on the same machine with the same flags. It reports, for both versions:
//   * per-record wire overhead (bytes added vs the plaintext)
//   * time to seal and to open one 1 KiB record
//   * throughput (MB/s) sealing and opening 1 KiB records
// over several runs, with mean and standard deviation. Handshake time is measured
// separately end-to-end with the real binaries (see performance/bench_handshake.sh),
// because it is dominated by the 2048-bit DH / RSA verify that live in the scaffold.
//
// v1 baseline here = AES-256-GCM with the RAW shared secret as key and a STATIC
// nonce (exactly v1's record path). v2 = sl2::seal/open_record (HKDF key, unique
// nonce per sequence number, sequence bound into the AAD).
//
// BUILD (from performance/, with ../securelink2.cpp and ../securelink2.hpp):
//   g++ -std=c++17 -O2 -Wall 23i-0008-E-TASKD-V1.cpp ../securelink2.cpp -I. -o taskd -lcrypto
// RUN:
//   ./taskd                 # human-readable table
//   ./taskd --csv perf.csv  # also write machine-readable rows for the chart

#include "securelink2.hpp"           // local copy of the v2 interface (build convenience)
#include <openssl/evp.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>
#include <cmath>

using clk = std::chrono::steady_clock;
static double secs(clk::time_point a, clk::time_point b) {
    return std::chrono::duration<double>(b - a).count();
}
static void stats(const std::vector<double>& v, double& mean, double& sd) {
    mean = 0; for (double x : v) mean += x; mean /= v.size();
    double s = 0; for (double x : v) s += (x - mean) * (x - mean);
    sd = std::sqrt(s / v.size());
}

// ---- v1 baseline record path: raw key, static nonce, AES-256-GCM ----------
static std::vector<uint8_t> v1_seal(const std::vector<uint8_t>& key,
                                    const std::vector<uint8_t>& nonce, const std::string& pt) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());
    std::vector<uint8_t> out(pt.size()); int len = 0;
    EVP_EncryptUpdate(ctx, out.data(), &len, (const unsigned char*)pt.data(), (int)pt.size());
    int outl = len; EVP_EncryptFinal_ex(ctx, out.data() + outl, &len); outl += len; out.resize(outl);
    std::vector<uint8_t> tag(16); EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data());
    EVP_CIPHER_CTX_free(ctx);
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}
static std::string v1_open(const std::vector<uint8_t>& key,
                           const std::vector<uint8_t>& nonce, const std::vector<uint8_t>& in) {
    const EVP_CIPHER* c = EVP_aes_256_gcm(); size_t clen = in.size() - 16;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, c, nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce.size(), nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data());
    std::vector<uint8_t> out(clen); int len = 0;
    EVP_DecryptUpdate(ctx, out.data(), &len, in.data(), (int)clen); int outl = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)(in.data() + clen));
    EVP_DecryptFinal_ex(ctx, out.data() + outl, &len);
    EVP_CIPHER_CTX_free(ctx);
    out.resize(outl + len); return std::string(out.begin(), out.end());
}

int main(int argc, char** argv) {
    const char* csv = nullptr;
    for (int i = 1; i < argc; ++i) if (!strcmp(argv[i], "--csv") && i + 1 < argc) csv = argv[++i];

    const size_t REC = 1024;                 // 1 KiB records
    const int    N   = 10000;                // records per throughput run
    const int    RUNS = 7;                   // >= 5 runs
    std::string plain(REC, 'A');

    std::vector<uint8_t> key(32, 0x11);      // a derived 256-bit key (same for both paths)
    std::vector<uint8_t> v1nonce(12, 0x22);  // v1's STATIC nonce

    printf("SmartLock Part D — record-layer performance (1 KiB records)\n");
    printf("Intel i7-9750H @ 2.60GHz, g++ -O2 -std=c++17, OpenSSL 3.x; %d records/run, %d runs\n\n", N, RUNS);

    // ---- per-record wire overhead ----
    auto r1 = v1_seal(key, v1nonce, plain);
    auto r2 = sl2::seal(key, 0, plain);
    // on the wire a record is "type:MSG\t..." with the ct in hex. v1 also sends a
    // nonce field; v2 sends none (nonce is implicit in the sequence number).
    size_t v1_wire = std::string("type:MSG\tnonce:").size() + v1nonce.size()*2
                   + std::string("\tct:").size() + r1.size()*2;
    size_t v2_wire = std::string("type:MSG\trec:").size() + r2.size()*2;
    printf("Per-record overhead (plaintext = %zu bytes):\n", REC);
    printf("  v1: sealed %zu B (AEAD expansion +%zu), wire line %zu B (overhead +%zu)\n",
           r1.size(), r1.size()-REC, v1_wire, v1_wire-REC);
    printf("  v2: sealed %zu B (AEAD expansion +%zu), wire line %zu B (overhead +%zu)\n\n",
           r2.size(), r2.size()-REC, v2_wire, v2_wire-REC);

    // ---- throughput: seal then open N records ----
    std::vector<double> v1s, v1o, v2s, v2o;
    for (int run = 0; run < RUNS; ++run) {
        // v1 seal
        auto t0 = clk::now();
        for (int i = 0; i < N; ++i) { volatile size_t z = v1_seal(key, v1nonce, plain).size(); (void)z; }
        auto t1 = clk::now();
        // v1 open
        auto rr = v1_seal(key, v1nonce, plain);
        auto t2 = clk::now();
        for (int i = 0; i < N; ++i) { volatile size_t z = v1_open(key, v1nonce, rr).size(); (void)z; }
        auto t3 = clk::now();
        // v2 seal
        auto t4 = clk::now();
        for (int i = 0; i < N; ++i) { volatile size_t z = sl2::seal(key, i, plain).size(); (void)z; }
        auto t5 = clk::now();
        // v2 open (open each at its own seqno)
        std::vector<std::vector<uint8_t>> recs(N);
        for (int i = 0; i < N; ++i) recs[i] = sl2::seal(key, i, plain);
        auto t6 = clk::now();
        for (int i = 0; i < N; ++i) { volatile size_t z = sl2::open_record(key, recs[i], i).size(); (void)z; }
        auto t7 = clk::now();

        double mb = (double)N * REC / (1024.0 * 1024.0);
        v1s.push_back(mb / secs(t0, t1));
        v1o.push_back(mb / secs(t2, t3));
        v2s.push_back(mb / secs(t4, t5));
        v2o.push_back(mb / secs(t6, t7));
    }
    double m, s;
    printf("Throughput (MB/s, mean +/- sd over %d runs):\n", RUNS);
    struct Row { const char* n; std::vector<double>* v; } rows[] =
        {{"v1 seal", &v1s}, {"v1 open", &v1o}, {"v2 seal", &v2s}, {"v2 open", &v2o}};
    FILE* f = csv ? fopen(csv, "w") : nullptr;
    if (f) fprintf(f, "metric,mean,sd\n");
    for (auto& r : rows) {
        stats(*r.v, m, s);
        printf("  %-8s %9.1f +/- %6.1f\n", r.n, m, s);
        if (f) fprintf(f, "%s,%.3f,%.3f\n", r.n, m, s);
    }
    // per-record latency (us) from throughput
    printf("\nPer-record latency (1 KiB):\n");
    stats(v1s, m, s); printf("  v1 seal %.2f us,", REC/(1024.0*1024.0)/m*1e6);
    stats(v1o, m, s); printf("  v1 open %.2f us\n", REC/(1024.0*1024.0)/m*1e6);
    stats(v2s, m, s); printf("  v2 seal %.2f us,", REC/(1024.0*1024.0)/m*1e6);
    stats(v2o, m, s); printf("  v2 open %.2f us\n", REC/(1024.0*1024.0)/m*1e6);
    if (f) { fprintf(f, "v1_wire_overhead_bytes,%zu,0\n", v1_wire-REC);
             fprintf(f, "v2_wire_overhead_bytes,%zu,0\n", v2_wire-REC); fclose(f);
             printf("\n[wrote %s]\n", csv); }
    return 0;
}

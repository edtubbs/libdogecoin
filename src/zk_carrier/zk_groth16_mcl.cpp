/*
 *  zk_groth16_mcl.cpp — In-process Groth16 BN254 verifier
 *
 *  The MIT License (MIT)
 *
 *  Copyright (c) 2026 edtubbs
 *  Copyright (c) 2026 The Dogecoin Foundation
 *
 *  Implements the C entry point declared in zk_groth16.c when libdogecoin
 *  is built with --with-mcl.  Uses herumi/mcl (BN_SNARK1 / "bn128" curve
 *  used by snarkjs / circom) for pairings.
 *
 *  Verification equation (Groth16, snarkjs convention):
 *
 *      e(A, B) == e(alpha_1, beta_2) * e(L, gamma_2) * e(C, delta_2)
 *
 *  where L = IC[0] + sum_i  pub_i * IC[i+1].
 *
 *  Inputs are NUL-terminated JSON strings from snarkjs:
 *    * vk_json     — verification_key.json
 *    * public_json — public.json (top-level array of decimal strings)
 *    * proof_json  — proof.json
 *
 *  Returns 0 on successful verification, non-zero on any error.  When
 *  err_buf is non-NULL it receives a short, non-sensitive diagnostic that
 *  callers may log alongside the return code.
 *
 *  Notes:
 *    * Snarkjs always emits affine points (Z = "1"); we ignore Z and read
 *      the X / Y coordinates directly.  G2 components are Fp2 = (a + b*i).
 *    * No JSON library is required — the input shape is fully determined
 *      by snarkjs; we walk for `"<key>"` then take the next [...] block,
 *      then collect every `"<digits>"` token inside.  This keeps the
 *      verifier dependency-free beyond mcl + libstdc++.
 */

#include <mcl/bn.hpp>

#include <cstddef>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>
#include <stdexcept>

extern "C" int groth16_verify_mcl(const char* vk_json,
                                  const char* public_json,
                                  const char* proof_json,
                                  char* err_buf,
                                  unsigned long err_buf_max);

namespace {

using namespace mcl::bn;

void set_err(char* err_buf, unsigned long err_buf_max, const char* msg) {
    if (!err_buf || err_buf_max == 0 || !msg) return;
    size_t n = std::strlen(msg);
    if (n >= err_buf_max) n = err_buf_max - 1;
    std::memcpy(err_buf, msg, n);
    err_buf[n] = '\0';
}

/* Find the [...] block that follows `"key"`, return its [lo, hi) range. */
bool find_value_array(const std::string& s, const char* key, size_t& out_lo, size_t& out_hi) {
    std::string needle = std::string("\"") + key + "\"";
    size_t p = s.find(needle);
    if (p == std::string::npos) return false;
    p = s.find('[', p);
    if (p == std::string::npos) return false;
    int depth = 0;
    for (size_t i = p; i < s.size(); ++i) {
        if (s[i] == '[') depth++;
        else if (s[i] == ']') {
            if (--depth == 0) { out_lo = p; out_hi = i + 1; return true; }
        }
    }
    return false;
}

/* Collect every "<digits>" token between [lo, hi) into a flat vector. */
std::vector<std::string> extract_decimal_strings(const std::string& s, size_t lo, size_t hi) {
    std::vector<std::string> out;
    size_t i = lo;
    while (i < hi) {
        if (s[i] != '"') { ++i; continue; }
        size_t j = i + 1;
        while (j < hi && s[j] != '"') ++j;
        if (j >= hi) break;
        std::string tok = s.substr(i + 1, j - i - 1);
        bool num = !tok.empty();
        for (char c : tok) { if (!(c >= '0' && c <= '9')) { num = false; break; } }
        if (num) out.push_back(tok);
        i = j + 1;
    }
    return out;
}

G1 make_g1(const std::string& x_dec, const std::string& y_dec) {
    G1 P;
    /* mcl decimal serialization: "<flag> <x> <y>" with flag=1 = affine non-zero */
    std::string serial = "1 " + x_dec + " " + y_dec;
    P.setStr(serial, 10);
    return P;
}

G2 make_g2(const std::string& x0, const std::string& x1,
           const std::string& y0, const std::string& y1) {
    G2 P;
    std::string serial = "1 " + x0 + " " + x1 + " " + y0 + " " + y1;
    P.setStr(serial, 10);
    return P;
}

bool g_pairing_initialised = false;

void ensure_pairing_initialised() {
    if (g_pairing_initialised) return;
    initPairing(mcl::BN_SNARK1);
    g_pairing_initialised = true;
}

} // anonymous namespace

extern "C" int groth16_verify_mcl(const char* vk_json,
                                  const char* public_json,
                                  const char* proof_json,
                                  char* err_buf,
                                  unsigned long err_buf_max) {
    if (err_buf && err_buf_max > 0) err_buf[0] = '\0';
    if (!vk_json || !public_json || !proof_json) {
        set_err(err_buf, err_buf_max, "null input");
        return 2;
    }
    try {
        ensure_pairing_initialised();

        std::string vk(vk_json);
        std::string pub(public_json);
        std::string prf(proof_json);

        size_t lo = 0, hi = 0;

        /* alpha_1 (G1) */
        if (!find_value_array(vk, "vk_alpha_1", lo, hi)) {
            set_err(err_buf, err_buf_max, "vk_alpha_1 missing"); return 3;
        }
        auto a_t = extract_decimal_strings(vk, lo, hi);
        if (a_t.size() < 2) { set_err(err_buf, err_buf_max, "vk_alpha_1 short"); return 3; }
        G1 alpha = make_g1(a_t[0], a_t[1]);

        /* beta/gamma/delta (G2) */
        auto load_g2 = [&](const char* key, G2& out) -> bool {
            size_t a, b;
            if (!find_value_array(vk, key, a, b)) return false;
            auto t = extract_decimal_strings(vk, a, b);
            if (t.size() < 4) return false;
            out = make_g2(t[0], t[1], t[2], t[3]);
            return true;
        };
        G2 beta, gamma, delta;
        if (!load_g2("vk_beta_2",  beta))  { set_err(err_buf, err_buf_max, "vk_beta_2 missing");  return 3; }
        if (!load_g2("vk_gamma_2", gamma)) { set_err(err_buf, err_buf_max, "vk_gamma_2 missing"); return 3; }
        if (!load_g2("vk_delta_2", delta)) { set_err(err_buf, err_buf_max, "vk_delta_2 missing"); return 3; }

        /* IC array (G1[]).  IC contains nPublic+1 G1 points. */
        if (!find_value_array(vk, "IC", lo, hi)) {
            set_err(err_buf, err_buf_max, "IC missing"); return 3;
        }
        auto ic_t = extract_decimal_strings(vk, lo, hi);
        if (ic_t.size() == 0 || ic_t.size() % 3 != 0) {
            set_err(err_buf, err_buf_max, "IC malformed"); return 3;
        }
        size_t n_ic = ic_t.size() / 3;
        std::vector<G1> IC; IC.reserve(n_ic);
        for (size_t i = 0; i < n_ic; ++i) {
            IC.push_back(make_g1(ic_t[3*i], ic_t[3*i + 1]));
        }

        /* public inputs (Fr[]) */
        auto pub_t = extract_decimal_strings(pub, 0, pub.size());
        if (pub_t.size() + 1 != n_ic) {
            set_err(err_buf, err_buf_max, "public inputs / IC length mismatch"); return 3;
        }
        std::vector<Fr> public_inputs; public_inputs.reserve(pub_t.size());
        for (auto& s : pub_t) {
            Fr f; f.setStr(s, 10);
            public_inputs.push_back(f);
        }

        /* proof: pi_a (G1), pi_b (G2), pi_c (G1) */
        if (!find_value_array(prf, "pi_a", lo, hi)) { set_err(err_buf, err_buf_max, "pi_a missing"); return 3; }
        auto pa_t = extract_decimal_strings(prf, lo, hi);
        if (pa_t.size() < 2) { set_err(err_buf, err_buf_max, "pi_a short"); return 3; }
        G1 A = make_g1(pa_t[0], pa_t[1]);

        if (!find_value_array(prf, "pi_b", lo, hi)) { set_err(err_buf, err_buf_max, "pi_b missing"); return 3; }
        auto pb_t = extract_decimal_strings(prf, lo, hi);
        if (pb_t.size() < 4) { set_err(err_buf, err_buf_max, "pi_b short"); return 3; }
        G2 B = make_g2(pb_t[0], pb_t[1], pb_t[2], pb_t[3]);

        if (!find_value_array(prf, "pi_c", lo, hi)) { set_err(err_buf, err_buf_max, "pi_c missing"); return 3; }
        auto pc_t = extract_decimal_strings(prf, lo, hi);
        if (pc_t.size() < 2) { set_err(err_buf, err_buf_max, "pi_c short"); return 3; }
        G1 C = make_g1(pc_t[0], pc_t[1]);

        /* L = IC[0] + sum pub_i * IC[i+1] */
        G1 L = IC[0];
        for (size_t i = 0; i < public_inputs.size(); ++i) {
            G1 t;
            G1::mul(t, IC[i + 1], public_inputs[i]);
            L += t;
        }

        /* Pairing equation: e(A, B) == e(alpha, beta) * e(L, gamma) * e(C, delta) */
        Fp12 lhs, e_alpha_beta, e_L_gamma, e_C_delta;
        pairing(lhs,           A,     B);
        pairing(e_alpha_beta,  alpha, beta);
        pairing(e_L_gamma,     L,     gamma);
        pairing(e_C_delta,     C,     delta);
        Fp12 rhs = e_alpha_beta * e_L_gamma * e_C_delta;

        if (lhs == rhs) {
            return 0;
        }
        set_err(err_buf, err_buf_max, "pairing eq mismatch");
        return 1;
    } catch (const std::exception& e) {
        set_err(err_buf, err_buf_max, e.what());
        return 4;
    } catch (...) {
        set_err(err_buf, err_buf_max, "unknown exception");
        return 4;
    }
}

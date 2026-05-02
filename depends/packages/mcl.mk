# mcl — herumi/mcl BN254 (BN_SNARK1) pairing library
#
# This package builds a static libmcl.a (no GMP, no LLVM bitcode emission)
# against the host toolchain and stages the headers + archive so that
# `./configure --with-mcl=$(host_prefix)` can find them.
#
# Linking the verifier into libdogecoin is opt-in via `./configure
# --with-mcl[=DIR]`.  Without it the C library returns
# DOGECOIN_ZK_ERR_DELEGATED for verify, so callers fall back to off-box
# verification (snarkjs).  This keeps libdogecoin mobile-friendly.
#
# ZK_CARRIER=1 must be set on the depends invocation to include this
# package in the dependency closure (mirrors the DEPENDS_NASM=1 pattern).
#
# Platform support: x86_64-linux-gnu, x86_64-apple-darwin, arm64-apple-darwin
# (the platforms libdogecoin's CI exercises).  Other hosts can add the
# appropriate architecture flags below; mcl itself supports a wide range.

package=mcl
$(package)_version=2.10
$(package)_download_path=https://github.com/herumi/mcl/archive/refs/tags
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=9166c642c53d6f8092f2e3a2cd64a1e17b8e04b96795989fed22debcfaed2e94

# mcl is self-contained — no GMP dependency when MCL_USE_VINT=1 (the default
# in v2.x).  We pin no transitive depends.
$(package)_dependencies=

# Refuse unsupported targets explicitly — mcl's build picks ASM tuning that
# we have not validated for these hosts.  Use the off-box snarkjs verifier
# instead by leaving --with-mcl unset (verify returns DELEGATED).
ifneq (,$(findstring mingw,$(host)))
$(error mcl vendoring not validated for Windows/mingw — leave --with-mcl unset and verify off-box via snarkjs)
endif
ifneq (,$(findstring android,$(host)))
$(error mcl vendoring not validated for Android — leave --with-mcl unset and verify off-box via snarkjs)
endif
ifneq (,$(findstring ios,$(host)))
$(error mcl vendoring not validated for iOS — leave --with-mcl unset and verify off-box via snarkjs)
endif

define $(package)_set_vars
  $(package)_config_opts =
endef

define $(package)_build_cmds
  $(MAKE) -C . lib/libmcl.a \
    CC='$(host_CC)' CXX='$(host_CXX)' \
    AR='$(host_AR)' RANLIB='$(host_RANLIB)' \
    CFLAGS='$(host_CFLAGS) -O2' CXXFLAGS='$(host_CXXFLAGS) -O2 -std=c++14' \
    MCL_USE_VINT=1 MCL_VINT_FIXED_BUFFER=1
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/lib && \
  mkdir -p $($(package)_staging_prefix_dir)/include && \
  cp lib/libmcl.a $($(package)_staging_prefix_dir)/lib/ && \
  cp -R include/mcl $($(package)_staging_prefix_dir)/include/
endef

# Notes for maintainers:
# - libdogecoin's C wrapper (src/zk_carrier/zk_groth16_mcl.cpp) calls
#   the mcl C++ API (initPairing(BN_SNARK1), pairing(...), Fp12::==).
#   The verifier expects the snarkjs JSON layout for vk_alpha_1, vk_beta_2,
#   vk_gamma_2, vk_delta_2, IC[], pi_a, pi_b, pi_c.
# - To switch curves later (e.g. BLS12-381 for a future circuit family),
#   only the `initPairing` argument in zk_groth16_mcl.cpp needs to change;
#   mcl supports MCL_BLS12_381 with the same archive.
# - mcl's vint mode produces a self-contained archive — no GMP / no MPIR /
#   no LLVM bitcode dependency at link time.

# rapidsnark — Groth16 verifier package (verifier-only, optional)
#
# Strategy: this package builds the Groth16 verifier portion of rapidsnark
# only.  The prover lives in JS/snarkjs (or the rapidsnark CLI on a host
# machine) — see contrib/zk_carrier/witness_helper.py.
#
# Linking the verifier into libdogecoin is opt-in via `./configure
# --with-rapidsnark`.  Without it the C library returns
# DOGECOIN_ZK_ERR_DELEGATED for verify, so callers fall back to off-box
# verification (snarkjs).  This keeps libdogecoin mobile-friendly.
#
# ZK_CARRIER=1 must be set on the depends invocation to include this package
# in the dependency closure (mirrors the DEPENDS_NASM=1 pattern).
#
# Platform support: x86_64-linux-gnu, x86_64-apple-darwin, arm64-apple-darwin
# only — these are the platforms libdogecoin's CI exercises.  Mingw and
# Android/iOS hosts emit a hard $(error) below; cross-compiling rapidsnark
# for those targets has not been validated and silently producing broken
# artifacts is worse than failing fast.

package=rapidsnark
$(package)_version=4b21f7a
$(package)_download_path=https://github.com/iden3/rapidsnark/archive
$(package)_file_name=$($(package)_version).tar.gz
$(package)_sha256_hash=0000000000000000000000000000000000000000000000000000000000000000
# !!! TODO before enabling in CI: replace the all-zero placeholder above with
# the real sha256 of the pinned tarball.  The package is gated behind
# ZK_CARRIER=1 (default OFF) precisely because this hash is unset; do NOT
# flip ZK_CARRIER on in CI until both the commit/tag and the sha256 are
# pinned to verified upstream values.

# Refuse unsupported targets explicitly.
ifneq (,$(findstring mingw,$(host)))
$(error rapidsnark vendoring not validated for Windows/mingw — set ZK_CARRIER=0 or build verification off-box via snarkjs)
endif
ifneq (,$(findstring android,$(host)))
$(error rapidsnark vendoring not validated for Android — set ZK_CARRIER=0 or build verification off-box via snarkjs)
endif
ifneq (,$(findstring ios,$(host)))
$(error rapidsnark vendoring not validated for iOS — set ZK_CARRIER=0 or build verification off-box via snarkjs)
endif

# rapidsnark vendors ffiasm/nasm at upstream.  When building for a host
# different from the build machine we rely on the depends-built native nasm.
$(package)_dependencies=

# Verifier-only build: skip the prover (which requires GMP, ffiasm, large
# build-time RAM).  The verifier is a small, header-mostly C/C++ unit.
define $(package)_set_vars
  $(package)_config_opts =
endef

define $(package)_preprocess_cmds
  # Strip the prover and witness-generator subtrees so the verifier-only
  # build doesn't try to link missing GMP / pthread symbols on the target.
  rm -rf src/prover src/witness 2>/dev/null || true
endef

define $(package)_build_cmds
  $(MAKE) -C build_verifier_only CC='$(host_CC)' CXX='$(host_CXX)' \
    AR='$(host_AR)' RANLIB='$(host_RANLIB)' \
    CFLAGS='$(host_CFLAGS) -O2' CXXFLAGS='$(host_CXXFLAGS) -O2'
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/lib && \
  mkdir -p $($(package)_staging_prefix_dir)/include/rapidsnark && \
  cp build_verifier_only/librapidsnark.a $($(package)_staging_prefix_dir)/lib/ && \
  cp src/groth16/groth16.h $($(package)_staging_prefix_dir)/include/rapidsnark/
endef

# Notes for maintainers:
# - The sha256_hash above is intentionally a placeholder (000…).  Pin a real
#   commit + hash before enabling this package in CI.  This is gated behind
#   ZK_CARRIER=1 which defaults OFF, so it does not affect today's CI.
# - The build_cmds assume a Makefile target `build_verifier_only` exists in
#   the upstream tree.  When pinning a commit, either select one that has
#   such a target or extend $(package)_preprocess_cmds with a small CMake
#   invocation that produces librapidsnark.a from the verifier sources.
# - libdogecoin's C wrapper (src/zk_carrier/zk_groth16.c) calls
#   `groth16_verify(vk_json, public_json, proof_json, err, errmax)`.  If the
#   pinned upstream uses a different symbol name, adjust the extern in
#   zk_groth16.c rather than this file.

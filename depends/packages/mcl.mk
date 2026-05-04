# mcl — herumi/mcl BN254 (BN_SNARK1) pairing library for Groth16 verification.
# Builds a static libmcl.a (no GMP, no LLVM).  Requires ZK_CARRIER=1 in depends invocation.

package=mcl
$(package)_version=2.10
$(package)_download_path=https://github.com/herumi/mcl/archive/refs/tags
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=9166c642c53d6f8092f2e3a2cd64a1e17b8e04b96795989fed22debcfaed2e94

$(package)_dependencies=

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

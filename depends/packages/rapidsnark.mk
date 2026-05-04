# rapidsnark — Groth16 verifier-only library (opt-in via --with-rapidsnark).

package=rapidsnark
$(package)_version=4b21f7a
$(package)_download_path=https://github.com/iden3/rapidsnark/archive
$(package)_file_name=$($(package)_version).tar.gz
$(package)_sha256_hash=0000000000000000000000000000000000000000000000000000000000000000
# Placeholder hash: run `make download` in depends/ then sha256sum the fetched tarball to replace.

$(package)_dependencies=

define $(package)_set_vars
  $(package)_config_opts =
endef

define $(package)_preprocess_cmds
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

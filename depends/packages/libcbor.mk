package=libcbor
$(package)_version=0.11.0
$(package)_download_path=https://github.com/PJK/libcbor/archive/refs/tags
$(package)_file_name=v$($(package)_version).tar.gz
$(package)_sha256_hash=89e0a83d16993ce50651a7501355453f5250e8729dfc8d4a251a78ea23bb26d7

define $(package)_set_vars
  $(package)_config_opts=-DBUILD_SHARED_LIBS=OFF -DCBOR_PRETTY_PRINTER=OFF -DWITH_EXAMPLES=OFF -DWITH_TESTS=OFF
endef

define $(package)_config_cmds
  cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$($(package)_staging_prefix_dir) $($(package)_config_opts)
endef

define $(package)_build_cmds
  cmake --build build
endef

define $(package)_stage_cmds
  cmake --install build --prefix $($(package)_staging_prefix_dir)
endef

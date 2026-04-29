package=libfido2
$(package)_version=1.14.0
$(package)_download_path=https://github.com/Yubico/libfido2/archive/refs/tags
$(package)_file_name=$($(package)_version).tar.gz
$(package)_sha256_hash=3601792e320032d428002c4cce8499a4c7b803319051a25a0c9f1f138ffee45a
$(package)_dependencies=libcbor

define $(package)_set_vars
  $(package)_config_opts=-DBUILD_SHARED_LIBS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_TOOLS=OFF -DUSE_PCSC=OFF -DUSE_HIDAPI=OFF
endef

define $(package)_config_cmds
  cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$($(package)_staging_prefix_dir) -DCMAKE_PREFIX_PATH=$($(package)_staging_prefix_dir) $($(package)_config_opts)
endef

define $(package)_build_cmds
  cmake --build build
endef

define $(package)_stage_cmds
  cmake --install build --prefix $($(package)_staging_prefix_dir)
endef

package=liboqs
$(package)_version=v0.0.1
$(package)_download_path=https://github.com/edtubbs/liboqs/archive/refs/tags
$(package)_file_name=$($(package)_version).tar.gz
$(package)_sha256_hash=7d5bd3a2deb8a2b72c9ca28803da8b8924d47f2343fb191dca2f4d63a1c8ecdb

define $(package)_build_cmds
	mkdir -p build && cd build && \
	cmake -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DBUILD_SHARED_LIBS=OFF \
		-DOQS_ENABLE_SIG_RACCOON_G=ON -DOQS_ENABLE_SIG_raccoon_g_44=ON \
		-DOQS_MINIMAL_BUILD="SIG_falcon_512;SIG_falcon_1024;SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;SIG_sphincs_shake_128s_simple;SIG_sphincs_shake_128f_simple;SIG_raccoon_g_44" \
		-DCMAKE_INSTALL_PREFIX=$(host_prefix) .. && \
	$(MAKE)
endef

define $(package)_stage_cmds
	cd build && $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

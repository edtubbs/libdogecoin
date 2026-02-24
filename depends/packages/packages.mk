packages:=libevent
native_packages := native_ccache

wallet_packages=

upnp_packages=

darwin_native_packages =

yubikey_packages = libyubikey libusb ykpers
liboqs_packages = liboqs
NO_LIBOQS ?= y
ifeq ($(ENABLE_LIBOQS),1)
NO_LIBOQS =
endif
ifeq ($(ENABLE_LIBOQS),yes)
NO_LIBOQS =
endif
ifeq ($(ENABLE_LIBOQS),true)
NO_LIBOQS =
endif
ifeq ($(ENABLE_LIBOQS),y)
NO_LIBOQS =
endif
liboqs_packages_$(NO_LIBOQS) = $(liboqs_packages)

ifneq ($(build_os),darwin)
darwin_native_packages += native_cctools native_libtapi

ifeq ($(strip $(FORCE_USE_SYSTEM_CLANG)),)
darwin_native_packages+= native_clang
endif

packages += $(liboqs_packages_)

endif

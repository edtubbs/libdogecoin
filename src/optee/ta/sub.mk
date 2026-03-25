global-incdirs-y += include
srcs-y += libdogecoin_ta.c
cppflags-$(CFG_ROCKCHIP_OTP) += -DUSE_ROCKCHIP_OTP
libnames += dogecoin utils yubikey usb-1.0 ykpers-1
libdirs += ${LIBDIR}

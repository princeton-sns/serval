LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

#
# Servd
#
LOCAL_HDR_FILES := \
	config.h \
	rtnl.h 

LOCAL_SRC_FILES := \
	rtnl.c \
	config.c \
	servd.c

SERVAL_INCLUDE_DIR=$(LOCAL_PATH)/../../include

LOCAL_C_INCLUDES += \
	$(SERVAL_INCLUDE_DIR)

LOCAL_SHARED_LIBRARIES = libservalctrl
LOCAL_STATIC_LIBRARIES = libcommon
LOCAL_LDLIBS :=-lservalctrl

EXTRA_DEFINES:=
DEFINES=-DOS_ANDROID -DOS_LINUX $(EXTRA_DEFINES)
LOCAL_CFLAGS:=-O2 -g
LOCAL_CPPFLAGS +=$(DEFINES)
LOCAL_LDFLAGS +=-L$(LOCAL_PATH)/../../android/Serval/obj/local/$(TARGET_ARCH_ABI)

LOCAL_PRELINK_MODULE := false
LOCAL_MODULE := servd

include $(BUILD_EXECUTABLE)

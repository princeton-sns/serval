LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

#
# Servd
#
LOCAL_HDR_FILES := \
	debug.h \
	rtnl.h \
	timer.h

LOCAL_SRC_FILES := \
	rtnl.c \
	timer.c \
	servd.c

SERVAL_INCLUDE_DIR=$(LOCAL_PATH)/../../include

LOCAL_C_INCLUDES += \
	$(SERVAL_INCLUDE_DIR)

# We need to compile our own version of libxml2, because the static
# library provided in Android does not have the configured options we need.
LOCAL_LDLIBS :=-lrt -lstack -lserval -lpthread
LOCAL_SHARED_LIBRARIES +=libdl libstack libserval

EXTRA_DEFINES:=-DOS_ANDROID -DOS_LINUX -DENABLE_DEBUG
LOCAL_CFLAGS:=-O2 -g $(EXTRA_DEFINES)
LOCAL_CPPFLAGS +=$(EXTRA_DEFINES)

LOCAL_PRELINK_MODULE := false
LOCAL_MODULE := servd

# LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_BIN_UNSTRIPPED)

include $(BUILD_EXECUTABLE)

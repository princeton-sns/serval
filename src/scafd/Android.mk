LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

#
# Scafd
#
LOCAL_SRC_FILES := \
	scafd.c

SCAFFOLD_INCLUDE_DIR=$(LOCAL_PATH)/../../include

SCAFD_HDR =

LOCAL_C_INCLUDES += \
	$(SCAFFOLD_INCLUDE_DIR)

# We need to compile our own version of libxml2, because the static
# library provided in Android does not have the configured options we need.
LOCAL_LDLIBS :=-lrt -lstack
LOCAL_SHARED_LIBRARIES +=libdl libstack

EXTRA_DEFINES:=-DOS_ANDROID -DENABLE_DEBUG
LOCAL_CFLAGS:=-O2 -g $(EXTRA_DEFINES)
LOCAL_CPPFLAGS +=$(EXTRA_DEFINES)

LOCAL_PRELINK_MODULE := false
LOCAL_MODULE := scafd

# LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_BIN_UNSTRIPPED)

include $(BUILD_EXECUTABLE)

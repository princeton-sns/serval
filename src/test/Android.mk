LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

#
# Scafd
#
LOCAL_HDR_FILES :=

LOCAL_SRC_FILES := \
	udp_server.c

SERVAL_INCLUDE_DIR=$(LOCAL_PATH)/../../include

LOCAL_C_INCLUDES += \
	$(SERVAL_INCLUDE_DIR)

# We need to compile our own version of libxml2, because the static
# library provided in Android does not have the configured options we need.
LOCAL_LDLIBS :=-lrt -lserval
LOCAL_SHARED_LIBRARIES +=libdl libserval

EXTRA_DEFINES:=-DOS_ANDROID -DENABLE_DEBUG -DSERVAL_NATIVE
LOCAL_CFLAGS:=-O2 -g $(EXTRA_DEFINES)
LOCAL_CPPFLAGS +=$(EXTRA_DEFINES)

LOCAL_PRELINK_MODULE := false
LOCAL_MODULE := udp_server

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

#
# Scafd
#
LOCAL_HDR_FILES :=

LOCAL_SRC_FILES := \
	udp_client.c

SERVAL_INCLUDE_DIR=$(LOCAL_PATH)/../../include

LOCAL_C_INCLUDES += \
	$(SERVAL_INCLUDE_DIR)

# We need to compile our own version of libxml2, because the static
# library provided in Android does not have the configured options we need.
LOCAL_LDLIBS :=-lrt -lserval
LOCAL_SHARED_LIBRARIES +=libdl libserval

EXTRA_DEFINES:=-DOS_ANDROID -DENABLE_DEBUG -DSERVAL_NATIVE
LOCAL_CFLAGS:=-O2 -g $(EXTRA_DEFINES)
LOCAL_CPPFLAGS +=$(EXTRA_DEFINES)

LOCAL_PRELINK_MODULE := false
LOCAL_MODULE := udp_client

include $(BUILD_EXECUTABLE)

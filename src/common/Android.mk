LOCAL_PATH := $(my-dir)
include $(CLEAR_VARS)

LOCAL_HDR_FILES := \
	$(LOCAL_PATH)/../../include/common/atomic.h \
	$(LOCAL_PATH)/../../include/common/debug.h \
	$(LOCAL_PATH)/../../include/common/hash.h \
	$(LOCAL_PATH)/../../include/common/hashtable.h \
	$(LOCAL_PATH)/../../include/common/heap.h \
	$(LOCAL_PATH)/../../include/common/list.h \
	$(LOCAL_PATH)/../../include/common/platform.h \
	$(LOCAL_PATH)/../../include/common/timer.h \
	$(LOCAL_PATH)/../../include/common/signal.h \
	platform.h

LOCAL_SRC_FILES := \
	hashtable.c \
	heap.c \
	signal.c \
	timer.c

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/../../include

EXTRA_DEFINES=-DOS_ANDROID -DOS_LINUX
LOCAL_CFLAGS :=-O2 -g $(EXTRA_DEFINES)
LOCAL_CPPFLAGS +=$(EXTRA_DEFINES)

LOCAL_PRELINK_MODULE := false

LOCAL_LDLIBS :=

LOCAL_MODULE := libcommon

include $(BUILD_STATIC_LIBRARY)

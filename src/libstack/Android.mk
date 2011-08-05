LOCAL_PATH := $(my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	libstack.c \
	ctrlmsg.c \
	netlink.c \
	unix.c \
	event.c

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/../../include

EXTRA_DEFINES=-DOS_ANDROID -DOS_LINUX -DENABLE_DEBUG
LOCAL_CFLAGS :=-O2 -g $(EXTRA_DEFINES)
LOCAL_CPPFLAGS +=$(EXTRA_DEFINES)

LOCAL_PRELINK_MODULE := false

LOCAL_LDLIBS :=

LOCAL_MODULE := libstack

include $(BUILD_SHARED_LIBRARY)

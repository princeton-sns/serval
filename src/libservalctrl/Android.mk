LOCAL_PATH := $(my-dir)
include $(CLEAR_VARS)

LOCAL_HDR_FILES := \
	$(LOCAL_PATH)/../../include/hostctrl.h \
	$(LOCAL_PATH)/../../include/init.h \
	$(LOCAL_PATH)/../../include/message_channel.h \
	$(LOCAL_PATH)/../../include/message.h \
	hostctrl_ops.h \
	message_channel_base.h \
	message_channel_internal.h

LOCAL_SRC_FILES := \
	hostctrl.c \
	hostctrl_local.c \
	hostctrl_remote.c \
	init.c \
	message.c \
	message_channel_base.c \
	message_channel.c \
	message_channel_internal.c \
	message_channel_netlink.c \
	message_channel_udp.c \
	message_channel_unix.c

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/../../include \
	$(LOCAL_PATH)/../../android/compat

LOCAL_STATIC_LIBRARIES := libcommon

EXTRA_DEFINES=
DEFINES=-DOS_ANDROID -DOS_LINUX $(EXTRA_DEFINES)
LOCAL_CFLAGS :=-O2 -g $(DEFINES)
LOCAL_CPPFLAGS +=$(DEFINES) 
LOCAL_PRELINK_MODULE := false

LOCAL_MODULE := libservalctrl

include $(BUILD_SHARED_LIBRARY)

LOCAL_PATH := $(my-dir)
include $(CLEAR_VARS)

LOCAL_SRC_FILES := \
	JNIHelp.c \
	org_servalarch_platform_ServalNetworkStack.c

LOCAL_C_INCLUDES += \
	$(JNI_H_INCLUDE) \
	$(LOCAL_PATH)/../../../include

LOCAL_SHARED_LIBRARIES := libdl

EXTRA_DEFINES=
LOCAL_CFLAGS :=-O2 -g $(EXTRA_DEFINES)
LOCAL_CPPFLAGS +=$(EXTRA_DEFINES)

LOCAL_PRELINK_MODULE := false

LOCAL_LDLIBS :=

LOCAL_MODULE := libservalnet_jni

include $(BUILD_SHARED_LIBRARY)

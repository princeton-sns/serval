LOCAL_PATH := $(my-dir)
include $(CLEAR_VARS)

LOCAL_HDR_FILES := \
	org_servalarch_servalctrl_HostCtrl.h \
	org_servalarch_servalctrl_HostCtrlCallback.h


LOCAL_SRC_FILES := \
	org_servalarch_servalctrl_HostCtrl.c

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/../../../../include \
	$(LOCAL_PATH)/../../../../android/compat

LOCAL_STATIC_LIBRARIES := libcommon
LOCAL_SHARED_LIBRARIES := libservalctrl

EXTRA_DEFINES=
DEFINES=-DOS_ANDROID -DOS_LINUX $(EXTRA_DEFINES)
LOCAL_CFLAGS :=-O2 -g $(DEFINES)
LOCAL_CPPFLAGS +=$(DEFINES) 
LOCAL_LDLIBS =-llog
LOCAL_PRELINK_MODULE := false

LOCAL_MODULE := libservalctrl_jni

include $(BUILD_SHARED_LIBRARY)

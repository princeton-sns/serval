LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

subdirs := $(addprefix $(LOCAL_PATH)/../../../,$(addsuffix /Android.mk, \
		src/common \
		src/libservalctrl \
		src/libservalctrl/java/jni/ \
		src/servd \
		src/test \
		src/tools \
		src/translator \
		src/javasock/jni \
        ))

include $(subdirs)

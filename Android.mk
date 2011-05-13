LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

subdirs := $(addprefix $(LOCAL_PATH)/,$(addsuffix /Android.mk, \
		src/stack \
		src/libstack \
		src/libserval \
		src/servd \
		src/test \
		src/javasock/jni \
        ))

include $(subdirs)

LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

subdirs := $(addprefix $(LOCAL_PATH)/,$(addsuffix /Android.mk, \
		src/stack \
		src/libstack \
		src/libscaffold \
		src/scafd \
		src/test \
        ))

include $(subdirs)

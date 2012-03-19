LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

LOCAL_HDR_FILES := \
	log.h

LOCAL_SRC_FILES := \
	splice.c \
	sys_splice.S \
	log.c \
	translator.c \
	translator_jni.c

SERVAL_INCLUDE_DIR=$(LOCAL_PATH)/../../include

LOCAL_C_INCLUDES += \
	$(SERVAL_INCLUDE_DIR)

LOCAL_SHARED_LIBRARIES := libdl
LOCAL_STATIC_LIBRARIES := libcommon

EXTRA_DEFINES:=
DEFINES=-DOS_ANDROID -DOS_LINUX $(EXTRA_DEFINES)
LOCAL_CFLAGS:=-O2 -g $(DEFINES)
LOCAL_CPPFLAGS +=$(DEFINES)
LOCAL_LDFLAGS=-llog

LOCAL_PRELINK_MODULE := false
LOCAL_MODULE := libtranslator_jni

include $(BUILD_SHARED_LIBRARY)

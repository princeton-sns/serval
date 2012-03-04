LOCAL_PATH := $(my-dir)
include $(CLEAR_VARS)

LOCAL_CPP_EXTENSION := .cc

LOCAL_HDR_FILES := \
	accept.hh \
	bind.hh \
	cli.hh \
	close.hh \
	connect.hh \
	listen.hh \
	log.hh \
	message.hh \
	recv.hh \
	select.hh \
	send.hh \
	socket.hh \
	sockio.hh \
	state.hh

LOCAL_SRC_FILES := \
	api.cc \
	accept.cc \
	bind.cc \
	cli.cc \
	close.cc \
	connect.cc \
	listen.cc \
	log.cc \
	message.cc \
	recv.cc \
	select.cc \
	send.cc \
	socket.cc \
	sockio.cc \
	state.cc

LOCAL_C_INCLUDES += \
	$(LOCAL_PATH)/../../include

LOCAL_SHARED_LIBRARIES := libdl

EXTRA_DEFINES=-DOS_ANDROID -DENABLE_DEBUG
LOCAL_CFLAGS :=-O2 -g $(EXTRA_DEFINES)
LOCAL_CPPFLAGS +=$(EXTRA_DEFINES)

LOCAL_PRELINK_MODULE := false

LOCAL_LDLIBS :=

LOCAL_MODULE := libserval

include $(BUILD_SHARED_LIBRARY)

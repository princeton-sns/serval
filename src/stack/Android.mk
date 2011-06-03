LOCAL_PATH:= $(call my-dir)
include $(CLEAR_VARS)

#
# Serval
#
LOCAL_SRC_FILES := \
	debug.c \
	platform.c \
        bst.c \
        service.c \
	ctrl_handler.c \
	af_serval.c \
	serval_sock.c \
	serval_srv.c \
	serval_ipv4.c \
	serval_udp.c \
	serval_tcp.c \
	userlevel/dst.c \
	userlevel/dev.c \
	userlevel/sock.c \
	userlevel/socket.c \
	userlevel/skbuff.c \
	userlevel/timer.c \
	userlevel/wait.c \
	userlevel/client_msg.c \
	userlevel/client.c \
	userlevel/packet_raw.c \
	userlevel/ctrl.c \
	userlevel/telnet.c \
	userlevel/serval.c

SERVAL_INCLUDE_DIR=$(LOCAL_PATH)/../../include

SERVAL_HDR = \
	af_serval.h \
	ctrl.h \
	bst.h \
        service.h \
	serval_sock.h \
	serval_udp_sock.h \
	serval_tcp_sock.h \
	serval_srv.h \
	serval_ipv4.h \
	userlevel/packet.h \
	userlevel/client_msg.h \
	userlevel/client.h \
	userlevel/telnet.h \
	$(SERVAL_INCLUDE_DIR)/libstack/ctrlmsg.h \
	$(SERVAL_INCLUDE_DIR)/netinet/serval.h \
	$(SERVAL_INCLUDE_DIR)/serval/platform_tcpip.h \
	$(SERVAL_INCLUDE_DIR)/serval/platform.h \
	$(SERVAL_INCLUDE_DIR)/serval/atomic.h \
	$(SERVAL_INCLUDE_DIR)/serval/bitops.h \
	$(SERVAL_INCLUDE_DIR)/serval/list.h \
	$(SERVAL_INCLUDE_DIR)/serval/hash.h \
	$(SERVAL_INCLUDE_DIR)/serval/debug.h \
	$(SERVAL_INCLUDE_DIR)/serval/lock.h \
	$(SERVAL_INCLUDE_DIR)/serval/net.h \
        $(SERVAL_INCLUDE_DIR)/serval/dst.h \
	$(SERVAL_INCLUDE_DIR)/serval/netdevice.h \
	$(SERVAL_INCLUDE_DIR)/serval/sock.h \
	$(SERVAL_INCLUDE_DIR)/serval/skbuff.h \
	$(SERVAL_INCLUDE_DIR)/serval/timer.h \
	$(SERVAL_INCLUDE_DIR)/serval/wait.h

LOCAL_C_INCLUDES += \
	$(SERVAL_INCLUDE_DIR)

#LOCAL_SHARED_LIBRARIES := \


# We need to compile our own version of libxml2, because the static
# library provided in Android does not have the configured options we need.
LOCAL_LDLIBS :=-lpthread -lrt

LOCAL_SHARED_LIBRARIES +=libdl

EXTRA_DEFINES:=-DHAVE_CONFIG -DOS_ANDROID -DENABLE_DEBUG
LOCAL_CFLAGS:=-O2 -g $(EXTRA_DEFINES)
LOCAL_CPPFLAGS +=$(EXTRA_DEFINES)

LOCAL_PRELINK_MODULE := false
LOCAL_MODULE := serval

# LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_BIN_UNSTRIPPED)

include $(BUILD_EXECUTABLE)

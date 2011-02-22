/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <sys/socket.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/serval.h>
#include <poll.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include "JNIHelp.h"
#include "serval_platform_ServalNetworkStack.h"

/* These option defines are from Harmony */
#define JAVASOCKOPT_TCP_NODELAY 1
#define JAVASOCKOPT_IP_TOS 3
#define JAVASOCKOPT_SO_REUSEADDR 4
#define JAVASOCKOPT_SO_KEEPALIVE 8
#define JAVASOCKOPT_IP_MULTICAST_IF 16
#define JAVASOCKOPT_MCAST_TTL 17
#define JAVASOCKOPT_IP_MULTICAST_LOOP 18
#define JAVASOCKOPT_MCAST_ADD_MEMBERSHIP 19
#define JAVASOCKOPT_MCAST_DROP_MEMBERSHIP 20
#define JAVASOCKOPT_IP_MULTICAST_IF2 31
#define JAVASOCKOPT_SO_BROADCAST 32
#define JAVASOCKOPT_SO_LINGER 128
#define JAVASOCKOPT_REUSEADDR_AND_REUSEPORT  10001
#define JAVASOCKOPT_SO_SNDBUF 4097
#define JAVASOCKOPT_SO_RCVBUF 4098
#define JAVASOCKOPT_SO_RCVTIMEOUT  4102
#define JAVASOCKOPT_SO_OOBINLINE  4099

static int kernelStack = 0;

static struct {
        jmethodID   constructor;
        jmethodID   getID;
        jclass      clazz;
} gServiceIDFields;

static int fill_in_sockaddr_sv(JNIEnv *env, struct sockaddr_sv *svaddr, 
				jobject srvid, int bits)
{
	jboolean isCopy;
	jbyteArray byteArr = (*env)->CallObjectMethod(env, srvid, 
						      gServiceIDFields.getID);
	jbyte *arr = (*env)->GetByteArrayElements(env, byteArr, &isCopy);
	
	if (bits < 0 || (unsigned int)bits > 
            ((sizeof(svaddr->sv_srvid) * 8) - 1))
		bits = 0;

	memset(svaddr, 0, sizeof(*svaddr));
	svaddr->sv_family = AF_SERVAL;
	svaddr->sv_prefix_bits = bits;
	memcpy(&svaddr->sv_srvid, arr, sizeof(svaddr->sv_srvid));
	
	(*env)->ReleaseByteArrayElements(env, byteArr, arr, 0);

        return 0;
}

static int fill_in_sockaddr_in(JNIEnv *env, struct sockaddr_in *saddr, 
                               jobject ipaddr)
{
	jboolean isCopy;
	jclass clazz = (*env)->GetObjectClass(env, ipaddr);
	jmethodID mid = (*env)->GetMethodID(env, clazz, "getAddress", "()[B");
	jbyteArray byteArr = (*env)->CallObjectMethod(env, ipaddr, mid);
	jbyte *arr;
	
        /* Verify that this is an IPv4 address. */
        if ((*env)->GetArrayLength(env, byteArr) != 4)
                return -1;

        arr = (*env)->GetByteArrayElements(env, byteArr, &isCopy);
        memset(saddr, 0, sizeof(*saddr));
        saddr->sin_family = AF_INET;
        memcpy(&saddr->sin_addr, arr, sizeof(saddr->sin_addr));
	
	(*env)->ReleaseByteArrayElements(env, byteArr, arr, 0);

        return 0;
}

/*
 * Class:     serval_platform_ServalNetworkStack
 * Method:    nativeInit
 * Signature: ()V
 */
void Java_serval_platform_ServalNetworkStack_nativeInit(JNIEnv *env, 
							jobject obj)
{
	int sock = socket(AF_SERVAL, SOCK_DGRAM, 0);
	jclass clazz;

	if (sock == -1) {
		if (errno == EAFNOSUPPORT) {
			/* Nothing to do really since we default to
			 * kernel stack */
		} else {
			/* This is weird */
		}
	} else {
		kernelStack = 1;
		close(sock);
	}

	jniHelpInit(env);

	clazz = (*env)->FindClass(env, "serval/net/ServiceID");

	if (clazz == NULL) {
		LOG_ERR("Could not find ServiceID class\n");
	}

	gServiceIDFields.clazz = (*env)->NewGlobalRef(env, clazz);
	gServiceIDFields.getID = (*env)->GetMethodID(env, clazz, 
						     "getID", "()[B");
	
	if (gServiceIDFields.getID == NULL) {
		LOG_ERR("Could not find ServiceID.getID() function\n");
	}

	gServiceIDFields.constructor = (*env)->GetMethodID(env, clazz, 
							   "<init>", "([B)V");
	
	if (gServiceIDFields.constructor == NULL) {
		LOG_ERR("Could not find ServiceID() function\n");
	}
}

static int createSocket(JNIEnv *env, int type, int protocol, jobject fd)
{
	int sock = -1;

	if (kernelStack) {
		sock = socket(AF_SERVAL, type, protocol);
	} else {
		/*
		sock = socket_sv(AF_SERVAL, type, protocol);
		*/
	}

	if (sock == -1) {
                jniThrowSocketException(env, errno);
	} else {
		jniSetFileDescriptorOfFD(env, fd, sock);
	}

	return sock;
}
/*
 * Class:     serval_platform_ServalNetworkStack
 * Method:    createDatagramSocket 
 * Signature: (Ljava/io/FileDescriptor;)I
 */
jint Java_serval_platform_ServalNetworkStack_createDatagramSocket(JNIEnv *env, 
								  jobject obj, 
								  jobject fd,
								  jint protocol)
{
	return createSocket(env, SOCK_DGRAM, protocol, fd);
}

/*
 * Class:     serval_platform_ServalNetworkStack
 * Method:    createStreamSocket
 * Signature: (Ljava/io/FileDescriptor;I)I
 */
jint Java_serval_platform_ServalNetworkStack_createStreamSocket(JNIEnv *env,
								jobject obj, 
								jobject fd,
								jint protocol)
{
	return createSocket(env, SOCK_STREAM, protocol, fd);
}

/*
 * Class:     serval_platform_ServalNetworkStack
 * Method:    bind
 * Signature: (Ljava/io/FileDescriptor;Lserval/net/ServiceID;I)I
 */
jint Java_serval_platform_ServalNetworkStack_bind(JNIEnv *env, 
						  jobject obj,
						  jobject fd, 
						  jobject service_id,
						  jint bindbits)
{
	struct sockaddr_sv svaddr;
	int sock = jniGetFDFromFileDescriptor(env, fd);
	int ret = 0;

	fill_in_sockaddr_sv(env, &svaddr, service_id, bindbits);

	ret = bind(sock, (struct sockaddr *)&svaddr, sizeof(svaddr));	
	
	if (ret == -1) {
		jniThrowSocketException(env, errno);
	}
	
	return 0;
}

/*
 * Class:     serval_platform_ServalNetworkStack
 * Method:    listen
 * Signature: (Ljava/io/FileDescriptor;I)I
 */
jint Java_serval_platform_ServalNetworkStack_listen(JNIEnv *env, 
						    jobject obj, 
						    jobject fd,
						    jint backlog)
{
	int sock, ret;

	sock = jniGetFDFromFileDescriptor(env, fd);

	if ((*env)->ExceptionCheck(env)) {
                LOG_ERR("Could not get sock from FD\n");
		return -1;
	}

	ret = listen(sock, backlog);

	if (ret == -1) {
                LOG_ERR("listen failed: %s\n", strerror(errno));
		jniThrowSocketException(env, errno);
	}

	return ret;
}

/*
 * Class:     serval_platform_ServalNetworkStack
 * Method:    accept
 * Signature: (Ljava/io/FileDescriptor;Lserval/net/ServalDatagramSocketImpl;)Ljava/io/FileDescriptor;
 */
jobject Java_serval_platform_ServalNetworkStack_accept(JNIEnv *env,
						       jobject obj, 
						       jobject fd, 
						       jobject sockImpl)
{
	int sock, ret;
	struct sockaddr_sv svaddr;
	socklen_t addrlen;
	
	if (sockImpl == NULL) {
		jniThrowException(env, "java/lang/NullPointerException", NULL);
		return NULL;
	}
	
	sock = jniGetFDFromFileDescriptor(env, fd);

	if ((*env)->ExceptionCheck(env)) {
                LOG_ERR("Could not get sock from FD\n");
		return NULL;
	}

	do {
		addrlen = sizeof(svaddr);
		ret = accept(sock, (struct sockaddr *)&svaddr, &addrlen);
	} while (ret < 0 && errno == EINTR);

	if (ret == -1) {
                LOG_ERR("Accept fail: %s\n", strerror(errno));
		jniThrowSocketException(env, errno);
		return NULL;
	}

	return jniCreateFileDescriptor(env, ret);
}

/*
 * Class:     serval_platform_ServalNetworkStack
 * Method:    connect
 * Signature: (Ljava/io/FileDescriptor;Lserval/net/ServiceID;Ljava/net/InetAddress;I)I
 */
jint Java_serval_platform_ServalNetworkStack_connect(JNIEnv *env, 
						     jobject obj, 
						     jobject fd, 
						     jobject service_id, 
						     jobject ipaddr,
                                                     jint timeout)
{
	struct {
		struct sockaddr_sv svaddr;
		struct sockaddr_in inaddr;
	} sa;
	socklen_t addrlen = sizeof(sa);
        struct pollfd fds;
	int sock, ret, nonblock = 1;

	sock = jniGetFDFromFileDescriptor(env, fd);

	if ((*env)->ExceptionCheck(env)) {
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	fill_in_sockaddr_sv(env, &sa.svaddr, service_id, 0);
	
	if (ipaddr == NULL) {
		addrlen = sizeof(sa.svaddr);
	} else if (fill_in_sockaddr_in(env, &sa.inaddr, ipaddr) != 0) {
		jniThrowException(env, "java/lang/IllegalArgumentException", 
				  "Bad IP address");
                return -1;
	}

        ret = ioctl(sock, FIONBIO, &nonblock);

        if (ret == -1) {
                LOG_ERR("Setting non-block failed: %s\n",
                        strerror(errno));
                jniThrowSocketException(env, errno);
                return -1;
        }

	ret = connect(sock, (struct sockaddr *)&sa, addrlen);

	if (ret == -1) {
                if (errno == EINPROGRESS) {
                        /* Everything OK */
                } else {
                        jniThrowSocketException(env, errno);
                        LOG_DBG("Connect failure: %s\n", strerror(errno));
                        goto out;
                }
	}

        fds.fd = sock;
        fds.events = POLLIN | POLLOUT | POLLERR | POLLHUP;
        fds.revents = 0;
	
        ret = poll(&fds, 1, timeout);
        
        if (ret == -1) {
                LOG_ERR("poll fail: %s\n", strerror(errno));
                jniThrowSocketException(env, errno);
        } else if (ret == 0) {
                /* Timeout */
                jniThrowConnectException(env, ETIMEDOUT);
        } else {
                if (fds.revents & POLLOUT) {
                        /* If write does not block, we either
                         * connected of failed */
                        if (fds.revents & POLLIN) {
                                int err = 0;
                                socklen_t errlen = sizeof(err);
                                
                                /* Figure out what to do */
                                ret = getsockopt(sock, SOL_SOCKET, SO_ERROR,
                                                 &err, &errlen);

                                if (ret >= 0) {
                                        ret = err;
                                        jniThrowConnectException(env, err);
                                } else {
                                        LOG_ERR("getsockopt err=%s\n",
                                                strerror(errno));
                                        jniThrowSocketException(env, errno);
                                }
                                goto out;
                        } else {
                                /* Connected! */
                                ret = 0;
                                goto out;
                        }
                }
           
                if (fds.revents & POLLERR) {
                        int err = 0;
                        socklen_t errlen = sizeof(err);
                        
                        /* Figure out error */
                        ret = getsockopt(sock, SOL_SOCKET, SO_ERROR,
                                         &err, &errlen);
                        
                        if (ret >= 0) {
                                ret = err;
                                jniThrowConnectException(env, err);
                        } else {
                                LOG_ERR("getsockopt err=%s\n",
                                        strerror(errno));
                                jniThrowSocketException(env, errno);
                        }
                }
        }
out:   
        nonblock = 0;

        ret = ioctl(sock, FIONBIO, &nonblock);

	return ret;
}

/*
 * Class:     serval_platform_ServalNetworkStack
 * Method:    disconnect
 * Signature: (Ljava/io/FileDescriptor;)I
 */
jint Java_serval_platform_ServalNetworkStack_disconnect(JNIEnv *env, 
							jobject obj, 
							jobject fd)
{
	/* Not sure what this is supposed to do */
	return 0;
}

/*
 * Class:     serval_platform_ServalNetworkStack
 * Method:    send
 * Signature: (Ljava/io/FileDescriptor;[BII)I
 */
jint Java_serval_platform_ServalNetworkStack_send(JNIEnv *env, 
						  jobject obj, 
						  jobject fd,
						  jbyteArray buf, 
						  jint offset, 
						  jint length)
{	
	int sock, ret;
	jbyte* data;

	sock = jniGetFDFromFileDescriptor(env, fd);

	if ((*env)->ExceptionCheck(env)) {
		return -1;
	}
	
	if (length < 0) {
		return -1;
	}

	data = (*env)->GetByteArrayElements(env, buf, NULL);

	if (data == NULL) {
		return -1;
	}

        do {
                ret = send(sock, (((char *)data) + offset), length, 0);
                /* Try again for non-critical errors */
        } while (ret == -1 && errno == EINTR);

	if (ret == -1) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        /* Send on a non-blocking socket --> return 0
                         * bytes sent */
			ret = 0;
		} else {
			jniThrowSocketException(env, errno);
			ret = 0;
		}
	}

	(*env)->ReleaseByteArrayElements(env, buf, data, 0);
	
	return ret;
}

/*
 * Class:     serval_platform_ServalNetworkStack
 * Method:    recv
 * Signature: (Ljava/io/FileDescriptor;[BIIIZ)I
 */
jint Java_serval_platform_ServalNetworkStack_recv(JNIEnv *env, jobject obj, 
						  jobject fd, jbyteArray buf, 
						  jint offset, jint length, 
						  jint timeout, jboolean peek)
{
	int sock, ret;
	int buflen = (length < 65536) ? length : 65536;
	jbyte *buffer;
	int flags = peek ? MSG_PEEK : 0;
        int retry = 1;

	sock = jniGetFDFromFileDescriptor(env, fd);

	if ((*env)->ExceptionCheck(env)) {
		return -1;
	}

	if (timeout != 0) {
		struct pollfd fds;
		fds.fd = sock;
		fds.events = POLLIN | POLLERR;
		fds.revents = 0;

		ret = poll(&fds, 1, timeout);

		if (ret == -1) {
                        jniThrowSocketException(env, errno);
			return -1;
                } else if (ret == 0) {                       
                        jniThrowSocketTimeoutException(env, EAGAIN);
                        return 0;
                }
	}
	
	buffer = (jbyte*) malloc(buflen);

	if (buffer == NULL) {
		jniThrowException(env, "java/lang/OutOfMemoryError",
				  "couldn't allocate enough memory for recv");
		return -1;
	}

	while (retry) {
		ret = recv(sock, (char *)buffer, buflen, flags);

		if (ret == -1) {
                        switch (errno) {
                        case EINTR:
                                /* Interrupted, continue */
                                break;
                        case EAGAIN:
                                /* Timeout, in case SO_RCVTIMEO was set. */
                                jniThrowSocketTimeoutException(env, errno);
                                retry = 0;
                                break;
                        default:
				jniThrowSocketException(env, errno);
                                retry = 0;
                                break;
			}
		} else if (ret == 0) {
                        /* Other end closed connection, return -1
                         * similarly to InputStream.read() */
                        ret = -1;
                        break;
                } else {
                        break;
                }
	}

	if (ret > 0) {
		(*env)->SetByteArrayRegion(env, buf, offset, ret, buffer);
	}
	
	free(buffer);

	return ret;
}

/*
 * Class:     serval_platform_ServalNetworkStack
 * Method:    close
 * Signature: (Ljava/io/FileDescriptor;)I
 */
jint Java_serval_platform_ServalNetworkStack_close(JNIEnv *env, 
						   jobject obj, 
						   jobject fd)
{
	int sock, ret;

	sock = jniGetFDFromFileDescriptor(env, fd);
	
	if ((*env)->ExceptionCheck(env)) {
		return -1;
	}
	
	ret = close(sock);

	return ret;
}

/*
 * Class:     serval_platform_ServalNetworkStack
 * Method:    getSocketLocalServiceID
 * Signature: (Ljava/io/FileDescriptor;)Lserval/net/ServiceID;
 */
jobject 
Java_serval_platform_ServalNetworkStack_getSocketLocalServiceID(JNIEnv *env, 
								jobject obj, 
								jobject fd)
{
	LOG_WARN("Not implemented!\n");
	return NULL;
}

/*
 * Class:     serval_platform_ServalNetworkStack
 * Method:    setOption
 * Signature: (Ljava/io/FileDescriptor;III)I
 */
jint Java_serval_platform_ServalNetworkStack_setOption(JNIEnv *env, 
						       jobject obj, 
						       jobject fd, 
						       jint opt, 
						       jint bool_value, 
						       jint int_value)
{
	int sock, ret = 0;
	int bval = bool_value ? 1 : 0;
	int ival = int_value;

	sock = jniGetFDFromFileDescriptor(env, fd);
	
	if ((*env)->ExceptionCheck(env)) {
		return -1;
	}

	switch (opt) {
        case JAVASOCKOPT_IP_TOS:
		ret = setsockopt(sock, IPPROTO_IP, 
                                 IP_TOS, &ival, sizeof(ival));
		break;
        case JAVASOCKOPT_SO_KEEPALIVE:
		ret = setsockopt(sock, SOL_SOCKET, 
                                 SO_KEEPALIVE, &bval, sizeof(bval));
                break;
        case JAVASOCKOPT_SO_BROADCAST:
		ret = setsockopt(sock, SOL_SOCKET, 
                                 SO_BROADCAST, &bval, sizeof(bval));
		break;
        case JAVASOCKOPT_SO_LINGER:
        {
                struct linger l  = { bval, ival };
		ret = setsockopt(sock, SOL_SOCKET, 
                                 SO_LINGER, &l, sizeof(l));
                break;
        }
        case JAVASOCKOPT_SO_REUSEADDR:
        case JAVASOCKOPT_REUSEADDR_AND_REUSEPORT:
		ret = setsockopt(sock, SOL_SOCKET, 
                                 SO_REUSEADDR, &bval, sizeof(bval));
                break;
        case JAVASOCKOPT_SO_SNDBUF:
		ret = setsockopt(sock, SOL_SOCKET, 
                                 SO_SNDBUF, &ival, sizeof(ival));
		break;
        case JAVASOCKOPT_SO_RCVBUF:
		ret = setsockopt(sock, SOL_SOCKET, 
                                 SO_RCVBUF, &ival, sizeof(ival));
		break;
        case JAVASOCKOPT_SO_RCVTIMEOUT:
        {
                struct timeval timeout = { ival / 1000, 
                                           (ival % 1000) * 1000 };

                LOG_DBG("SO_RCVTIMEO %ld.%06ld\n", 
                        timeout.tv_sec, timeout.tv_usec);
		ret = setsockopt(sock, SOL_SOCKET, 
                                 SO_RCVTIMEO, &timeout, sizeof(timeout));
		break;
        }
        case JAVASOCKOPT_SO_OOBINLINE:
		ret = setsockopt(sock, SOL_SOCKET, 
                                 SO_OOBINLINE, &bval, sizeof(bval));
                break;
	default:
		jniThrowException(env, "java/lang/IllegalArgumentException", 
				  "Bad socket option");
		return -1;
	}

	if (ret == -1) {
		jniThrowSocketException(env, errno);
	}

	return ret;
}

/*
 * Class:     serval_platform_ServalNetworkStack
 * Method:    getOption
 * Signature: (Ljava/io/FileDescriptor;I)I
 */
jint Java_serval_platform_ServalNetworkStack_getOption(JNIEnv *env, 
						       jobject obj, 
						       jobject fd, 
						       jint opt)
{
	int sock, ret;
	int val = 0;
	socklen_t len = sizeof(val);

	sock = jniGetFDFromFileDescriptor(env, fd);
	
	if ((*env)->ExceptionCheck(env)) {
		return -1;
	}
	
	switch (opt) {
	case JAVASOCKOPT_IP_TOS:
		ret = getsockopt(sock, IPPROTO_IP, IP_TOS, &val, &len);
		break;
        case JAVASOCKOPT_SO_KEEPALIVE:
		ret = getsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &val, &len);
                break;
        case JAVASOCKOPT_SO_BROADCAST:
		ret = getsockopt(sock, SOL_SOCKET, SO_BROADCAST, &val, &len);
		break;
        case JAVASOCKOPT_SO_LINGER:
        {
                struct linger l  = { 0, 0 };
                len = sizeof(l);
		ret = getsockopt(sock, SOL_SOCKET, SO_LINGER, &l, &len);
                val = l.l_onoff;
                break;
        }
        case JAVASOCKOPT_SO_REUSEADDR:
        case JAVASOCKOPT_REUSEADDR_AND_REUSEPORT:
		ret = getsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, &len);
                break;
        case JAVASOCKOPT_SO_SNDBUF:
		ret = getsockopt(sock, SOL_SOCKET, SO_SNDBUF, &val, &len);
		break;
        case JAVASOCKOPT_SO_RCVBUF:
		ret = getsockopt(sock, SOL_SOCKET, SO_RCVBUF, &val, &len);
		break;
        case JAVASOCKOPT_SO_RCVTIMEOUT:
        {
                struct timeval timeout = { 0, 0 };
                len = sizeof(timeout);
		ret = getsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &val, &len);
                val = timeout.tv_sec * 1000 + (timeout.tv_usec / 1000);
		break;
        }
        case JAVASOCKOPT_SO_OOBINLINE:
		ret = getsockopt(sock, SOL_SOCKET, SO_OOBINLINE, &val, &len);
	default:
		jniThrowException(env, "java/lang/IllegalArgumentException", 
				  "Bad socket option");
		return -1;
	}

	if (ret == -1) {
		jniThrowSocketException(env, errno);
                return -1;
	}

	return val;
}

/*
 * Class:     serval_platform_ServalNetworkStack
 * Method:    getSocketFlags
 * Signature: ()I
 */
jint Java_serval_platform_ServalNetworkStack_getSocketFlags(JNIEnv *env, 
							    jobject obj)
{
	LOG_WARN("Not implemented!\n");
	return 0;
}

jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
        JNIEnv *env;

        //jvm = vm;

        if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_4) != JNI_OK) {
                fprintf(stderr, "Could not get JNI env in JNI_OnLoad\n");
                return -1;
        }

	return JNI_VERSION_1_4;
}

void JNI_OnUnload(JavaVM *vm, void *reserved)
{
	JNIEnv *env = NULL;
	
        if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_4) != JNI_OK) {
		fprintf(stderr, "Could not get JNI env in JNI_OnUnload\n");
                return;
        }         
}

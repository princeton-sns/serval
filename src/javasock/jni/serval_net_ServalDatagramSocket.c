/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/serval.h>
#include "serval_net_ServalDatagramSocket.h"

/*
 * Class:     serval_net_ServalDatagramSocket
 * Method:    socket
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_serval_net_ServalDatagramSocket_socket(JNIEnv *env, jobject obj)
{
	return socket(AF_SERVAL, SOCK_DGRAM, 0);
}

/*
 * Class:     serval_net_ServalDatagramSocket
 * Method:    bind
 * Signature: (I[BI)I
 */
JNIEXPORT jint JNICALL Java_serval_net_ServalDatagramSocket_bind(JNIEnv *env, jobject obj, jint fd, jbyteArray serviceid)
{
	struct sockaddr_sv svaddr;
	jboolean isCopy;
	jbyte *arr = (*env)->GetByteArrayElements(env, serviceid, &isCopy);
	
	svaddr.sv_family = AF_SERVAL;
	memcpy(&svaddr.sv_srvid, arr, sizeof(svaddr.sv_srvid));
	
	(*env)->ReleaseByteArrayElements(env, serviceid, arr, 0);
	
	return bind(fd, (struct sockaddr *)&svaddr, sizeof(svaddr));
}


/*
 * Class:     serval_net_ServalDatagramSocket
 * Method:    listen
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_serval_net_ServalDatagramSocket_listen(JNIEnv *env, jobject obj, jint fd, jint backlog)
{
	return listen(fd, backlog);
}

/*
 * Class:     serval_net_ServalDatagramSocket
 * Method:    accept
 * Signature: (I[B)I
 */
JNIEXPORT jint JNICALL Java_serval_net_ServalDatagramSocket_accept(JNIEnv *env, jobject obj, jint fd, jbyteArray serviceid)
{
	struct sockaddr_sv svaddr;
	socklen_t addrlen = sizeof(struct sockaddr_sv);	
	jboolean isCopy;
	jbyte *arr;
	int client_fd;

	svaddr.sv_family = AF_SERVAL;

	client_fd = accept(fd, (struct sockaddr *)&svaddr, &addrlen);

	if (client_fd == -1) {
		return -1;
	}

	arr = (*env)->GetByteArrayElements(env, serviceid, &isCopy);

	memcpy(arr, &svaddr.sv_srvid, sizeof(svaddr.sv_srvid));

	(*env)->ReleaseByteArrayElements(env, serviceid, arr, JNI_COMMIT);

	return client_fd;
}

/*
 * Class:     serval_net_ServalDatagramSocket
 * Method:    connect
 * Signature: (I[BI)I
 */
JNIEXPORT jint JNICALL Java_serval_net_ServalDatagramSocket_connect(JNIEnv *env, jobject obj, jint fd, jbyteArray serviceid)
{
	struct sockaddr_sv svaddr;
	jboolean isCopy;
	jbyte *arr = (*env)->GetByteArrayElements(env, serviceid, &isCopy);
	int ret; 

	svaddr.sv_family = AF_SERVAL;
	memcpy(&svaddr.sv_srvid, arr, sizeof(svaddr.sv_srvid));

	(*env)->ReleaseByteArrayElements(env, serviceid, arr, 0);

	ret = connect(fd, (struct sockaddr *)&svaddr, sizeof(svaddr));

	return ret;
}

/*
 * Class:     serval_net_ServalDatagramSocket
 * Method:    send
 * Signature: (I[BII)I
 */
JNIEXPORT jint JNICALL Java_serval_net_ServalDatagramSocket_send(JNIEnv *env, jobject obj, jint fd, jbyteArray buffer, jint flags)
{
	jboolean isCopy;
	jbyte *data = (*env)->GetByteArrayElements(env, buffer, &isCopy);
	int ret;
	
	ret = send(fd, data, (*env)->GetArrayLength(env, buffer), flags);
	
	(*env)->ReleaseByteArrayElements(env, buffer, data, 0);

	return ret;
}

/*
 * Class:     serval_net_ServalDatagramSocket
 * Method:    recv
 * Signature: (I[BII)I
 */
JNIEXPORT jint JNICALL Java_serval_net_ServalDatagramSocket_recv(JNIEnv *env, jobject obj, jint fd, jbyteArray buffer, jint flags)
{
	jboolean isCopy;
	jbyte *data = (*env)->GetByteArrayElements(env, buffer, &isCopy);
	int ret;

	ret = recv(fd, data, (*env)->GetArrayLength(env, buffer), flags);
	
	(*env)->ReleaseByteArrayElements(env, buffer, data, JNI_COMMIT);

	return ret;
}

/*
 * Class:     serval_net_ServalDatagramSocket
 * Method:    close
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_serval_net_ServalDatagramSocket_close(JNIEnv *env, jobject obj, jint fd)
{
	return close(fd);
}


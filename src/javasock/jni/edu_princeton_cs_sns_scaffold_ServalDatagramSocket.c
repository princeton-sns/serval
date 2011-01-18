#include <sys/socket.h>
#include <unistd.h>
#include <netinet/serval.h>
#include "edu_princeton_cs_sns_serval_ServalDatagramSocket.h"

/*
 * Class:     edu_princeton_cs_sns_serval_ServalDatagramSocket
 * Method:    socket
 * Signature: ()I
 */
JNIEXPORT jint JNICALL Java_edu_princeton_cs_sns_serval_ServalDatagramSocket_socket(JNIEnv *env, jobject obj)
{
	return socket(AF_SERVAL, SOCK_DGRAM, 0);
}

/*
 * Class:     edu_princeton_cs_sns_serval_ServalDatagramSocket
 * Method:    bind
 * Signature: (I[BI)I
 */
JNIEXPORT jint JNICALL Java_edu_princeton_cs_sns_serval_ServalDatagramSocket_bind(JNIEnv *env, jobject obj, jint fd, jbyteArray serviceid)
{
	struct sockaddr_sf sfaddr;
	jboolean isCopy;
	jbyte *arr = (*env)->GetByteArrayElements(env, serviceid, &isCopy);
	
	sfaddr.sf_family = AF_SERVAL;
	memcpy(&sfaddr.sf_srvid, arr, sizeof(sfaddr.sf_srvid));
	
	(*env)->ReleaseByteArrayElements(env, serviceid, arr, 0);
	
	return bind(fd, (struct sockaddr *)&sfaddr, sizeof(sfaddr));
}


/*
 * Class:     edu_princeton_cs_sns_serval_ServalDatagramSocket
 * Method:    listen
 * Signature: (II)I
 */
JNIEXPORT jint JNICALL Java_edu_princeton_cs_sns_serval_ServalDatagramSocket_listen(JNIEnv *env, jobject obj, jint fd, jint backlog)
{
	return listen(fd, backlog);
}

/*
 * Class:     edu_princeton_cs_sns_serval_ServalDatagramSocket
 * Method:    accept
 * Signature: (I[B)I
 */
JNIEXPORT jint JNICALL Java_edu_princeton_cs_sns_serval_ServalDatagramSocket_accept(JNIEnv *env, jobject obj, jint fd, jbyteArray serviceid)
{
	struct sockaddr_sf sfaddr;
	socklen_t addrlen = sizeof(struct sockaddr_sf);	
	jboolean isCopy;
	jbyte *arr;
	int client_fd;

	sfaddr.sf_family = AF_SERVAL;

	client_fd = accept(fd, (struct sockaddr *)&sfaddr, &addrlen);

	if (client_fd == -1) {
		return -1;
	}

	arr = (*env)->GetByteArrayElements(env, serviceid, &isCopy);

	memcpy(arr, &sfaddr.sf_srvid, sizeof(sfaddr.sf_srvid));

	(*env)->ReleaseByteArrayElements(env, serviceid, arr, JNI_COMMIT);

	return client_fd;
}

/*
 * Class:     edu_princeton_cs_sns_serval_ServalDatagramSocket
 * Method:    connect
 * Signature: (I[BI)I
 */
JNIEXPORT jint JNICALL Java_edu_princeton_cs_sns_serval_ServalDatagramSocket_connect(JNIEnv *env, jobject obj, jint fd, jbyteArray serviceid)
{
	struct sockaddr_sf sfaddr;
	jboolean isCopy;
	jbyte *arr = (*env)->GetByteArrayElements(env, serviceid, &isCopy);
	int ret; 

	sfaddr.sf_family = AF_SERVAL;
	memcpy(&sfaddr.sf_srvid, arr, sizeof(sfaddr.sf_srvid));

	(*env)->ReleaseByteArrayElements(env, serviceid, arr, 0);

	ret = connect(fd, (struct sockaddr *)&sfaddr, sizeof(sfaddr));

	return ret;
}

/*
 * Class:     edu_princeton_cs_sns_serval_ServalDatagramSocket
 * Method:    send
 * Signature: (I[BII)I
 */
JNIEXPORT jint JNICALL Java_edu_princeton_cs_sns_serval_ServalDatagramSocket_send(JNIEnv *env, jobject obj, jint fd, jbyteArray buffer, jint flags)
{
	jboolean isCopy;
	jbyte *data = (*env)->GetByteArrayElements(env, buffer, &isCopy);
	int ret;
	
	ret = send(fd, data, (*env)->GetArrayLength(env, buffer), flags);
	
	(*env)->ReleaseByteArrayElements(env, buffer, data, 0);

	return ret;
}

/*
 * Class:     edu_princeton_cs_sns_serval_ServalDatagramSocket
 * Method:    recv
 * Signature: (I[BII)I
 */
JNIEXPORT jint JNICALL Java_edu_princeton_cs_sns_serval_ServalDatagramSocket_recv(JNIEnv *env, jobject obj, jint fd, jbyteArray buffer, jint flags)
{
	jboolean isCopy;
	jbyte *data = (*env)->GetByteArrayElements(env, buffer, &isCopy);
	int ret;

	ret = recv(fd, data, (*env)->GetArrayLength(env, buffer), flags);
	
	(*env)->ReleaseByteArrayElements(env, buffer, data, JNI_COMMIT);

	return ret;
}

/*
 * Class:     edu_princeton_cs_sns_serval_ServalDatagramSocket
 * Method:    close
 * Signature: (I)I
 */
JNIEXPORT jint JNICALL Java_edu_princeton_cs_sns_serval_ServalDatagramSocket_close(JNIEnv *env, jobject obj, jint fd)
{
	return close(fd);
}


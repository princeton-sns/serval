/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
/*
 * Copyright (C) 2006 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * JNI helper functions taken from Android/Harmony.
 */
#include "JNIHelp.h"
/* Make sure we include a POSIX compliant strerror_r */
#undef _POSIX_C_SOURCE 
#define _POSIX_C_SOURCE 200112L
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <errno.h>
/*
* Get a human-readable summary of an exception object.  The buffer will
* be populated with the "binary" class name and, if present, the
* exception message.
*/
static void getExceptionSummary(JNIEnv* env, jthrowable excep, char* buf,
		size_t bufLen)
{
	if (excep == NULL)
		return;

	/* get the name of the exception's class; none of these should fail */
        jclass clazz = (*env)->GetObjectClass(env, excep); // exception's class
        jclass jlc = (*env)->GetObjectClass(env, clazz);   // java.lang.Class
        jmethodID getNameMethod =
                (*env)->GetMethodID(env, jlc, "getName", "()Ljava/lang/String;");
        jstring className = (*env)->CallObjectMethod(env, clazz, getNameMethod);

        /* get printable string */
        const char* nameStr = (*env)->GetStringUTFChars(env, className, NULL);
        if (nameStr == NULL) {
                snprintf(buf, bufLen, "%s", "out of memory generating summary");
                (*env)->ExceptionClear(env);            // clear OOM
                return;
        }

        /* if the exception has a message string, get that */
        jmethodID getThrowableMessage =
                (*env)->GetMethodID(env, clazz, "getMessage", "()Ljava/lang/String;");
        jstring message = (*env)->CallObjectMethod(env, excep, getThrowableMessage);

        if (message != NULL) {
                const char* messageStr = (*env)->GetStringUTFChars(env, message, NULL);
                snprintf(buf, bufLen, "%s: %s", nameStr, messageStr);
                if (messageStr != NULL)
                        (*env)->ReleaseStringUTFChars(env, message, messageStr);
                else
                        (*env)->ExceptionClear(env);        // clear OOM
        } else {
                strncpy(buf, nameStr, bufLen);
                buf[bufLen-1] = '\0';
        }

        (*env)->ReleaseStringUTFChars(env, className, nameStr);
}

/*
 * Throw an exception with the specified class and an optional message.
 *
 * If an exception is currently pending, we log a warning message and
 * clear it.
 *
 * Returns 0 if the specified exception was successfully thrown.  (Some
 * sort of exception will always be pending when this returns.)
 */
int jniThrowException(JNIEnv* env, const char* className, const char* msg)
{
        jclass exceptionClass;

        if ((*env)->ExceptionCheck(env)) {
                /* TODO: consider creating the new exception with this as "cause" */
                char buf[256];

                jthrowable excep = (*env)->ExceptionOccurred(env);
                (*env)->ExceptionClear(env);
                getExceptionSummary(env, excep, buf, sizeof(buf));
                LOG_WARN("Discarding pending exception (%s) to throw %s\n",
                         buf, className);
        }

        exceptionClass = (*env)->FindClass(env, className);
        if (exceptionClass == NULL) {
                LOG_DBG("Unable to find exception class %s\n", className);
                /* ClassNotFoundException now pending */
                return -1;
        }

        if ((*env)->ThrowNew(env, exceptionClass, msg) != JNI_OK) {
                LOG_DBG("Failed throwing '%s' '%s'\n", className, msg);
                /* an exception, most likely OOM, will now be pending */
                return -1;
        }
        return 0;
}
/*
 * Throw a java.lang.IllegalArgumentException, with an optional message.
 */
int jniThrowIllegalArgumentException(JNIEnv* env, const char* msg)
{
        return jniThrowException(env, "java/lang/IllegalArgumentException", msg);
}

/*
 * Throw a java.lang.NullPointerException, with an optional message.
 */
int jniThrowNullPointerException(JNIEnv* env, const char* msg)
{
        return jniThrowException(env, "java/lang/NullPointerException", msg);
}

/*
 * Throw a java.lang.RuntimeException, with an optional message.
 */
int jniThrowRuntimeException(JNIEnv* env, const char* msg)
{
        return jniThrowException(env, "java/lang/RuntimeException", msg);
}

/*
 * Throw a java.io.IOException, generating the message from errno.
 */
int jniThrowIOException(JNIEnv* env, int errnum)
{
        char buffer[80];
        const char* message = jniStrError(errnum, buffer, sizeof(buffer));
        return jniThrowException(env, "java/io/IOException", message);
}

const char* jniStrError(int errnum, char* buf, size_t buflen)
{
        int ret = strerror_r(errnum, buf, buflen);

        if (ret == 0) {
                return buf;
        } else {
                snprintf(buf, buflen, "errno %d", errnum);
                return buf;
        } 
}

void jniThrowExceptionWithErrno(JNIEnv* env,
                                const char* exceptionClassName, int error) 
{
        char buf[BUFSIZ];
        jniThrowException(env, exceptionClassName,
                          jniStrError(error, buf, sizeof(buf)));
}

void jniThrowBindException(JNIEnv* env, int error) 
{
        jniThrowExceptionWithErrno(env, "java/net/BindException", error);
}

void jniThrowConnectException(JNIEnv* env, int error) 
{
        jniThrowExceptionWithErrno(env, "java/net/ConnectException", error);
}

void jniThrowSocketException(JNIEnv* env, int error) 
{
        jniThrowExceptionWithErrno(env, "java/net/SocketException", error);
}

void jniThrowSocketTimeoutException(JNIEnv* env, int error) 
{
        jniThrowExceptionWithErrno(env, "java/net/SocketTimeoutException", error);
}

// Used by functions that shouldn't throw SocketException. (These functions
// aren't meant to see bad addresses, so seeing one really does imply an
// internal error.)
// TODO: fix the code (native and Java) so we don't paint ourselves into this corner.
void jniThrowBadAddressFamily(JNIEnv* env) 
{
        jniThrowException(env, "java/lang/IllegalArgumentException", "Bad address family");
}


/*
 * These are JNI field IDs for the stuff we're interested in.  They're
 * computed when the class is loaded.
 */
static struct {
        jfieldID    descriptor;       /* int */
        jmethodID   constructorInt;
        jmethodID   setFD;
        jclass      clazz;
} gCachedFields;

/*
 * Internal helper function.
 *
 * Get the file descriptor.
 */
static inline int getFd(JNIEnv* env, jobject obj)
{
	return (*env)->GetIntField(env, obj, gCachedFields.descriptor);
}

/*
 * Internal helper function.
 *
 * Set the file descriptor.
 */
static inline void setFd(JNIEnv* env, jobject obj, jint value)
{
        (*env)->SetIntField(env, obj, gCachedFields.descriptor, value);
}

/*
 * native private static void nativeClassInit()
 *
 * Perform one-time initialization.  If the class is unloaded and re-loaded,
 * this will be called again.
 */
void jniHelpInit(JNIEnv* env)
{
        jclass clazz = (*env)->FindClass(env, "java/io/FileDescriptor");

        gCachedFields.clazz = (*env)->NewGlobalRef(env, clazz);

        /* Harmony Java implementation */
        gCachedFields.descriptor =
                (*env)->GetFieldID(env, clazz, "descriptor", "I");
       
        if ((*env)->ExceptionCheck(env)) {
                (*env)->ExceptionClear(env);
        }
        if (gCachedFields.descriptor == NULL) {
                
                /* Oracle Java implementation */
                gCachedFields.descriptor =
                        (*env)->GetFieldID(env, clazz, "fd", "I");
                                
                if ((*env)->ExceptionCheck(env)) {
                        (*env)->ExceptionClear(env);
                }
                if (gCachedFields.descriptor == NULL) {
                        jniThrowException(env, "java/lang/NoSuchFieldError", 
                                          "FileDescriptor");
                        return;
                }
        }

        gCachedFields.constructorInt =
                (*env)->GetMethodID(env, clazz, "<init>", "()V");

        if (gCachedFields.constructorInt == NULL) {
                jniThrowException(env, "java/lang/NoSuchMethodError", "<init>()V");
                return;
        }
}

/* 
 * For JNIHelp.c
 * Get an int file descriptor from a java.io.FileDescriptor
 */

jobject jniCreateFileDescriptor(JNIEnv *env, int fd) {
        jobject ret;
                
        ret = (*env)->NewObject(env, gCachedFields.clazz,
                                gCachedFields.constructorInt);
        
        (*env)->SetIntField(env, ret, gCachedFields.descriptor, fd);
        
        return ret;
}

int jniGetFDFromFileDescriptor (JNIEnv* env, jobject fileDescriptor) {
        /* should already be initialized if it's an actual FileDescriptor */
        assert(fileDescriptor != NULL);
        assert(gCachedFields.clazz != NULL);

        return getFd(env, fileDescriptor);
}

/*
 * For JNIHelp.c
 * Set the descriptor of a java.io.FileDescriptor
 */

void jniSetFileDescriptorOfFD(JNIEnv* env, jobject fileDescriptor, int value) 
{
        /* should already be initialized if it's an actual FileDescriptor */
        assert(fileDescriptor != NULL);
        assert(gCachedFields.clazz != NULL);

        setFd(env, fileDescriptor, value);
}

int jniGetFd(JNIEnv* env, jobject fileDescriptor, int *fd) 
{
	*fd = jniGetFDFromFileDescriptor(env, fileDescriptor);

	if (*fd == -1) {
		jniThrowSocketException(env, EBADF);
		return 0;
	}
	return 1;
}



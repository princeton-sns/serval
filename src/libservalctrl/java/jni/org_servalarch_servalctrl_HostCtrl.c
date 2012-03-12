/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <libservalctrl/hostctrl.h>
#include <libservalctrl/init.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/serval.h>
#include "org_servalarch_servalctrl_HostCtrl.h"

/*
  These conversion macros are needed to stop the compiler from
  complaining about converting a 64-bit jlong value to a 32-bit
  pointer value on 32-bit platforms.
 */
#if defined(__LP64__)
#define ptr_to_jlong(p) (p ? (jlong)p : 0)
#define jlong_to_ptr(l) ((void *)((uintptr_t)l))
#else
#define ptr_to_jlong(p) (p ? (jlong)((jint)p) : 0)
#define jlong_to_ptr(l) ((void *) (((uintptr_t)l) & 0xffffffff))
#endif

static JavaVM *jvm = NULL;

struct jni_context {
    JNIEnv *env;
    jobject obj;
    jclass cls;
    jobject callbacks;
    jclass hostctrl_cls;
    jclass callbacks_cls;
    struct hostctrl *hc;
};

static struct jni_context *get_native_context(JNIEnv *env, jobject obj)
{
	jclass cls = (*env)->GetObjectClass(env, obj);
	jfieldID fid = (*env)->GetFieldID(env, cls, "nativeHandle", "J");

    if (!fid)
        return NULL;

	return (struct jni_context *)jlong_to_ptr((*env)->GetLongField(env, obj, fid));
}

static int set_native_context(JNIEnv *env, jobject obj, struct jni_context *ctx)
{
	jfieldID fid = (*env)->GetFieldID(env, ctx->cls, "nativeHandle", "J");

    if (!fid)
        return -1;
    
    (*env)->SetLongField(env, obj, fid, ptr_to_jlong(ctx));

    return 0;
}

static int fill_in_service_id(JNIEnv *env, jobject obj, struct service_id *sid)
{
    jboolean isCopy = JNI_FALSE;
	jclass cls = (*env)->GetObjectClass(env, obj);
	jfieldID fid;
    jbyteArray array;
    jbyte *buffer;

    fid = (*env)->GetFieldID(env, cls, "identifier", "[B");

    if (!fid)
        return -1;

    array = (*env)->GetObjectField(env, obj, fid);

    if (!array)
        return -1;

    buffer = (*env)->GetByteArrayElements(env, array, &isCopy);

    if (!buffer)
        return -1;
    
    memcpy(sid->s_sid, buffer, (*env)->GetArrayLength(env, array));

    (*env)->ReleaseByteArrayElements(env, array, buffer, 0);

    return 0;
}

static int fill_in_addr(JNIEnv *env, jobject obj, struct in_addr *ipaddr)
{
    jboolean isCopy = JNI_FALSE;
	jclass cls;
	jmethodID mid;
    jbyteArray array;
    jbyte *buffer;

    cls = (*env)->FindClass(env, "java/net/InetAddress");
    
    if (!cls)
        return -1;
    
    mid = (*env)->GetMethodID(env, cls, "getAddress", "()[B");

    if (!mid)
        return -1;

    array = (*env)->CallObjectMethod(env, obj, mid);

    if (!array)
        return -1;

    buffer = (*env)->GetByteArrayElements(env, array, &isCopy);

    if (!buffer)
        return -1;
    
    memcpy(&ipaddr->s_addr, buffer, (*env)->GetArrayLength(env, array));

    (*env)->ReleaseByteArrayElements(env, array, buffer, 0);

    return 0;
}

static jobject get_callbacks(JNIEnv *env, struct jni_context *ctx)
{
    jfieldID fid;

    fid = (*env)->GetFieldID(env, ctx->hostctrl_cls, "callbacks", 
                             "Lorg/servalarch/servalctrl/HostCtrlCallbacks;");

    if (!fid) {
        fprintf(stderr, "could not get fid\n");
        return NULL;
    }

    return (*env)->GetObjectField(env, ctx->obj, fid);
}

static jobject new_service_id(JNIEnv *env, const struct service_id *srvid)
{
    jclass cls = (*env)->FindClass(env, "org/servalarch/net/ServiceID");
    jbyteArray arr;
    jobject service_id;
    jmethodID cid;

    if (!cls)
        return NULL;

    cid = (*env)->GetMethodID(env, cls, "<init>", "([B)V");

    if (!cid)
        return NULL;

    arr = (*env)->NewByteArray(env, 20);

    if (!arr)
        return NULL;

    (*env)->SetByteArrayRegion(env, arr, 0, 20, (jbyte *)srvid->s_sid);

    service_id = (*env)->NewObject(env, cls, cid, arr);

    (*env)->DeleteLocalRef(env, arr);
    
    return service_id;
}

static jobject new_inet4addr(JNIEnv *env, const struct in_addr *ipaddr)
{
    jclass cls = (*env)->FindClass(env, "java/net/InetAddress");
    jbyteArray arr;
    jobject addr;
    jmethodID mid;

    if (!cls) {
        fprintf(stderr, "could not find InetAddress class\n");
        return NULL;
    }

    mid = (*env)->GetStaticMethodID(env, cls, "getByAddress", "([B)Ljava/net/InetAddress;");

    if (!mid) {
        fprintf(stderr, "could not find getByAddress mid\n");
        return NULL;
    }

    arr = (*env)->NewByteArray(env, 4);

    if (!arr) {
        fprintf(stderr, "could not create byteArray\n");
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, arr, 0, 4, (jbyte *)ipaddr);

    addr = (*env)->CallStaticObjectMethod(env, cls, mid, arr);

    if (!addr) {
        fprintf(stderr, "addr is NULL\n");
    }

    (*env)->DeleteLocalRef(env, arr);
    
    return addr;
}

static int service_registration(struct hostctrl *hc,
                                const struct service_id *srvid,
                                unsigned short flags,
                                unsigned short prefix,
                                const struct in_addr *ip,
                                const struct in_addr *old_ip)
{
    struct jni_context *ctx = (struct jni_context *)hc->context;
    JNIEnv *env = ctx->env;
    jobject service_id, addr, old_addr = NULL;
    jmethodID mid;

    mid = (*env)->GetMethodID(env, ctx->callbacks_cls, "serviceRegistration", 
                              "(Lorg/servalarch/net/ServiceID;IILjava/net/InetAddress;Ljava/net/InetAddress;)V");

    if (!mid) {
        fprintf(stderr, "could not find mid\n");
        return -1;
    }
    service_id = new_service_id(env, srvid);
    
    if (!service_id) {
        fprintf(stderr, "could not create serviceID\n");
        return -1;
    }

    addr = new_inet4addr(env, ip);

    if (!addr) {
        fprintf(stderr, "could not create addr1\n");
        goto err_addr;
    }

    if (old_ip) {
        old_addr = new_inet4addr(env, old_ip);
        
        if (!old_addr) {
            fprintf(stderr, "could not create addr2\n");
            goto err_old_addr;
        }
    }

    (*env)->CallVoidMethod(env, get_callbacks(env, ctx), mid, service_id, (jint)flags, 
                           (jint)prefix, addr, old_addr);

    (*env)->DeleteLocalRef(env, old_addr);
err_old_addr:
    (*env)->DeleteLocalRef(env, addr);
err_addr:
    (*env)->DeleteLocalRef(env, service_id);

    return 0;
}

static int service_unregistration(struct hostctrl *hc,
                                  const struct service_id *srvid,
                                  unsigned short flags,
                                  unsigned short prefix,
                                  const struct in_addr *ip)
{
    struct jni_context *ctx = (struct jni_context *)hc->context;
    JNIEnv *env = ctx->env;
    jobject service_id, addr;
    jmethodID mid;

    mid = (*env)->GetMethodID(env, ctx->callbacks_cls, "serviceUnregistration", 
                              "(Lorg/servalarch/net/ServiceID;IILjava/net/InetAddress;)V");

    if (!mid)
        return -1;
    
    service_id = new_service_id(env, srvid);
    
    if (!service_id)
        return -1;

    addr = new_inet4addr(env, ip);

    if (!addr)
        goto err_addr;
   
    (*env)->CallVoidMethod(env, get_callbacks(env, ctx), mid, service_id, (jint)flags, 
                           (jint)prefix, addr);

    (*env)->DeleteLocalRef(env, addr);
err_addr:
    (*env)->DeleteLocalRef(env, service_id);

    return 0;
}

static int service_stat_update(struct hostctrl *hc,
                               struct service_info_stat *stat,
                               unsigned int num_stat)
{
    /*
    struct jni_context *ctx = (struct jni_context *)hc->context;
    JNIEnv *env = ctx->env;
    */
    return 0;
}

static int service_get(struct hostctrl *hc,
                       const struct service_id *srvid,
                       unsigned short flags,
                       unsigned short prefix,
                       unsigned int priority,
                       unsigned int weight,
                       struct in_addr *ip)
{
    struct jni_context *ctx = (struct jni_context *)hc->context;
    JNIEnv *env = ctx->env;
    jobject service_id, addr;
    jmethodID mid;

    mid = (*env)->GetMethodID(env, ctx->callbacks_cls, "serviceGet", 
                              "(Lorg/servalarch/net/ServiceID;IIIILjava/net/InetAddress;)V");

    if (!mid)
        return -1;
    
    service_id = new_service_id(env, srvid);
    
    if (!service_id)
        return -1;

    addr = new_inet4addr(env, ip);

    if (!addr)
        goto err_addr;

    (*env)->CallVoidMethod(env, get_callbacks(env, ctx), mid, service_id, (jint)flags, 
                           (jint)prefix, (jint)priority, (jint)weight, addr);

    (*env)->DeleteLocalRef(env, addr);
err_addr:
    (*env)->DeleteLocalRef(env, service_id);

    return 0;
}

static int hostctrl_on_start(struct hostctrl *hc)
{
    struct jni_context *ctx = (struct jni_context *)hc->context;
    (*jvm)->AttachCurrentThread(jvm, &ctx->env, NULL);
    return 0;
}

static void hostctrl_on_stop(struct hostctrl *hc) {
    if ((*jvm)->DetachCurrentThread(jvm) != JNI_OK) {
        fprintf(stderr, "%s: Could not detach callback thread\n", __func__);
    }
}

static struct hostctrl_callback cb = {
    .start = hostctrl_on_start,
    .stop = hostctrl_on_stop,
    .service_registration = service_registration,
    .service_unregistration = service_unregistration,
    .service_stat_update = service_stat_update,
    .service_get = service_get,
};


enum {
	HOSTCTRL_LOCAL,
	HOSTCTRL_REMOTE,
};

jint JNICALL Java_org_servalarch_servalctrl_HostCtrl_nativeInit(JNIEnv *env, jobject obj, jint type)
{
    struct jni_context *ctx;
	jclass cls = (*env)->GetObjectClass(env, obj);
    jclass hostctrl_cls = (*env)->FindClass(env, "org/servalarch/servalctrl/HostCtrl");
    jclass callbacks_cls;

    if (!hostctrl_cls) {
        fprintf(stderr, "%s could not find HostCtrl class\n", __func__);
        return -1;
    }

    callbacks_cls = (*env)->FindClass(env, "org/servalarch/servalctrl/HostCtrlCallbacks");

    if (!callbacks_cls) {
        fprintf(stderr, "%s could not find HostCtrlCallbacks class\n", __func__);
        return -1;
    }

    ctx = malloc(sizeof(*ctx));

    if (!ctx)
        return -1;
   
    memset(ctx, 0, sizeof(*ctx));
    ctx->obj = (*env)->NewGlobalRef(env, obj);
    ctx->cls = (*env)->NewGlobalRef(env, cls);
    ctx->hostctrl_cls = (*env)->NewGlobalRef(env, hostctrl_cls);
    ctx->callbacks_cls = (*env)->NewGlobalRef(env, callbacks_cls);
    ctx->callbacks = (*env)->NewGlobalRef(env, get_callbacks(env, ctx));
    ctx->env = NULL; /* Initialized on callback thread when it starts */

	if (set_native_context(env, obj, ctx) == -1) {
        free(ctx);
        return -1;
    }

	if (type == HOSTCTRL_LOCAL)
		ctx->hc = hostctrl_local_create(&cb, ctx, HCF_NONE);
	else if (type == HOSTCTRL_REMOTE)
		ctx->hc = hostctrl_remote_create(&cb, ctx, HCF_NONE);
	else
		return -1;

    if (!ctx->hc)
        return -1;

    if (hostctrl_start(ctx->hc) == -1) {
        hostctrl_free(ctx->hc);
        ctx->hc = NULL;
        return -1;
    }

	return 0;
}

void JNICALL Java_org_servalarch_servalctrl_HostCtrl_nativeFree(JNIEnv *env, jobject obj)
{
    struct jni_context *ctx = get_native_context(env, obj);
    if (ctx->hc)
        hostctrl_free(ctx->hc);
    (*env)->DeleteGlobalRef(env, ctx->obj);
    (*env)->DeleteGlobalRef(env, ctx->cls);
    (*env)->DeleteGlobalRef(env, ctx->hostctrl_cls);
    (*env)->DeleteGlobalRef(env, ctx->callbacks_cls);
    (*env)->DeleteGlobalRef(env, ctx->callbacks);
    free(ctx);
}

jint JNICALL Java_org_servalarch_servalctrl_HostCtrl_migrateFlow(JNIEnv *env, jobject obj, 
                                                                 jlong flowid, jstring ifname)
{
	const char *name;
    struct jni_context *ctx = get_native_context(env, obj);
    struct flow_id fl = { .s_id32 = htonl(flowid) };
    int ret;

    name = (*env)->GetStringUTFChars(env, ifname, 0); 
    
    if (!name)
        return -1;

    ret = hostctrl_flow_migrate(ctx->hc, &fl, name);
    
    (*env)->ReleaseStringUTFChars(env, ifname, name);
    
    return ret;
}

jint JNICALL Java_org_servalarch_servalctrl_HostCtrl_migrateInterface(JNIEnv *env, jobject obj, jstring fromIface, jstring toIface)
{
    const char *from, *to;
    struct jni_context *ctx = get_native_context(env, obj);
    int ret;
    
    from = (*env)->GetStringUTFChars(env, fromIface, 0);
    
    if (!from)
        return -1;

    to = (*env)->GetStringUTFChars(env, toIface, 0);

    if (!to) {
        (*env)->ReleaseStringUTFChars(env, fromIface, from);
        return -1;
    }
    
    ret = hostctrl_interface_migrate(ctx->hc, from, to);

    (*env)->ReleaseStringUTFChars(env, fromIface, from);
    (*env)->ReleaseStringUTFChars(env, toIface, to);

    return ret;
}

jint JNICALL Java_org_servalarch_servalctrl_HostCtrl_addService4(JNIEnv *env, jobject obj, 
                                                                 jobject service_id, jint prefix_bits, 
                                                                 jint priority, jint weight, jobject addr)
{
    struct jni_context *ctx = get_native_context(env, obj);
    struct service_id srvid;
    struct in_addr ipaddr;

    if (fill_in_service_id(env, service_id, &srvid) == -1)
        return -1;
    
    if (fill_in_addr(env, addr, &ipaddr) == -1)
        return -1;

    return hostctrl_service_add(ctx->hc, &srvid, (unsigned short)prefix_bits, 
                                (unsigned int)priority, (unsigned int)weight, &ipaddr);
}

jint JNICALL Java_org_servalarch_servalctrl_HostCtrl_getService4(JNIEnv *env, jobject obj, 
                                                                 jobject service_id, jint prefix_bits, 
                                                                 jobject addr)
{
    struct jni_context *ctx = get_native_context(env, obj);
    struct service_id srvid;
    struct in_addr ipaddr;

    if (fill_in_service_id(env, service_id, &srvid) == -1)
        return -1;
    
    if (fill_in_addr(env, addr, &ipaddr) == -1)
        return -1;

    return hostctrl_service_get(ctx->hc, &srvid, (unsigned short)prefix_bits, &ipaddr);
}

jint JNICALL Java_org_servalarch_servalctrl_HostCtrl_removeService4(JNIEnv *env, jobject obj, 
                                                                    jobject service_id, jint prefix_bits, 
                                                                    jobject addr)
{
    struct jni_context *ctx = get_native_context(env, obj);
    struct service_id srvid;
    struct in_addr ipaddr;

    if (fill_in_service_id(env, service_id, &srvid) == -1)
        return -1;
    
    if (fill_in_addr(env, addr, &ipaddr) == -1)
        return -1;

    return hostctrl_service_remove(ctx->hc, &srvid, (unsigned short)prefix_bits, &ipaddr);
}

jint JNICALL Java_org_servalarch_servalctrl_HostCtrl_registerService4(JNIEnv *env, jobject obj, 
                                                                      jobject service_id, jint prefix_bits, 
                                                                      jobject addr)
{
    struct jni_context *ctx = get_native_context(env, obj);
    struct service_id srvid;
    struct in_addr ipaddr;

    if (fill_in_service_id(env, service_id, &srvid) == -1)
        return -1;
    
    if (fill_in_addr(env, addr, &ipaddr) == -1)
        return -1;

    return hostctrl_service_register(ctx->hc, &srvid, (unsigned short)prefix_bits, &ipaddr);
}

jint JNICALL Java_org_servalarch_servalctrl_HostCtrl_unregisterService4(JNIEnv *env, jobject obj, 
                                                                        jobject service_id, jint prefix_bits)
{
    struct jni_context *ctx = get_native_context(env, obj);
    struct service_id srvid;

    if (fill_in_service_id(env, service_id, &srvid) == -1)
        return -1;
    
    return hostctrl_service_unregister(ctx->hc, &srvid, (unsigned short)prefix_bits);
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env;
    int ret;

    jvm = vm;

    if ((*jvm)->GetEnv(jvm, (void **)&env, JNI_VERSION_1_4) != JNI_OK) {
        fprintf(stderr, "Could not get JNI env in JNI_OnLoad\n");
        return -1;
    }
    
    ret = libservalctrl_init();
    
	return ret == 0 ? JNI_VERSION_1_4 : ret;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{
	JNIEnv *env = NULL;
    
    libservalctrl_fini();

    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_4) != JNI_OK) {
        fprintf(stderr, "Could not get JNI env in JNI_OnUnload\n");
        return;
    }         
}

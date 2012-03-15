/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */
#include <libservalctrl/hostctrl.h>
#include <libservalctrl/init.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/serval.h>
#include <common/debug.h>
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

/* Cached classes */
static jclass hostctrl_cls;
static jclass hostctrlcallbacks_cls;
static jclass serviceinfo_cls;
static jclass serviceinfostat_cls;
static jclass serviceid_cls;
static jclass inetaddress_cls;

struct jni_context {
    JNIEnv *env;
    jobject obj;
    jobject callbacks;
    struct hostctrl *hc;
};

static struct jni_context *get_native_context(JNIEnv *env, jobject obj)
{
    struct jni_context *ctx;
	jfieldID fid = (*env)->GetFieldID(env, hostctrl_cls, "nativeHandle", "J");

    if (!fid)
        return NULL;

	ctx = (struct jni_context *)jlong_to_ptr((*env)->GetLongField(env, obj, fid));

    return ctx;
}

static int set_native_context(JNIEnv *env, jobject obj, struct jni_context *ctx)
{
	jfieldID fid = (*env)->GetFieldID(env, hostctrl_cls, "nativeHandle", "J");

    if (!fid)
        return -1;
    
    (*env)->SetLongField(env, obj, fid, ptr_to_jlong(ctx));

    return 0;
}

static int fill_in_service_id(JNIEnv *env, jobject obj, struct service_id *sid)
{
    jboolean isCopy = JNI_FALSE;
	jfieldID fid;
    jbyteArray array;
    jbyte *buffer;

    fid = (*env)->GetFieldID(env, serviceid_cls, "identifier", "[B");

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
    (*env)->DeleteLocalRef(env, array);
        
    return 0;
}

static int fill_in_addr(JNIEnv *env, jobject obj, struct in_addr *ipaddr)
{
    jboolean isCopy = JNI_FALSE;
	jmethodID mid;
    jbyteArray array;
    jbyte *buffer;

    memset(ipaddr, 0, sizeof(*ipaddr));

    if (!obj)
        return 0;
    
    mid = (*env)->GetMethodID(env, inetaddress_cls, "getAddress", "()[B");

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
    (*env)->DeleteLocalRef(env, array);

    return 0;
}

static jobject get_callbacks(JNIEnv *env, struct jni_context *ctx)
{
    jfieldID fid;
    jobject obj;

    fid = (*env)->GetFieldID(env, hostctrl_cls, "callbacks", 
                             "Lorg/servalarch/servalctrl/HostCtrlCallbacks;");

    if (!fid) {
        LOG_ERR("could not get fid\n");
        return NULL;
    }

    obj = (*env)->GetObjectField(env, ctx->obj, fid);

    return obj;
}

static jobject new_service_id(JNIEnv *env, const struct service_id *srvid)
{
    jbyteArray arr;
    jobject service_id;
    jmethodID mid;

    mid = (*env)->GetMethodID(env, serviceid_cls, "<init>", "([B)V");

    if (!mid) {
        LOG_ERR("%s methodID not found\n", __func__);
        return NULL;
    }
    arr = (*env)->NewByteArray(env, sizeof(srvid->s_sid));

    if (!arr)
        return NULL;

    (*env)->SetByteArrayRegion(env, arr, 0, 
                               sizeof(srvid->s_sid), 
                               (jbyte *)srvid->s_sid);

    service_id = (*env)->NewObject(env, serviceid_cls, mid, arr);

    (*env)->DeleteLocalRef(env, arr);
    
    return service_id;
}

static jobject new_inet4addr(JNIEnv *env, const struct in_addr *ipaddr)
{
    jbyteArray arr;
    jobject addr;
    jmethodID mid;

    mid = (*env)->GetStaticMethodID(env, inetaddress_cls, "getByAddress", "([B)Ljava/net/InetAddress;");

    if (!mid) {
        LOG_ERR("could not find getByAddress mid\n");
        return NULL;
    }

    arr = (*env)->NewByteArray(env, 4);

    if (!arr) {
        LOG_ERR("could not create byteArray\n");
        return NULL;
    }

    (*env)->SetByteArrayRegion(env, arr, 0, 4, (jbyte *)ipaddr);

    addr = (*env)->CallStaticObjectMethod(env, inetaddress_cls, mid, arr);

    if (!addr) {
        jthrowable exc;

        LOG_ERR("Could not crate IP address\n");

        exc = (*env)->ExceptionOccurred(env);
        
        if (exc) {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
        }
    }

    (*env)->DeleteLocalRef(env, arr);
    
    return addr;
}

static jobject new_service_info(JNIEnv *env, const struct service_info *si)
{
    jmethodID mid;
    jobject service_id, obj;
    jobject addr;
    
    mid = (*env)->GetMethodID(env, serviceinfo_cls, "<init>", 
                              "(Lorg/servalarch/net/ServiceID;IILjava/net/InetAddress;JJJJJ)V");

    if (!mid)
        return NULL;
    
    service_id = new_service_id(env, &si->srvid);

    if (!service_id) {
        LOG_ERR("could not create service_id\n");
        return NULL;
    }

    addr = new_inet4addr(env, &si->address);
    
    obj = (*env)->NewObject(env, serviceinfo_cls, mid, 
                            service_id,
                            (jint)si->srvid_prefix_bits, 
                            (jint)si->srvid_flags,
                            addr,
                            (jlong)si->if_index, 
                            (jlong)si->priority,
                            (jlong)si->weight, 
                            (jlong)si->idle_timeout, 
                            (jlong)si->hard_timeout);

    (*env)->DeleteLocalRef(env, service_id);
    (*env)->DeleteLocalRef(env, addr);
    
    return obj;
}

static jobject new_service_info_stat(JNIEnv *env, const struct service_info_stat *sis)
{
    const struct service_info *si = &sis->service;
    jmethodID mid;
    jobject service_id, addr, obj;

    mid = (*env)->GetMethodID(env, serviceinfostat_cls, "<init>", 
                                    "(Lorg/servalarch/net/ServiceID;SSLjava/net/InetAddress;JJJJJJJJJJJ)V");

    if (!mid)
        return NULL;

    service_id = new_service_id(env, &si->srvid);
    addr = new_inet4addr(env, &si->address);

    obj = (*env)->NewObject(env, serviceinfostat_cls, mid, 
                            service_id,
                            (jint)si->srvid_prefix_bits, 
                            (jint)si->srvid_flags,
                            addr,
                            (jlong)si->if_index, 
                            (jlong)si->priority, 
                            (jlong)si->weight, 
                            (jlong)si->idle_timeout, 
                            (jlong)si->hard_timeout,
                            (jlong)sis->duration_sec,
                            (jlong)sis->duration_nsec,
                            (jlong)sis->packets_resolved,
                            (jlong)sis->bytes_resolved,
                            (jlong)sis->packets_dropped,
                            (jlong)sis->bytes_dropped,
                            (jlong)sis->tokens_consumed);

    (*env)->DeleteLocalRef(env, service_id);
    (*env)->DeleteLocalRef(env, addr);

    return obj;
}

static int on_service_registration(struct hostctrl *hc,
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
    jthrowable exc;

    mid = (*env)->GetMethodID(env, hostctrlcallbacks_cls, "onServiceRegistration", 
                              "(Lorg/servalarch/net/ServiceID;IILjava/net/InetAddress;Ljava/net/InetAddress;)V");

    if (!mid) {
        LOG_ERR("could not find mid\n");
        return -1;
    }

    service_id = new_service_id(env, srvid);
    
    if (!service_id) {
        LOG_ERR("could not create serviceID\n");
        return -1;
    }

    addr = new_inet4addr(env, ip);

    if (!addr) {
        LOG_ERR("could not create addr1\n");
        goto err_addr;
    }

    if (old_ip) {
        old_addr = new_inet4addr(env, old_ip);
        
        if (!old_addr) {
            LOG_ERR("could not create addr2\n");
            goto err_old_addr;
        }
    }

    (*env)->CallVoidMethod(env, get_callbacks(env, ctx), mid, service_id, (jint)flags, 
                           (jint)prefix, addr, old_addr);

    exc = (*env)->ExceptionOccurred(env);
    
    if (exc) {
        LOG_DBG("Callback threw exception\n");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    (*env)->DeleteLocalRef(env, old_addr);
err_old_addr:
    (*env)->DeleteLocalRef(env, addr);
err_addr:
    (*env)->DeleteLocalRef(env, service_id);

    return 0;
}

static int on_service_unregistration(struct hostctrl *hc,
                                     const struct service_id *srvid,
                                     unsigned short flags,
                                     unsigned short prefix,
                                     const struct in_addr *ip)
{
    struct jni_context *ctx = (struct jni_context *)hc->context;
    JNIEnv *env = ctx->env;
    jobject service_id, addr;
    jmethodID mid;
    jthrowable exc;

    mid = (*env)->GetMethodID(env, hostctrlcallbacks_cls, "onServiceUnregistration", 
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
    
    exc = (*env)->ExceptionOccurred(env);
    
    if (exc) {
        LOG_DBG("Callback threw exception\n");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    (*env)->DeleteLocalRef(env, addr);
err_addr:
    (*env)->DeleteLocalRef(env, service_id);

    return 0;
}

static int on_service_stat_update(struct hostctrl *hc,
                                  unsigned int xid,
                                  int retval,
                                  const struct service_stat *stat,
                                  unsigned int num_stat)
{

    /*
    struct jni_context *ctx = (struct jni_context *)hc->context;
    JNIEnv *env = ctx->env;
    */
    return 0;
}

static int on_service_info_callback(struct hostctrl *hc, 
                                    unsigned int xid,
                                    int retval,
                                    const struct service_info *si, 
                                    unsigned int num, 
                                    jmethodID mid)
{
    struct jni_context *ctx = (struct jni_context *)hc->context;
    JNIEnv *env = ctx->env;
    jobjectArray arr = NULL;
    jthrowable exc;
    
    if (num > 0) {
        unsigned int i;

        arr = (*env)->NewObjectArray(env, num, serviceinfo_cls, 0);
        
        if (!arr) {
            LOG_ERR("could not create array\n");
            return -1;
        }

        for (i = 0; i < num; i++) {
            jobject service_info = new_service_info(env, si);
            
            if (!service_info) {
                LOG_ERR("could not create service info object\n");
                (*env)->DeleteLocalRef(env, arr);
                return -1;
            }
            
            (*env)->SetObjectArrayElement(env, arr, i, service_info);
            (*env)->DeleteLocalRef(env, service_info);
        }
    }

    (*env)->CallVoidMethod(env, get_callbacks(env, ctx), mid, (jlong)xid, (jint)retval, arr);

    exc = (*env)->ExceptionOccurred(env);
    
    if (exc) {
        LOG_DBG("Callback threw exception\n");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }
    
    (*env)->DeleteLocalRef(env, arr);

    return 0;
}

static int on_service_get(struct hostctrl *hc,
                          unsigned int xid,
                          int retval,
                          const struct service_info *si,
                          unsigned int num)
{
    struct jni_context *ctx = (struct jni_context *)hc->context;
    JNIEnv *env = ctx->env;
    jmethodID mid;
    
    mid = (*env)->GetMethodID(env, hostctrlcallbacks_cls, "onServiceGet", 
                              "(JI[Lorg/servalarch/servalctrl/ServiceInfo;)V");
    
    if (!mid)
        return -1;

    return on_service_info_callback(hc, xid, retval, si, num, mid);
}

static int on_service_add(struct hostctrl *hc,
                          unsigned int xid,
                          int retval,
                          const struct service_info *si,
                          unsigned int num)
{
    struct jni_context *ctx = (struct jni_context *)hc->context;
    JNIEnv *env = ctx->env;
    jmethodID mid;

    mid = (*env)->GetMethodID(env, hostctrlcallbacks_cls, "onServiceAdd", 
                              "(JI[Lorg/servalarch/servalctrl/ServiceInfo;)V");

    if (!mid) {
        LOG_ERR("Could not find methodID\n");
        return -1;
    }

    return on_service_info_callback(hc, xid, retval, si, num, mid);
}

static int on_service_mod(struct hostctrl *hc,
                          unsigned int xid,
                          int retval,
                          const struct service_info *si,
                          unsigned int num)
{
    struct jni_context *ctx = (struct jni_context *)hc->context;
    JNIEnv *env = ctx->env;
    jmethodID mid;

    mid = (*env)->GetMethodID(env, hostctrlcallbacks_cls, "onServiceMod", 
                              "(JI[Lorg/servalarch/servalctrl/ServiceInfo;)V");

    if (!mid)
        return -1;

    return on_service_info_callback(hc, xid, retval, si, num, mid);
}

static int on_service_remove(struct hostctrl *hc,
                             unsigned int xid,
                             int retval,
                             const struct service_info_stat *si,
                             unsigned int num)
{
    struct jni_context *ctx = (struct jni_context *)hc->context;
    JNIEnv *env = ctx->env;
    jmethodID mid;
    jobjectArray arr = NULL;
    jthrowable exc;

    mid = (*env)->GetMethodID(env, hostctrlcallbacks_cls, "onServiceRemove", 
                              "(JI[Lorg/servalarch/servalctrl/ServiceInfoStat;)V");
    
    if (!mid)
        return -1;

    if (num > 0) {
        unsigned int i;

        arr = (*env)->NewObjectArray(env, num, serviceinfostat_cls, 0);
    
        if (!arr)
            return -1;
    
        for (i = 0; i < num; i++) {
            jobject service_info_stat = new_service_info_stat(env, si);
            
            if (!service_info_stat) {
                (*env)->DeleteLocalRef(env, arr);
                return -1;
            }
            
            (*env)->SetObjectArrayElement(env, arr, i, service_info_stat);
            (*env)->DeleteLocalRef(env, service_info_stat);
        }
    }

    (*env)->CallVoidMethod(env, get_callbacks(env, ctx), mid,
                           (jlong)xid, (jint)retval, arr);

    exc = (*env)->ExceptionOccurred(env);
    
    if (exc) {
        LOG_DBG("Callback threw exception\n");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    (*env)->DeleteLocalRef(env, arr);

    return 0;
}

#include <common/platform.h>
#if defined(OS_ANDROID)
#define JNI_ENV_CAST(env) (env)
#else
#define JNI_ENV_CAST(env) (void **)(env)
#endif

static int hostctrl_on_start(struct hostctrl *hc)
{
    struct jni_context *ctx = (struct jni_context *)hc->context;
    (*jvm)->AttachCurrentThread(jvm, JNI_ENV_CAST(&ctx->env), NULL);
    return 0;
}

static void hostctrl_on_stop(struct hostctrl *hc) {
    if ((*jvm)->DetachCurrentThread(jvm) != JNI_OK) {
        LOG_ERR("%s: Could not detach callback thread\n", __func__);
    }
}

static struct hostctrl_callback cb = {
    .start = hostctrl_on_start,
    .stop = hostctrl_on_stop,
    .service_registration = on_service_registration,
    .service_unregistration = on_service_unregistration,
    .service_stat_update = on_service_stat_update,
    .service_get_result = on_service_get,
    .service_add_result = on_service_add,
    .service_mod_result = on_service_mod,
    .service_remove_result = on_service_remove,
};


enum {
	HOSTCTRL_LOCAL,
	HOSTCTRL_REMOTE,
};

jint JNICALL Java_org_servalarch_servalctrl_HostCtrl_nativeInit(JNIEnv *env, jobject obj, jint type)
{
    struct jni_context *ctx;

    ctx = malloc(sizeof(*ctx));

    if (!ctx)
        return -1;
   
    memset(ctx, 0, sizeof(*ctx));
    ctx->obj = (*env)->NewGlobalRef(env, obj);
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

jint JNICALL Java_org_servalarch_servalctrl_HostCtrl_migrateInterface(JNIEnv *env, jobject obj, 
                                                                      jstring fromIface, jstring toIface)
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

jlong JNICALL Java_org_servalarch_servalctrl_HostCtrl_getXid(JNIEnv *env, jobject obj)
{
    struct jni_context *ctx = get_native_context(env, obj);
    
    if (!ctx->hc)
        return -1;

    return (jlong)ctx->hc->xid;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    JNIEnv *env;
    int ret;

    jvm = vm;

    if ((*jvm)->GetEnv(jvm, (void **)&env, JNI_VERSION_1_4) != JNI_OK) {
        LOG_ERR("Could not get JNI env in JNI_OnLoad\n");
        return -1;
    }
    
    ret = libservalctrl_init();

	hostctrl_cls = (*env)->FindClass(env, "org/servalarch/servalctrl/HostCtrl");

    if (!hostctrl_cls) {
        LOG_ERR("could not find HostCtrl class\n");
        return -1;
    }

    hostctrlcallbacks_cls = (*env)->FindClass(env, "org/servalarch/servalctrl/HostCtrlCallbacks");

    if (!hostctrlcallbacks_cls) {
        LOG_ERR("could not find HostCtrlCallbacks class\n");
        return -1;
    }

	serviceinfo_cls = (*env)->FindClass(env, "org/servalarch/servalctrl/ServiceInfo");

    if (!serviceinfo_cls) {
        LOG_ERR("could not find ServiceInfo class\n");
        return -1;
    }

	serviceinfostat_cls = (*env)->FindClass(env, "org/servalarch/servalctrl/ServiceInfoStat");

    if (!serviceinfostat_cls) {
        LOG_ERR("could not find ServiceInfoStat class\n");
        return -1;
    }

	serviceid_cls = (*env)->FindClass(env, "org/servalarch/net/ServiceID");

    if (!serviceid_cls) {
        LOG_ERR("could not find ServiceID class\n");
        return -1;
    }

    inetaddress_cls = (*env)->FindClass(env, "java/net/InetAddress");

    if (!inetaddress_cls) {
        LOG_ERR("could not find InetAddress class\n");
        return -1;
    }

    hostctrl_cls = (*env)->NewGlobalRef(env, hostctrl_cls);
    hostctrlcallbacks_cls = (*env)->NewGlobalRef(env, hostctrlcallbacks_cls);
    serviceinfo_cls  = (*env)->NewGlobalRef(env, serviceinfo_cls);
    serviceinfostat_cls = (*env)->NewGlobalRef(env, serviceinfostat_cls);
    serviceid_cls = (*env)->NewGlobalRef(env, serviceid_cls);
    inetaddress_cls = (*env)->NewGlobalRef(env, inetaddress_cls);
    
	return ret == 0 ? JNI_VERSION_1_4 : ret;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{
	JNIEnv *env = NULL;
    
    libservalctrl_fini();

    (*env)->DeleteGlobalRef(env, hostctrl_cls);
    (*env)->DeleteGlobalRef(env, hostctrlcallbacks_cls);
    (*env)->DeleteGlobalRef(env, serviceinfo_cls);
    (*env)->DeleteGlobalRef(env, serviceinfostat_cls);
    (*env)->DeleteGlobalRef(env, serviceid_cls);
    (*env)->DeleteGlobalRef(env, inetaddress_cls);

    if ((*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_4) != JNI_OK) {
        LOG_ERR("Could not get JNI env in JNI_OnUnload\n");
        return;
    }         
}

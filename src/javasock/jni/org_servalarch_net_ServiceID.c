/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- */
#include "org_servalarch_net_ServiceID.h"
#include <netinet/serval.h>
/*
 * Class:     org_servalarch_net_ServiceID
 * Method:    fqdnToService
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT
jstring Java_org_servalarch_net_ServiceID_fqdnToService(JNIEnv *env, 
                                                        jobject obj, 
                                                        jstring fqdn)
{
        const char *fqdn_str;
        struct service_id srvid;

        fqdn_str = (*env)->GetStringUTFChars(env, fqdn, NULL);

        if (fqdn_str == NULL)
                return NULL;

        memset(&srvid, '\0', sizeof(srvid));
     
        if (serval_pton(fqdn_str, &srvid) != 1) {
                (*env)->ReleaseStringUTFChars(env, fqdn, fqdn_str);
                return NULL;
        }
        
        (*env)->ReleaseStringUTFChars(env, fqdn, fqdn_str);
        
        return (*env)->NewStringUTF(env, srvid.s_sid);
}

/*
 * Class:     org_servalarch_net_ServiceID
 * Method:    serviceToFqdn
 * Signature: (Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT 
jstring Java_org_servalarch_net_ServiceID_serviceToFqdn(JNIEnv *env, 
                                                        jobject obj, 
                                                        jstring service)
{
        const char *service_str;
        char fqdn[SERVICE_ID_MAX_LEN+1];

        service_str = (*env)->GetStringUTFChars(env, service, NULL);

        if (service_str == NULL)
                return NULL;

        if (serval_ntop(service_str, fqdn, sizeof(fqdn)) == NULL) {
                (*env)->ReleaseStringUTFChars(env, service, service_str);
                return NULL;
        }

        (*env)->ReleaseStringUTFChars(env, service, service_str);
        
        return (*env)->NewStringUTF(env, fqdn);
 }

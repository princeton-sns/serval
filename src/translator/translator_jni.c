/* -*- Mode: C; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 8 -*- 
 *
 * JNI connections for translator
 *
 * Authors: Erik Nordström <enordstr@cs.princeton.edu>
 * 
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation; either version 2 of
 *	the License, or (at your option) any later version.
 */
#include <jni.h>
#include <netinet/in.h>
#include "translator.h"

JNIEXPORT 
jint JNICALL Java_org_servalarch_serval_TranslatorService_runTranslator(JNIEnv *env, 
                                                                        jobject obj, jint port, jboolean xtranslate)
{
        return run_translator(port & 0xffff, NULL, (int)xtranslate, INET_ONLY_MODE);
}

JNIEXPORT 
jint JNICALL Java_org_servalarch_serval_TranslatorService_shutdown(JNIEnv *env , jobject obj)
{
        signal_raise_val(&main_signal, 1);
}

JNIEXPORT 
jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
        signal_raise_val(&main_signal, SIGNAL_EXIT);

	return JNI_VERSION_1_4;
}

JNIEXPORT 
void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{
}

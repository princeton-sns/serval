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

extern int run_translator(int, int);
extern struct signal exit_signal;
extern int cross_translate;

JNIEXPORT 
jint JNICALL Java_org_servalarch_serval_TranslatorService_runTranslator(JNIEnv *env, 
                                                                        jobject obj, jint port, jboolean xtranslate)
{
        cross_translate = (xtranslate == JNI_TRUE) ? 1 : 0;
        return run_translator(AF_INET, (int)port);
}

JNIEXPORT 
jint JNICALL Java_org_servalarch_serval_TranslatorService_shutdown(JNIEnv *env , jobject obj)
{
	signal_raise(&exit_signal);
}

JNIEXPORT 
jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
	signal_init(&exit_signal);

	return JNI_VERSION_1_4;
}

JNIEXPORT 
void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{
}

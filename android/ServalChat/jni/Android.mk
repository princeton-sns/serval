LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)

subdirs := $(addprefix $(APP_PROJECT_PATH)/../../,$(addsuffix /Android.mk, \
                src/javasock/jni \
        ))

include $(subdirs)

# Build all java files in the src subdirectory
LOCAL_SRC_FILES := $(call all-java-files-under,../src)

LOCAL_STATIC_JAVA_LIBRARIES := org.servalarch.javasock

# Enabling the following line will bundle all necessary libraries with the 
# application package
LOCAL_JNI_SHARED_LIBRARIES += libservalnet_jni

# Name of the APK to build
LOCAL_PACKAGE_NAME := ServalChat

LOCAL_PROGUARD_FLAGS := -include $(LOCAL_PATH)/proguard.cfg

# Tell it to build an APK
include $(BUILD_PACKAGE)

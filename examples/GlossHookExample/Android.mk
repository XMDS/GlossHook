LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := GlossHook
LOCAL_SRC_FILES := $(LOCAL_PATH)/$(TARGET_ARCH)/libGlossHook.a
include $(PREBUILT_STATIC_LIBRARY)
 
include $(CLEAR_VARS)
LOCAL_MODULE := GlossHookDemo
LOCAL_CPP_EXTENSION := .cpp
LOCAL_SRC_FILES := main.cpp
LOCAL_EXPORT_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/include
LOCAL_CPPFLAGS += -std=c++17 -Wall -Wextra -Werror
LOCAL_LDLIBS += -llog
ifeq ($(TARGET_ARCH_ABI),arm64-v8a)
    LOCAL_LDFLAGS += -Wl,-z,max-page-size=16384
else ifeq ($(TARGET_ARCH_ABI), armeabi-v7a)
    LOCAL_CPPFLAGS += -mfloat-abi=softfp
endif
LOCAL_STATIC_LIBRARIES := GlossHook
include $(BUILD_EXECUTABLE)
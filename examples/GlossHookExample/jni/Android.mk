LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := GlossHook
LOCAL_SRC_FILES := $(LOCAL_PATH)/GlossHook/lib/$(TARGET_ARCH)/libGlossHook.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/GlossHook/include/
include $(PREBUILT_STATIC_LIBRARY)
 
include $(CLEAR_VARS)
LOCAL_MODULE    := GlossHookExample
LOCAL_CPP_EXTENSION := .cpp
LOCAL_SRC_FILES := GlossHookExample.cpp
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
LOCAL_STATIC_LIBRARIES := libGlossHook
LOCAL_CXXFLAGS += -O0 -mthumb -Wall
LOCAL_CONLYFLAGS := -std=c++17
LOCAL_LDLIBS += -landroid -llog -ldl
# LOCAL_ARM_MODE := arm

include $(BUILD_EXECUTABLE)

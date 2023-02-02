#pragma once
#include <android/log.h>

#ifndef GLOSS_TAG
#define GLOSS_TAG "GlossHook"

#define WLOGI(text) ((void)__android_log_write(ANDROID_LOG_INFO, GLOSS_TAG, text))
#define WLOGE(text) ((void)__android_log_write(ANDROID_LOG_ERROR, GLOSS_TAG, text))
#define WLOGD(text) ((void)__android_log_write(ANDROID_LOG_DEBUG, GLOSS_TAG, text))
#define WLOGW(text) ((void)__android_log_write(ANDROID_LOG_WARN, GLOSS_TAG, text))

#define GLOGI(text, ...) ((void)__android_log_print(ANDROID_LOG_INFO, GLOSS_TAG, text, __VA_ARGS__))
#define GLOGE(text, ...) ((void)__android_log_print(ANDROID_LOG_ERROR, GLOSS_TAG, text, __VA_ARGS__))
#define GLOGD(text, ...) ((void)__android_log_print(ANDROID_LOG_DEBUG, GLOSS_TAG, text, __VA_ARGS__))
#define GLOGW(text, ...) ((void)__android_log_print(ANDROID_LOG_WARN, GLOSS_TAG, text, __VA_ARGS__))

#endif
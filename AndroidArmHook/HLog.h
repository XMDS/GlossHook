#pragma once
#include <android/log.h>

#ifndef HTAG
#define HTAG "ARMHook"

#define WLOGI(text) ((void)__android_log_write(ANDROID_LOG_INFO, HTAG, text))
#define WLOGE(text) ((void)__android_log_write(ANDROID_LOG_ERROR, HTAG, text))
#define WLOGD(text) ((void)__android_log_write(ANDROID_LOG_DEBUG, HTAG, text))
#define WLOGW(text) ((void)__android_log_write(ANDROID_LOG_WARN, HTAG, text))

#define HLOGI(text, ...) ((void)__android_log_print(ANDROID_LOG_INFO, HTAG, text, __VA_ARGS__))
#define HLOGE(text, ...) ((void)__android_log_print(ANDROID_LOG_ERROR, HTAG, text, __VA_ARGS__))
#define HLOGD(text, ...) ((void)__android_log_print(ANDROID_LOG_DEBUG, HTAG, text, __VA_ARGS__))
#define HLOGW(text, ...) ((void)__android_log_print(ANDROID_LOG_WARN, HTAG, text, __VA_ARGS__))

#endif // !HTAG
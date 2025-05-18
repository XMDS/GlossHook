NDK_TOOLCHAIN_VERSION := clang

APP_STL := c++_static

APP_ABI := armeabi-v7a arm64-v8a

ifeq ($(NDK_DEBUG), 1)
	APP_OPTIM := debug
else
	APP_OPTIM := release
endif

APP_PLATFORM := android-21
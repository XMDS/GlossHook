# GlossHook
GlossHook is a simple yet feature-rich Android NativeHook library, well-suited for Android game modification and mod development, and it can also be applied in other contexts.
GlossHook is utilized by AndroidModLoader and has enabled the creation of a vast number of mods for Android GTA games, demonstrating its stability!

GlossHook是一个简单、功能多的安卓NativeHook库，适用于安卓游戏修改和模组制作，它也能用于其它场景。
GlossHook被AndroidModLoader使用，为安卓GTA游戏创建了大量模组，它是稳定的！

[AML](https://github.com/RusJJ/AndroidModLoader.git)

# Features
## English
- Supports InlineHook and PltHook (GotHook) for thumb/arm/arm64 architectures.

- Supports Android 5.0～14.0.

- Supports hooking at a single call site (branch instructions BL/BLX) of a function. Sometimes, you may only need to hook one specific call site of a function rather than all its call sites.

- Supports hooking at any arbitrary location within a function. Within the proxy function, you can read/write registers and the stack at that location and insert any type of function call.

- Supports inserting inline assembly functions (asm) at a specific location.

- Supports hooking functions in the Linker, such as dlopen/dlsym, etc.

- Supports hooking for loading dynamic libraries (so) in the future.

- Supports hooking constructor/entry functions (.init and .init_array sections functions).

- Supports the shortest 4-byte hooking, accommodating short functions.

- Supports multiple hooking at the same location.

- Supports calling back the original function within the proxy function or directly replacing the function without calling back.

- Supports enable/disable/delete any single or multiple hooking. When enable/disable/delete a single hooking, it does not affect other hooking at the same location.

- Provides commonly used APIs for retrieving dynamic library (so) information, such as obtaining the base address and searching for symbol addresses.

- Provide APIs for writing to memory, reading from memory, and removing memory protection.

- Provides APIs for writing assembly instructions, such as commonly used assembly instructions like NOP/RET/B.

- For more APIs, refer to the header file descriptions.

## 中文
* 支持thumb/arm/arm64的InlineHook和PltHook(GotHook).

* 支持安卓5.0～14.0.

* 支持对函数单个调用点的hook(分支指令BL/BLX)，有时候你可能只需要hook函数其中一处调用点，而不是函数的全部调用点.

* 支持对函数内任意位置的hook，在代理函数中可读写该位置的寄存器和栈，插入任何类型的函数调用.

* 支持对一个位置插入内嵌汇编函数(asm).

* 支持对Linke中函数的hook，例如dlopen/dlsym等.

* 支持对未来加载动态库(so)的hook.

* 支持对构造函数/入口函数的hook(.init和.init_array节中的函数).

* 支持最短4字节hook，适配短函数.

* 支持对同一个位置的多次hook.

* 支持代理函数中回调原函数，也可不回调直接替换函数.

* 支持开启/关闭/删除任意一个或多个hook. 开启/关闭/删除任意1个hook时，对同位置其它hook不影响.

* 提供常用的获取动态库(so)信息的API，例如获取首地址，查找符号地址等.

* 提供写入内存/读取内存/解除内存保护/的API.

* 提供汇编指令写入API，例如NOP/RET/B等常用汇编指令.

* 更多其它API见头文件说明.
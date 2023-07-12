# GlossHook
A simple Android arm Hook library.

## 中文说明
一个简易、功能多的安卓arm hook库.
GlossHook目前只是一个arm的分支版本，待以后更新(目前稳定性不敢保证)，但基本上可以使用.

### 特性
* 支持thumb/arm/arm64的InlineHook和GotHook(不是PLT Hook).
* 支持对单个分支指令(B BL BLX)调用函数的hook，有时候你可能只需要hook其中一处调用点，而不是函数的全部调用点.
* 支持短函数Hook(最短4字节函数).
* 支持对函数代码内任意位置地址的hook patch，在用户函数中可读写hook位置的寄存器、栈、调用任何类型的函数.
* hook后，可回调原函数，也可不回调直接替换函数.
* 支持对同一个位置的多次hook.
* 同一个位置有多个hook时， 支持通过hook指针和hook位置，开启/关闭/删除任意一个或全部的hook. 开启/关闭/删除任意1个hook时，对同位置其它hook不影响.
* 如果多个使用方使用GlossHook对同一个位置hook，任意一个使用方可以通过地址开启/关闭/删除其它的hook.
* 提供了函数获取一个位置被hook的数量.
* 支持替换已经正在hook的用户函数
* 提供常用的库查找、库信息、获取符号地址、读写内存、解除内存权限等API函数.
* 其它待更新ing

## English
Features:
- Support for Android Thumb/ARM/ARM64 architectures.

- Implementation of Inline Hook and GotHook (not PLT Hook).

- Support for hooking a single branch instruction (B, BL, BLX) calling a function. Sometimes you may only need to hook one specific call site of a function, rather than all call sites.

- Support for hooking short functions (minimum 4 bytes).

- Support for hook patching at any address within executable code. You can read and write registers, stack, and call other functions within your hooked function.

- After hooking, you can choose to either callback the original function or directly replace the function.

- Support for multiple hooks at the same location.

- For multiple hooks at the same location, you can enable/disable/remove any individual hook or all hooks using the hook pointer or hook address. Enabling/disabling/removing one hook does not affect other hooks at the same location.

- If multiple users use GlossHook to hook the same location, any user can enable/disable/remove other hooks using the hook pointer.

- Provides a function to get the number of hooks at a specific location.

- Support for replacing a user function that is already being hooked.

- Provides common API functions for library lookup, library information, symbol address retrieval, memory read/write, and memory permission removal, etc.

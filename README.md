# GlossHook
A simple Android arm Hook library.

## 中文说明
一个简易、功能强大的安卓arm Hook库.
GlossHook仍然处于早期版本，虽然时间少，但尽量更新，更加完善和稳定.

### 特性
* 支持thumb/arm的InlineHook(arm64待更新)
* 目前仅支持对整个函数hook，对函数替换、注入等
* 支持对同一个函数多次hook.
* 同一个函数有多个hook时，
支持通过hook指针和hook地址，取消/恢复/删除任意一个或全部的hook.
取消任意1个hook时，对其它hook不影响.
* 提供常用的库查找、获取符号地址、读写内存、解除内存等API函数
* 其它待更新ing…

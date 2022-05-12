#pragma once
#include <stdint.h>

namespace ARMHook
{
	class Call
	{
	public:
		template <typename Ret, typename... Args>
		static Ret FunctionCdecl(uintptr_t address, Args... args) {
			volatile uintptr_t address_ = address;
			return reinterpret_cast<Ret(__cdecl*)(Args...)>(address_)(args...);
		}

		template <typename Ret, typename... Args>
		static Ret FunctionFastCall(uintptr_t address, Args... args) {
			volatile uintptr_t address_ = address;
			return reinterpret_cast<Ret(__fastcall*)(Args...)>(address_)(args...);
		}

		template <typename Ret, typename... Args>
		static Ret FunctionStdCall(uintptr_t address, Args... args) {
			volatile uintptr_t address_ = address;
			return reinterpret_cast<Ret(__stdcall*)(Args...)>(address_)(args...);
		}

		template <typename Ret, typename... Args>
		static Ret Function(uintptr_t address, Args... args) {
			uintptr_t address_ = address;
			return reinterpret_cast<Ret(__cdecl*)(Args...)>(address_)(args...);
		}

		template <typename Ret, typename C, typename... Args>
		static Ret Method(uintptr_t address, C _this, Args... args) {
			volatile uintptr_t address_ = address;
			return reinterpret_cast<Ret(__thiscall*)(C, Args...)>(address_)(_this, args...);
		}
	};
}



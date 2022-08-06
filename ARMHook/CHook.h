#pragma once
#include <vector>
#include <sys/mman.h>
#include "Assembly/InstructionType.h"
#include "Include/xdl.h"

struct bytePattern
{
	struct byteEntry
	{
		uint8_t nValue;
		bool bUnknown;
	};
	std::vector<byteEntry> vBytes;
};

namespace ARMHook
{
	class CHook
	{
	public:
		static uintptr_t GetLibAddress(const char* libName, pid_t pid = -1);
		static uintptr_t GetLibLength(const char* libName, pid_t pid = -1);
		static void* GetLibHandle(const char* libName);
		static const char* GetLibFilePath(uintptr_t libAddr);
		static size_t GetLibFileSize(uintptr_t libAddr);
		static uintptr_t GetSymbolAddress(void* handle, const char* name);
		static uintptr_t GetSymbolAddress(uintptr_t LibAddr, const char* name);
		static bool unprotect(uintptr_t addr, size_t len = PAGE_SIZE);
		static void WriteMemory(void* addr, void* data, size_t size);
		static void* ReadMemory(void* addr, void* data, size_t size);

		template <typename T>
		inline static void WriteMemory(uintptr_t addr, T value)
		{
			WriteMemory((void*)addr, &value, sizeof(T));
		}
		template <typename T>
		inline static T ReadMemory(uintptr_t addr)
		{
			T value = NULL;
			return *reinterpret_cast<T*>(ReadMemory((void*)addr, &value, sizeof(T)));
		}

		static void PLTInternal(void* addr, void* func, void** original);
		static void Inline(void* addr, void* func, void** original);
		static uintptr_t GetAddressFromPattern(const char* pattern, const char* library);
		static uintptr_t GetAddressFromPattern(const char* pattern, uintptr_t libStart, uintptr_t scanLen);

		
		static void MakeArmNOP(uintptr_t addr, size_t size);
		static void MakeArmRET(uintptr_t addr, bool type = false);

#ifdef __arm__
		static void MakeThumbNOP(uintptr_t addr, size_t size);
		static void MakeThumbRET(uintptr_t addr, bool type = false);

		static void MakeThumbBL(uintptr_t addr, uintptr_t func);
		static void MakeThumbBLX(uintptr_t addr, uintptr_t func);
		static void MakeThumbB(uintptr_t addr, uintptr_t targe);
		static void MakeThumbB(uintptr_t addr, uintptr_t targe, cond_type cond);
		static void MakeThumbCBZ_CBNZ(uintptr_t addr, uintptr_t targe, uint8_t reg, bool is_cbnz);
		static void MakeThumbB_W(uintptr_t addr, uintptr_t targe);
		static void MakeThumbB_W(uintptr_t addr, uintptr_t targe, cond_type cond);
#endif
		
		static void MakeArmBL(uintptr_t addr, uintptr_t func);
		static void MakeArmB(uintptr_t addr, uintptr_t targe);
		static void MakeArmB(uintptr_t addr, uintptr_t targe, cond_type cond);

#ifdef __aarch64__
		static void MakeArmCBZ_CBNZ(uintptr_t addr, uintptr_t targe, uint8_t reg, bool is_cbnz, bool is64);
#endif

		static uintptr_t GetThumbCallAddr(uintptr_t addr);
		static uintptr_t GetArmCallAddr(uintptr_t addr);
		
		static InstructionType GetThumbInstructionType(uintptr_t addr, bool isThumb32);
		static InstructionType GetArmInstructionType(uintptr_t addr);

		/*
		static uintptr_t InitialiseTrampolines(uintptr_t addr, size_t size);
		static void ReplaceThumbCall(uintptr_t addr, uintptr_t func);
		static void ReplaceArmCall(uintptr_t addr, uintptr_t func);
		static void HookThumbFunc(void* func, uint32_t startSize, void* func_to, void** func_orig);
		static void HookArmFunc(void* func, uint32_t startSize, void* func_to, void** func_orig);
		*/
	};	
}
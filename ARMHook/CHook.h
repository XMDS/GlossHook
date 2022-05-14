#pragma once
#include <vector>
#include <sys/mman.h>
#include "Assembly/InstructionType.h"

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
		static uintptr_t GetLibraryAddress(const char* library);
		static uintptr_t GetLibraryLength(const char* library);
		static void* GetLibHandle(const char* library);
		static const char* GetLibraryFilePath(uintptr_t LibAddr);
		static uintptr_t GetSymbolAddress(void* handle, const char* name);
		static uintptr_t GetSymbolAddress(uintptr_t LibAddr, const char* name);
		static int unprotect(uintptr_t addr, size_t len = PAGE_SIZE);
		static void WriteMemory(void* addr, void* data, size_t size);
		static void* ReadMemory(void* addr, void* data, size_t size);
		static void PLTInternal(void* addr, void* func, void** original);
		static void Internal(void* addr, void* func, void** original);
		static uintptr_t GetAddressFromPattern(const char* pattern, const char* library);
		static uintptr_t GetAddressFromPattern(const char* pattern, uintptr_t libStart, uintptr_t scanLen);

		static void MakeThumbNOP(uintptr_t addr, size_t size);
		static void MakeArmNOP(uintptr_t addr, size_t size);
		static void MakeThumbRET(uintptr_t addr, int type);
		static void MakeArmRET(uintptr_t addr, int type);

		static void MakeThumbBL(uintptr_t addr, uintptr_t func);
		static void MakeThumbBLX(uintptr_t addr, uintptr_t func);
		static void MakeThumbB(uintptr_t addr, uintptr_t targe);
		static void MakeThumbB(uintptr_t addr, uintptr_t targe, cond_type cond);
		static void MakeThumbCBZ_CBNZ(uintptr_t addr, uintptr_t targe, uint8_t reg, bool nonzero);
		static void MakeThumbB_W(uintptr_t addr, uintptr_t func);
		static void MakeThumbB_W(uintptr_t addr, uintptr_t targe, cond_type cond);

		static void MakeArmBL(uintptr_t addr, uintptr_t func);
		static void MakeArmB(uintptr_t addr, uintptr_t targe);
		static void MakeArmB(uintptr_t addr, uintptr_t targe, cond_type cond);

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
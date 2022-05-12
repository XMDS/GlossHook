#pragma once
#include "Assembly/UsefulMacros.h"
#include <stdint.h>
#include <vector>

enum eInstructionSet
{
	INSTRUCTION_SET_UNDEFINED,
	INSTRUCTION_SET_ARM,
	INSTRUCTION_SET_THUMB,
};

namespace ARMHook
{
	class CPatch
	{
	public:
		static void WriteDataToMemory(uintptr_t addr, void* data, int size);
		static void SetUint8(uintptr_t addr, uint8_t value);
		static void SetUint16(uintptr_t addr, uint16_t value);
		static void SetUint32(uintptr_t addr, uint32_t value);
		static void SetPointer(uintptr_t addr, void* value);
		static void SetFloat(uintptr_t addr, float value);
		static uint8_t GetUint8(uintptr_t addr);
		static uint16_t GetUint16(uintptr_t addr);
		static uint32_t GetUint32(uintptr_t addr);
		static void* GetPointer(uintptr_t addr);
		static float GetFloat(uintptr_t addr);
		static void NOP(eInstructionSet sourceInstructionSet, uintptr_t dwAddress, int iSize);
		static void RedirectCode(eInstructionSet sourceInstructionSet, uintptr_t dwAddress, uintptr_t to);
		static void RedirectCodeEx(eInstructionSet sourceInstructionSet, uintptr_t dwAddress, const void* to);
		static void RedirectFunction(uintptr_t functionJumpAddress, void* to);
	};
}
#include "CPatch.h"
#include "CHook.h"
#include <unistd.h>

namespace ARMHook
{
	void CPatch::WriteDataToMemory(uintptr_t addr, void* data, int size)
	{
		CHook::WriteMemory((void*)addr, data, size);
	}

	void CPatch::SetUint8(uintptr_t addr, uint8_t value)
	{
		CHook::WriteMemory((void*)addr, &value, sizeof(value));
	}

	void CPatch::SetUint16(uintptr_t addr, uint16_t value)
	{
		CHook::WriteMemory((void*)addr, &value, sizeof(value));
	}

	void CPatch::SetUint32(uintptr_t addr, uint32_t value)
	{
		CHook::WriteMemory((void*)addr, &value, sizeof(value));
	}

	void CPatch::SetPointer(uintptr_t addr, void* value)
	{
		CHook::WriteMemory((void*)addr, &value, sizeof(value));
	}

	void CPatch::SetFloat(uintptr_t addr, float value)
	{
		CHook::WriteMemory((void*)addr, &value, sizeof(value));
	}

	uint8_t CPatch::GetUint8(uintptr_t addr)
	{
		uint8_t value;
		CHook::ReadMemory((void*)addr, &value, sizeof(uint8_t));
		return value;
	}

	uint16_t CPatch::GetUint16(uintptr_t addr)
	{
		uint16_t value;
		CHook::ReadMemory((void*)addr, &value, sizeof(uint16_t));
		return value;
	}

	uint32_t CPatch::GetUint32(uintptr_t addr)
	{
		uint32_t value;
		CHook::ReadMemory((void*)addr, &value, sizeof(uint32_t));
		return value;
	}

	void* CPatch::GetPointer(uintptr_t addr)
	{
		uintptr_t value;
		CHook::ReadMemory((void*)addr, &value, sizeof(uintptr_t));
		return (void*)value;
	}

	float CPatch::GetFloat(uintptr_t addr)
	{
		float value;
		CHook::ReadMemory((void*)addr, &value, sizeof(float));
		return value;
	}
	
	void CPatch::NOP(eInstructionSet sourceInstructionSet, uintptr_t dwAddress, int iSize)
	{
		if (sourceInstructionSet == INSTRUCTION_SET_THUMB)
			return CHook::MakeThumbNOP(dwAddress, iSize);

		else if (sourceInstructionSet == INSTRUCTION_SET_ARM)
			return CHook::MakeArmNOP(dwAddress, iSize);
	}

	void CPatch::RedirectCode(eInstructionSet sourceInstructionSet, uintptr_t dwAddress, uintptr_t to)
	{
		return RedirectCodeEx(sourceInstructionSet, dwAddress, (const void*)to);
	}

	//by fastamn92
	void CPatch::RedirectCodeEx(eInstructionSet sourceInstructionSet, uintptr_t dwAddress, const void* to)
	{
		// Thumb trampoline may take 8 bytes (if address is aligned to value of 4) or 10 bytes.
		if (sourceInstructionSet == INSTRUCTION_SET_THUMB)
		{
			char code[12];
			unsigned int sizeOfData = 0;

			if (dwAddress % 4 == 0)
			{
				*(uint32_t*)(code + 0) = 0xF000F8DF;	//LDR.W PC, [PC, #0]
				*(const void**)(code + 4) = to;	// pointer, where to jump
				sizeOfData = 8;
			}
			else
			{
				*(uint32_t*)(code + 0) = 0xBF00;     //NOP
				*(uint32_t*)(code + 2) = 0xF000F8DF; //LDR.W PC, [PC, #0]

				*(const void**)(code + 6) = to;	// pointer, where to jump
				sizeOfData = 10;
			}

			WriteDataToMemory(dwAddress, code, sizeOfData);
		}
		else if (sourceInstructionSet == INSTRUCTION_SET_ARM)
		{
			char code[8];

			*(uint32_t*)(code + 0) = 0xE51FF004;	//LDR PC, [PC, #-4]
			*(const void**)(code + 4) = to;	// pointer, where to jump
			WriteDataToMemory(dwAddress, code, sizeof(code));
		}
	}

	void CPatch::RedirectFunction(uintptr_t functionJumpAddress, void* to)
	{
		RedirectCodeEx(
			GET_INSTRUCTION_SET_FROM_ADDRESS(functionJumpAddress),
			GET_CODE_START(functionJumpAddress),
			to
		);
	}
}

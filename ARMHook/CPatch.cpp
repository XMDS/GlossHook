#include "CPatch.h"
#include <unistd.h>
#include <android/log.h>
#include "CHook.h"

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
		if (sourceInstructionSet == SET_THUMB)
			return CHook::MakeThumbNOP(dwAddress, iSize);
		else if (sourceInstructionSet == SET_ARM)
			return CHook::MakeArmNOP(dwAddress, iSize);
		else
			return;
	}

	void CPatch::RedirectCode(eInstructionSet sourceInstructionSet, uintptr_t dwAddress, uintptr_t to)
	{
		return RedirectCodeEx(sourceInstructionSet, dwAddress, (const void*)to);
	}

	//by fastamn92
	void CPatch::RedirectCodeEx(eInstructionSet sourceInstructionSet, uintptr_t dwAddress, const void* to)
	{
		// Thumb trampoline may take 8 bytes (if address is aligned to value of 4) or 10 bytes.
		if (sourceInstructionSet == SET_THUMB)
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
		else if (sourceInstructionSet == SET_ARM)
		{
			char code[8];

			*(uint32_t*)(code + 0) = 0xE51FF004;	//LDR PC, [PC, #-4]
			*(const void**)(code + 4) = to;	// pointer, where to jump
			WriteDataToMemory(dwAddress, code, sizeof(code));
		}
	}

	void CPatch::RedirectFunction(uintptr_t addr, void* func)
	{
		RedirectCodeEx(
			GET_INSTRUCTION_SET_FROM_ADDRESS(addr),
			GET_CODE_START(addr),
			func
		);
	}

	//Trampolines Hook
	uintptr_t CPatch::Trampolines_addr_start = 0;
	uintptr_t CPatch::Trampolines_addr_end = 0;
	
	void CPatch::SetTrampolinesHook(uintptr_t addr, int32_t num_trampolines)
	{
		while (addr % 4) addr += 1;
		Trampolines_addr_start = addr;
		Trampolines_addr_end = Trampolines_addr_start + num_trampolines * 8;
	}
	
	void CPatch::CheckTrampolinesLimit()
	{
		while (CHook::GetThumbInstructionType(Trampolines_addr_start, true) == LDRW_THUMB32 || CHook::GetArmInstructionType(Trampolines_addr_start) == LDR_ARM)
			Trampolines_addr_start += 8;
		
		if (Trampolines_addr_start == 0 || Trampolines_addr_end == 0 || Trampolines_addr_end < (Trampolines_addr_start + 8))
		{
			__android_log_write(ANDROID_LOG_ERROR, "ARMHook", "Error!!! Trampolines Space limit reached.");
			exit(1);
		}
	}

	void CPatch::TrampolinesRedirectCall(eInstructionSet sourceInstructionSet, uintptr_t addr, void* func, void** orig_func, InstructionType CallType)
	{
		CPatch::CheckTrampolinesLimit();
		uintptr_t naddr = GET_CODE_START(Trampolines_addr_start);
		if (sourceInstructionSet == SET_THUMB)
		{
			addr = GET_CODE_START(addr);
			InstructionType type = CHook::GetThumbInstructionType(addr, true);
			if (type == BW_THUMB32 || type == BL_THUMB32)
			{
				if (orig_func != NULL)
					*orig_func = (void*)ASM_GET_THUMB_ADDRESS_FOR_JUMP(CHook::GetThumbCallAddr(addr));
			}
			else if (type == BLX_THUMB32)
			{
				if (orig_func != NULL)
					*orig_func = (void*)ASM_GET_ARM_ADDRESS_FOR_JUMP(CHook::GetThumbCallAddr(addr));
			}
			else
				return;

			if (CallType == BW_THUMB32) {
				CHook::MakeThumbB_W(addr, naddr);
				sourceInstructionSet = SET_THUMB;
			}
			else if (CallType == BL_THUMB32) {
				CHook::MakeThumbBL(addr, naddr);
				sourceInstructionSet = SET_THUMB;
			}
			else if (CallType == BLX_THUMB32) {
				CHook::MakeThumbBLX(addr, naddr);
				sourceInstructionSet = SET_ARM;
			}
			else
				return;
			
			RedirectCode(sourceInstructionSet, naddr, ASM_GET_THUMB_ADDRESS_FOR_JUMP((uintptr_t)func));
		}
		else if (sourceInstructionSet == SET_ARM)
		{
			InstructionType type = CHook::GetArmInstructionType(addr);
			if (type == B_ARM || type == BL_ARM)
			{
				if (orig_func != NULL)
					*orig_func = (void*)ASM_GET_ARM_ADDRESS_FOR_JUMP(CHook::GetArmCallAddr(addr));
			}
			else if (type == BLX_ARM)
			{
				if (orig_func != NULL)
					*orig_func = (void*)ASM_GET_THUMB_ADDRESS_FOR_JUMP(CHook::GetArmCallAddr(addr));
			}
			else
				return;

			if (CallType == B_ARM)
			{
				CHook::MakeArmB(addr, naddr);
				sourceInstructionSet = SET_ARM;
			}
			else if (CallType == BL_ARM || CallType == BLX_ARM)
			{
				CHook::MakeArmBL(addr, naddr);
				sourceInstructionSet = SET_ARM;
			}
			else
				return;

			RedirectCode(sourceInstructionSet, naddr, ASM_GET_ARM_ADDRESS_FOR_JUMP((uintptr_t)func));
		}
		else
			return;
		
		Trampolines_addr_start += 8;
	}

	void ARMHook::CPatch::TrampolinesRedirectJump(eInstructionSet sourceInstructionSet, uintptr_t addr, void* func, void** orig_func)
	{
		if (sourceInstructionSet == SET_THUMB)
			return TrampolinesRedirectCall(sourceInstructionSet, addr, func, orig_func, BW_THUMB32);
		else if (sourceInstructionSet == SET_ARM)
			return TrampolinesRedirectCall(sourceInstructionSet, addr, func, orig_func, B_ARM);
		else
			return;
	}
}

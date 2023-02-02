#include "Instruction.h"
#include "GlossHook.h"

namespace Inst
{
#ifdef __arm__
	
	bool IsThumb32(uintptr_t addr)
	{
		int code = ReadMemory<uint16_t>(addr, false) >> 11;
		return (code == 0x1D) || (code == 0x1E) || (code == 0x1F);
	}
	
	int CheckAbsoluteJump(uintptr_t addr) //check hook
	{
		int ret = -2;

		if (IS_ADDR_ALIGN_4(addr)) {
			if (ReadMemory<uint32_t>(addr) == _JUMP.T1 && GetThumb32InstType(addr) == LDR_PC_THUMB32)
				ret = 0;
			else if (ReadMemory<uint32_t>(addr - 4) == _JUMP.T1 && GetThumb32InstType(addr - 4) == LDR_PC_THUMB32)
				ret = -1;
			else if (ReadMemory<uint32_t>(addr + 4) == _JUMP.T1 && GetThumb32InstType(addr + 4) == LDR_PC_THUMB32)
				ret = 1;

			else if (ReadMemory<uint32_t>(addr) == _JUMP.A1 && GetArmInstType(addr) == LDR_PC_ARM)
				ret = 0;
			else if (ReadMemory<uint32_t>(addr - 4) == _JUMP.A1 && GetArmInstType(addr - 4) == LDR_PC_ARM)
				ret = -1;
			else if (ReadMemory<uint32_t>(addr + 4) == _JUMP.A1 && GetArmInstType(addr + 4) == LDR_PC_ARM)
				ret = 1;
		}
		else
		{
			if (ReadMemory<uint32_t>(addr + 2) == _JUMP.T1 && GetThumb32InstType(addr + 2) == LDR_PC_THUMB32)
				ret = 0;
		}
		return ret;
	}

	/********************************************************************THUMB********************************************************************************/

	void MakeThumb16NOP(uintptr_t addr, size_t size)
	{
		Unprotect(addr, size);
		for (int i = 0; i < size; i += 2) {
			*((uint16_t*)addr + i) = _NOP.T1;
		}
	}

	void MakeThumb32NOP(uintptr_t addr, size_t size) // NOP<c>.W
	{
		Unprotect(addr, size);
		for (int i = 0; i < size; i += 4) {
			*((uint32_t*)addr + i) = _NOP.T2;
		}
	}

	void MakeThumbRET(uintptr_t addr, uint8_t type)
	{
		WriteMemory<uint16_t>(addr, type == 1 ? _RET.T1 : _RET.T2);
	}

	void MakeThumb16B(uintptr_t addr, uintptr_t dest) //B
	{
		uintptr_t PC = GET_THUMB_PC(addr);
		uint16_t offset = (dest - PC) & 0x7FFFFF; //offset = dest - PC
		uint16_t hex = (offset & 0xFFF) >> 1 | 0xE000; //& 0xFFF go forward jump, clear sign bit

		WriteMemory<uint16_t>(addr, hex);
	}

	void MakeThumb16BCond(uintptr_t addr, uintptr_t dest, conds cond) //B<c>
	{
		uintptr_t PC = GET_THUMB_PC(addr);
		uint16_t offset = (dest - PC) & 0x7FFFFF; //offset = dest - PC   
		uint16_t code = 0xD000 | (static_cast<int>(cond) << 8);
		uint16_t hex = (offset & 0xFFF) >> 1 & 0xFF | code; //& 0xFFF go forward jump, clear sign bit

		WriteMemory<uint16_t>(addr, hex);
	}

	void MakeThumb32B(uintptr_t addr, uintptr_t dest) //B.W
	{
		uintptr_t PC = GET_THUMB_PC(addr);
		uint32_t offset = (dest - PC) & 0x7FFFFF; //offset = dest - PC
		uint16_t high = offset >> 12 | 0xF000;
		uint16_t low = (offset & 0xFFF) >> 1 | 0xB800; //& 0xFFF go forward jump, clear sign bit
		uint32_t hex = MAKE_THUMB32_HEX(low, high);

		WriteMemory<uint32_t>(addr, hex);
	}

	void MakeThumb32BCond(uintptr_t addr, uintptr_t dest, conds cond) //B<c>.W
	{
		int c = static_cast<int>(cond);
		uint16_t code1, code2;
		if (dest < addr)
		{
			code1 = 0xA800;
			code2 = 0xF43F | (c << 6);
		}
		else
		{
			code1 = 0x8000;
			code2 = 0xF000 | (c << 6);
		}
		uintptr_t PC = GET_THUMB_PC(addr);
		uint32_t offset = (dest - PC) & 0x7FFFFF; //offset = dest - PC
		uint16_t high = (offset & 0xFFF) >> 12 | code2;
		uint16_t low = (offset & 0xFFF) >> 1 | code1; //& 0xFFF go forward jump, clear sign bit
		uint32_t hex = MAKE_THUMB32_HEX(low, high);

		WriteMemory<uint32_t>(addr, hex);
	}

	void MakeThumbBL(uintptr_t addr, uintptr_t func)
	{
		uintptr_t PC = GET_THUMB_PC(addr);
		uint32_t offset = (func - PC) & 0x7FFFFF; //offset = func - PC
		uint16_t high = offset >> 12 | 0xF000;
		uint16_t low = (offset & 0xFFF) >> 1 | 0xF800; //& 0xFFF go forward jump, clear sign bit
		uint32_t hex = MAKE_THUMB32_HEX(low, high);

		WriteMemory<uint32_t>(addr, hex);
	}

	void MakeThumbBLX(uintptr_t addr, uintptr_t func)
	{
		uintptr_t PC = GET_THUMB_PC(addr);
		uint32_t offset = (func - PC) & 0x7FFFFF; //offset = func - PC
		uint16_t high = offset >> 12 | 0xF000;
		uint16_t low = (offset & 0xFFF) >> 1; //& 0xFFF go forward jump, clear sign bit
		if (low % 2 != 0)//align
			low++;
		uint32_t hex = MAKE_THUMB32_HEX((low | 0xE800), high);

		WriteMemory<uint32_t>(addr, hex);
	}

	void MakeThumbCB(uintptr_t addr, uintptr_t dest, uint8_t reg, bool is_cbnz) //CBZ CBNZ
	{
		uint16_t code;
		if (dest - addr > 0x40)
			code = is_cbnz ? 0xBB00 : 0xB300;
		else
			code = is_cbnz ? 0xB900 : 0xB100;

		uintptr_t PC = GET_THUMB_PC(addr);
		uint16_t offset = (dest - PC) & 0x7FFFFF; //offset = dest - PC
		uint16_t hex = (offset & 0xFFF) << 2 & 0xFF | reg | code;

		WriteMemory<uint16_t>(addr, hex);
	}

	int8_t MakeThumbAbsoluteJump(uintptr_t addr, uintptr_t dest)
	{
		if (IS_ADDR_ALIGN_4(addr))
		{
			//addr[0] LDR.W PC, [PC, #0]
			//addr[4] dest
			WriteMemory<uint32_t>(addr, _JUMP.T1);
			WriteMemory<uintptr_t>(addr + 4, dest);
			return 8;
		}
		else //align
		{
			//addr[0] NOP
			//addr[2] LDR.W PC, [PC, #0]
			//addr[6] dest
			MakeThumb16NOP(addr, 2);
			WriteMemory<uint32_t>(addr + 2, _JUMP.T1);
			WriteMemory<uintptr_t>(addr + 6, dest);
			return 10;
		}
	}

	uintptr_t GetThumb16BranchDestination(uintptr_t addr)
	{
		uintptr_t PC = GET_THUMB_PC(addr);
		uint16_t high = ReadMemory<uint16_t>(addr, false);
		uint32_t x, imm32 = NULL;

		switch (GetThumb16InstType(addr)) {
		case B_COND_THUMB16:
		{
			x = (high & 0xFF) << 1;
			int top_bit = x >> 8;
			imm32 = top_bit ? (x | (0xFFFFFFFF << 8)) : x;
			break;
		}
		case B_THUMB16:
		{
			x = (high & 0x7FF) << 1;
			int top_bit = x >> 11;
			imm32 = top_bit ? (x | (0xFFFFFFFF << 11)) : x;
			break;
		}
		default:
			return imm32;
		}
		return PC + imm32;
	}

	uintptr_t GetThumb32BranchDestination(uintptr_t addr)
	{
		uintptr_t PC = GET_THUMB_PC(addr);
		uint16_t high = ReadMemory<uint16_t>(addr, false);
		uint16_t low = ReadMemory<uint16_t>(addr + 2, false);
		uint32_t x, imm32 = NULL;
		uint32_t j1 = (low & 0x2000) >> 13;
		uint32_t j2 = (low & 0x800) >> 11;
		uint32_t s = (high & 0x400) >> 10;
		uint32_t i1 = !(j1 ^ s);
		uint32_t i2 = !(j2 ^ s);

		switch (GetThumb32InstType(addr)) {
		case B_COND_THUMB32:
		{
			x = (s << 20) | (j2 << 19) | (j1 << 18) | ((high & 0x3F) << 12) | ((low & 0x7FF) << 1);
			imm32 = s ? (x | (0xFFFFFFFF << 21)) : x;
			break;
		}
		case B_THUMB32:
		case BL_THUMB32:
		{
			x = (s << 24) | (i1 << 23) | (i2 << 22) | ((high & 0x3FF) << 12) | ((low & 0x7FF) << 1);
			imm32 = s ? (x | (0xFFFFFFFF << 25)) : x;
			break;
		}
		case BLX_THUMB32:
		{
			x = (s << 24) | (i1 << 23) | (i2 << 22) | ((high & 0x3FF) << 12) | ((low & 0x7FE) << 1);
			imm32 = s ? (x | (0xFFFFFFFF << 25)) : x;
			break;
		}
		default:
			return imm32;
		}
		return PC + imm32;
	}

	i_type GetThumb16CondInstType(uintptr_t addr)
	{
		if (GetThumb16InstType(addr) == B_COND_THUMB16) {
			uint16_t hex16 = ReadMemory<uint16_t>(addr, false);

			if ((hex16 & 0xFF00) == 0xD000)
				return BEQ_THUMB16;
			else if ((hex16 & 0xFF00) == 0xD100)
				return BNE_THUMB16;
			else if ((hex16 & 0xFF00) == 0xD200)
				return BCS_THUMB16;
			else if ((hex16 & 0xFF00) == 0xD300)
				return BCC_THUMB16;
			else if ((hex16 & 0xFF00) == 0xD400)
				return BMI_THUMB16;
			else if ((hex16 & 0xFF00) == 0xD500)
				return BPL_THUMB16;
			else if ((hex16 & 0xFF00) == 0xD600)
				return BVS_THUMB16;
			else if ((hex16 & 0xFF00) == 0xD700)
				return BVC_THUMB16;
			else if ((hex16 & 0xFF00) == 0xD800)
				return BHI_THUMB16;
			else if ((hex16 & 0xFF00) == 0xD900)
				return BLS_THUMB16;
			else if ((hex16 & 0xFF00) == 0xDA00)
				return BGE_THUMB16;
			else if ((hex16 & 0xFF00) == 0xDB00)
				return BLT_THUMB16;
			else if ((hex16 & 0xFF00) == 0xDC00)
				return BGT_THUMB16;
			else if ((hex16 & 0xFF00) == 0xDD00)
				return BLE_THUMB16;
			else
				return B_COND_THUMB16;
		}
		else
			return UNDEFINE;
	}

	i_type GetThumb32CondInstType(uintptr_t addr)
	{
		if (GetThumb32InstType(addr) == B_COND_THUMB32) {
			uint16_t high = ReadMemory<uint16_t>(addr, false);
			uint16_t low = ReadMemory<uint16_t>(addr + 2, false);
			uint32_t hex32 = MAKE_THUMB32_HEX(high, low);

			if ((hex32 & 0xFBA0D000) == 0xF0008000)
				return BEQ_THUMB32;
			else if ((hex32 & 0xFBA0D000) == 0xF0408000)
				return BNE_THUMB32;
			else if ((hex32 & 0xFBA0D000) == 0xF0808000)
				return BCS_THUMB32;
			else if ((hex32 & 0xFBA0D000) == 0xF0C08000)
				return BCC_THUMB32;
			else if ((hex32 & 0xFBA0D000) == 0xF1008000)
				return BMI_THUMB32;
			else if ((hex32 & 0xFBA0D000) == 0xF1408000)
				return BPL_THUMB32;
			else if ((hex32 & 0xFBA0D000) == 0xF1808000)
				return BVS_THUMB32;
			else if ((hex32 & 0xFBA0D000) == 0xF1C08000)
				return BVC_THUMB32;
			else if ((hex32 & 0xFBA0D000) == 0xF2008000)
				return BHI_THUMB32;
			else if ((hex32 & 0xFBA0D000) == 0xF2408000)
				return BLS_THUMB32;
			else if ((hex32 & 0xFBA0D000) == 0xF2808000)
				return BGE_THUMB32;
			else if ((hex32 & 0xFBA0D000) == 0xF2C08000)
				return BLT_THUMB32;
			else if ((hex32 & 0xFBA0D000) == 0xF3008000)
				return BGT_THUMB32;
			else if ((hex32 & 0xFBA0D000) == 0xF3408000)
				return BLE_THUMB32;
			else
				return B_COND_THUMB32;
		}
		else
			return UNDEFINE;
	}

	i_type GetThumb16InstType(uintptr_t addr)
	{
		uint16_t hex16 = ReadMemory<uint16_t>(addr, false);

		if (((hex16 & 0xFF00) == 0xBF00) && ((hex16 & 0x000F) != 0x0000) && ((hex16 & 0x00F0) != 0x00F0))
			return IT_THUMB16;
		else if (((hex16 & 0xF000) == 0xD000) && ((hex16 & 0x0F00) != 0x0F00) && ((hex16 & 0x0F00) != 0x0E00))
			return B_COND_THUMB16;
		else if ((hex16 & 0xF800) == 0xE000)
			return B_THUMB16;
		else if ((hex16 & 0xFFF8) == 0x4778) /* ((hex16 & 0xFF00u) == 0x4700) */
			return BX_PC_THUMB16;
		else if (((hex16 & 0xFF78) == 0x4478) && ((hex16 & 0x0087) != 0x0085))
			return ADD_PC_THUMB16;
		else if ((hex16 & 0xFF78) == 0x4678) /* ((hex16 & 0xFF00u) == 0x4600) */
			return MOV_PC_THUMB16;
		else if ((hex16 & 0xF800) == 0xA000)
			return ADR_THUMB16;
		else if ((hex16 & 0xF800) == 0x4800)
			return LDR_THUMB16;
		/*
		else if (((hex16 & 0xF800) == 0x6800) || ((hex16 & 0xF800) == 0x5800) || ((hex16 & 0xF800) == 0x9800))
			return LDR_REG_THUMB16;
		*/
		else if ((hex16 & 0xF500) == 0xB100) {
			if ((hex16 & 0xFD00) == 0xB100)
				return CBZ_THUMB16;
			else if ((hex16 & 0xFD00) == 0xB900)
				return CBNZ_THUMB16;
			else
				return CB_THUMB16;
		}
		/*
		else if (((hex16 & 0xF800) == 0x1800) || ((hex16 & 0xF800) == 0x3000))
			return ADDS_THUMB16;
		else if ((hex16 & 0xF800) == 0x2000)
			return MOVS_THUMB16;
		else if (((hex16 & 0xF800) == 0xA800) || ((hex16 & 0xF800) == 0xB000))
			return ADD_REG_THUMB16;
		*/
		else
			return UNDEFINE;
	}

	i_type GetThumb32InstType(uintptr_t addr)
	{
		uint16_t high = ReadMemory<uint16_t>(addr, false);
		uint16_t low = ReadMemory<uint16_t>(addr + 2, false);
		uint32_t hex32 = MAKE_THUMB32_HEX(high, low);

		if (((hex32 & 0xF800D000) == 0xF0008000) && ((hex32 & 0x03800000) != 0x03800000))
			return B_COND_THUMB32;
		else if ((hex32 & 0xF800D000) == 0xF0009000)
			return B_THUMB32;
		else if ((hex32 & 0xF800D000) == 0xF000D000)
			return BL_THUMB32;
		else if ((hex32 & 0xF800D000) == 0xF000C000)
			return BLX_THUMB32;
		else if ((hex32 & 0xFBFF8000) == 0xF2AF0000)
			return ADR_BEFORE_THUMB32;
		else if ((hex32 & 0xFBFF8000) == 0xF20F0000)
			return ADR_AFTER_THUMB32;
		else if ((hex32 & 0xFF7F0000) == 0xF85F0000)
			return ((hex32 & 0x0000F000) == 0x0000F000) ? LDR_PC_THUMB32 : LDR_THUMB32;
		else if (((hex32 & 0xFF7F0000) == 0xF81F0000) && ((hex32 & 0xF000) != 0xF000))
			return LDRB_THUMB32;
		else if ((hex32 & 0xFF7F0000) == 0xE95F0000)
			return LDRD_THUMB32;
		else if (((hex32 & 0xFF7F0000) == 0xF83F0000) && ((hex32 & 0xF000) != 0xF000))
			return LDRH_THUMB32;
		else if (((hex32 & 0xFF7F0000) == 0xF91F0000) && ((hex32 & 0xF000) != 0xF000))
			return LDRSB_THUMB32;
		else if (((hex32 & 0xFF7F0000) == 0xF93F0000) && ((hex32 & 0xF000) != 0xF000))
			return LDRSH_THUMB32;
		else if ((hex32 & 0xFF7FF000) == 0xF81FF000)
			return PLD_THUMB32;
		else if ((hex32 & 0xFF7FF000) == 0xF91FF000)
			return PLI_THUMB32;
		else if ((hex32 & 0xFFF0FFF0) == 0xE8D0F000)
			return TBB_THUMB32;
		else if ((hex32 & 0xFFF0FFF0) == 0xE8D0F010)
			return TBH_THUMB32;
		else if ((hex32 & 0xFF3F0C00) == 0xED1F0800)
			return VLDR_THUMB32;
		else
			return UNDEFINE;
	}

	/********************************************************************ARM**********************************************************************************/

	void MakeArmNOP(uintptr_t addr, size_t size)
	{
		Unprotect(addr, size);
		for (int i = 0; i < size; i += 4) {
			*((uint32_t*)addr + i) = _NOP.A1;
		}
	}

	void MakeArmRET(uintptr_t addr, uint8_t type)
	{
		WriteMemory<uint32_t>(addr, type == 1 ? _RET.A1 : _RET.A2);
	}

	void MakeArmB(uintptr_t addr, uintptr_t dest) //B
	{
		uintptr_t PC = GET_ARM_PC(addr);
		uint32_t hex = ((dest - PC) / 4) & 0xFFFFFF | 0xEA000000; //offset = dest - PC   (/ 4 = align)

		WriteMemory<uint32_t>(addr, hex);
	}

	void MakeArmBCond(uintptr_t addr, uintptr_t dest, conds cond)
	{
		uintptr_t PC = GET_ARM_PC(addr);
		int32_t code = 0x0A000000 | (static_cast<int>(cond) << 28);
		uint32_t hex = ((dest - PC) / 4) & 0xFFFFFF | code; //offset = dest - PC   (/ 4 = align)

		WriteMemory<uint32_t>(addr, hex);
	}

	void MakeArmBL(uintptr_t addr, uintptr_t func)
	{
		uintptr_t PC = GET_ARM_PC(addr);
		uint32_t hex = ((func - PC) / 4) & 0xFFFFFF | 0xEB000000; //offset = func - PC  (/ 4 = align)

		WriteMemory<uint32_t>(addr, hex);
	}

	void MakeArmBLX(uintptr_t addr, uintptr_t func)
	{
		uintptr_t PC = GET_ARM_PC(addr);
		uint32_t code = (func - PC) % 4 == 0 ? 0xFA000000 : 0xFB000000; //align
		uint32_t hex = ((func - PC) / 4) & 0xFFFFFF | code; //offset = func - PC  (/ 4 = align)

		WriteMemory<uint32_t>(addr, hex);
	}

	int8_t MakeArmAbsoluteJump(uintptr_t addr, uintptr_t dest)
	{
		//addr[0] LDR PC, [PC, #-4]
		//addr[4] dest
		WriteMemory<uint32_t>(addr, _JUMP.A1);
		WriteMemory<uintptr_t>(addr + 4, dest);
		return 4;
	}

	uintptr_t GetArmBranchDestination(uintptr_t addr)
	{
		uintptr_t PC = GET_ARM_PC(addr);
		uint32_t hex = ReadMemory<uint32_t>(addr, false);
		uint32_t x, imm32 = NULL;

		switch (GetArmInstType(addr))
		{
		case B_ARM:
		case BL_ARM:
		{
			x = (hex & 0xFFFFFF) << 2;
			break;
		}

		case BLX_ARM:
		{
			x = ((hex & 0xFFFFFF) << 2) | ((hex & 0x1000000) >> 23);
			break;

		}
		default:
			return imm32;
		}

		int top_bit = x >> 25;
		imm32 = top_bit ? (x | (0xFFFFFFFF << 26)) : x;
		return PC + imm32;
	}

	i_type GetArmCondInstType(uintptr_t addr)
	{
		i_type type = GetArmInstType(addr);
		if (type == B_ARM) {
			uint32_t hex32 = ReadMemory<uint32_t>(addr, false);

			if ((hex32 & 0xFE000000) == 0x0A000000)
				return BEQ_ARM;
			else if ((hex32 & 0xFE000000) == 0x1A000000)
				return BNE_ARM;
			else if ((hex32 & 0xFE000000) == 0x2A000000)
				return BCS_ARM;
			else if ((hex32 & 0xFE000000) == 0x3A000000)
				return BCC_ARM;
			else if ((hex32 & 0xFE000000) == 0x4A000000)
				return BMI_ARM;
			else if ((hex32 & 0xFE000000) == 0x5A000000)
				return BPL_ARM;
			else if ((hex32 & 0xFE000000) == 0x6A000000)
				return BVS_ARM;
			else if ((hex32 & 0xFE000000) == 0x7A000000)
				return BVC_ARM;
			else if ((hex32 & 0xFE000000) == 0x8A000000)
				return BHI_ARM;
			else if ((hex32 & 0xFE000000) == 0x9A000000)
				return BLS_ARM;
			else if ((hex32 & 0xFE000000) == 0xAA000000)
				return BGE_ARM;
			else if ((hex32 & 0xFE000000) == 0xBA000000)
				return BLT_ARM;
			else if ((hex32 & 0xFE000000) == 0xCA000000)
				return BGT_ARM;
			else if ((hex32 & 0xFE000000) == 0xDA000000)
				return BLE_ARM;
			else
				return B_ARM; //B no_cond
		}
		else
			return UNDEFINE;
	}

	i_type GetArmInstType(uintptr_t addr)
	{
		uint32_t hex32 = ReadMemory<uint32_t>(addr, false);

		if (((hex32 & 0x0F000000) == 0x0A000000) && ((hex32 & 0xFE000000) == 0xEA000000) && ((hex32 & 0xF0000000) != 0xF0000000))
			return B_ARM;
		else if ((((hex32 & 0x0FFFFFFF) == 0x012FFF1F) && ((hex32 & 0x0FF000FF) == 0x0120001F)) && ((hex32 & 0xF0000000) != 0xF0000000))
			return BX_PC_ARM;
		else if (((hex32 & 0x0F000000) == 0x0B000000) && ((hex32 & 0xF0000000) != 0xF0000000))
			return BL_ARM;
		else if ((hex32 & 0xFE000000) == 0xFA000000)
			return BLX_ARM;
		else if (((hex32 & 0x0FE00010) == 0x00800000) && ((hex32 & 0xF0000000) != 0xF0000000) && ((hex32 & 0x0010F000) != 0x0010F000) &&
			((hex32 & 0x000F0000) != 0x000D0000) && (((hex32 & 0x000F0000) == 0x000F0000) || ((hex32 & 0x0000000F) == 0x0000000F)))
			return ((hex32 & 0x0000F000) == 0x0000F000) ? ADD_PC_ARM : ADD_ARM;
		else if (((hex32 & 0x0FE00010) == 0x00400000) && ((hex32 & 0xF0000000) != 0xF0000000) &&
			((hex32 & 0x0010F000) != 0x0010F000) && ((hex32 & 0x000F0000) != 0x000D0000) &&
			(((hex32 & 0x000F0000) == 0x000F0000) || ((hex32 & 0x0000000F) == 0x0000000F)))
			return ((hex32 & 0x0000F000) == 0x0000F000) ? SUB_PC_ARM : SUB_ARM;
		else if (((hex32 & 0x0FFF0000) == 0x028F0000) && ((hex32 & 0xF0000000) != 0xF0000000))
			return ADR_AFTER_ARM;
		else if (((hex32 & 0x0FFF0000) == 0x024F0000) && ((hex32 & 0xF0000000) != 0xF0000000))
			return ADR_BEFORE_ARM;
		else if (((hex32 & 0x0FEF001F) == 0x01A0000F) && ((hex32 & 0xF0000000) != 0xF0000000) &&
			((hex32 & 0x0010F000) != 0x0010F000) && (!(((hex32 & 0x0000F000) == 0x0000F000) && ((hex32 & 0x00000FF0) != 0x00000000))))
			return ((hex32 & 0x0000F000) == 0x0000F000) ? MOV_PC_ARM : MOV_ARM;
		else if (((hex32 & 0x0F7F0000) == 0x051F0000) && ((hex32 & 0xF0000000) != 0xF0000000))
			return ((hex32 & 0x0000F000) == 0x0000F000) ? LDR_PC_ARM : LDR_ARM;
		else if (((hex32 & 0x0F7F0000) == 0x055F0000) && ((hex32 & 0xF0000000) != 0xF0000000))
			return LDRB_ARM;
		else if (((hex32 & 0x0F7F00F0) == 0x014F00D0) && ((hex32 & 0xF0000000) != 0xF0000000))
			return LDRD_ARM;
		else if (((hex32 & 0x0F7F00F0) == 0x015F00B0) && ((hex32 & 0xF0000000) != 0xF0000000))
			return LDRH_ARM;
		else if (((hex32 & 0x0F7F00F0) == 0x015F00D0) && ((hex32 & 0xF0000000) != 0xF0000000))
			return LDRSB_ARM;
		else if (((hex32 & 0x0F7F00F0) == 0x015F00F0) && ((hex32 & 0xF0000000) != 0xF0000000))
			return LDRSH_ARM;
		else if (((hex32 & 0x0E5F0010) == 0x061F0000) && ((hex32 & 0xF0000000) != 0xF0000000) && ((hex32 & 0x01200000) != 0x00200000))
			return ((hex32 & 0x0000F000) == 0x0000F000) ? LDR_PC_REG_ARM : LDR_REG_ARM;
		else if (((hex32 & 0x0E5F0010) == 0x065F0000) && ((hex32 & 0xF0000000) != 0xF0000000) && ((hex32 & 0x01200000) != 0x00200000))
			return LDRB_REG_ARM;
		else if (((hex32 & 0x0E5F0FF0) == 0x000F00D0) && ((hex32 & 0xF0000000) != 0xF0000000) && ((hex32 & 0x01200000) != 0x00200000))
			return LDRD_REG_ARM;
		else if (((hex32 & 0x0E5F0FF0) == 0x001F00B0) && ((hex32 & 0xF0000000) != 0xF0000000) && ((hex32 & 0x01200000) != 0x00200000))
			return LDRH_REG_ARM;
		else if (((hex32 & 0x0E5F0FF0) == 0x001F00D0) && ((hex32 & 0xF0000000) != 0xF0000000) && ((hex32 & 0x01200000) != 0x00200000))
			return LDRSB_REG_ARM;
		else if (((hex32 & 0x0E5F0FF0) == 0x001F00F0) && ((hex32 & 0xF0000000) != 0xF0000000) && ((hex32 & 0x01200000) != 0x00200000))
			return LDRSH_REG_ARM;
		else
			return UNDEFINE;
	}

#elif __aarch64__

	void MakeArm64NOP(uintptr_t addr, size_t size)
	{
		Unprotect(addr, size);
		for (int i = 0; i < size; i += 4) {
			*((uint32_t*)addr + i) = _NOP.A64;
		}
	}

	void MakeArm64RET(uintptr_t addr, uint8_t type)
	{
		WriteMemory<uint32_t>(addr, type == 1 ? _RET.A64_A1 : _RET.A64_A2);
	}

	void MakeArm64B(uintptr_t addr, uintptr_t dest) //B
	{
		uintptr_t PC = GET_ARM_PC(addr);
		uint32_t code = ((dest - PC) & 0x800000) ? 0x17000000 : 0x14000000;
		uint32_t hex = ((dest - PC) / 4) & 0xFFFFFF | code; // (/ 4 = align)
		//uint32_t hex = ((dest - PC) & 0xFFFFFFF) >> 2 | 0x14000000;

		WriteMemory<uint32_t>(addr, hex);
	}

	void MakeArm64BCond(uintptr_t addr, uintptr_t dest, conds cond)
	{
		uintptr_t PC = GET_ARM_PC(addr);
		uint32_t hex = ((dest - PC) / 4) << 5 & 0xFFFFE0 | 0x54000000 | static_cast<int>(cond); // (/ 4 = align)

		WriteMemory<uint32_t>(addr, hex);
	}
	
	void MakeArm64BL(uintptr_t addr, uintptr_t func)
	{
		uintptr_t PC = GET_ARM_PC(addr);
		uint32_t code = ((func - PC) & 0x800000) ? 0x97000000 : 0x94000000;
		uint32_t hex = ((func - PC) / 4) & 0xFFFFFF | code; // (/ 4 = align)
		//uint32_t hex = ((func - PC) & 0xFFFFFFF) >> 2 | 0x94000000;

		WriteMemory<uint32_t>(addr, hex);
	}
	
	void MakeArm64CB(uintptr_t addr, uintptr_t dest, uint8_t reg, bool is_cbnz, bool is64reg)
	{
		uintptr_t PC = GET_ARM_PC(addr);
		uint32_t code = is_cbnz ? (is64reg ? 0xB5000000 : 0x35000000) : (is64reg ? 0xB4000000 : 0x34000000);
		uint32_t hex = ((dest - PC) / 4) << 5 & 0xFFFFE0 | code | reg;

		WriteMemory<uint32_t>(addr, hex);
	}

	int8_t MakeArm64AbsoluteJump(uintptr_t addr, uintptr_t dest, REG::ARM64 reg)
	{
		using REG::ARM64;
		if (reg == ARM64::X17) {
			//addr[0] LDR X17, #8
			//addr[4] BR X17
			WriteMemory<uint32_t>(addr, jump_hex::A64_A1[0]);
			WriteMemory<uint32_t>(addr + 4, jump_hex::A64_A1[1]);
		}
		else {
			//addr[0] LDR REG, #8
			//addr[4] BR REG
			WriteMemory<uint32_t>(addr, jump_hex::A64_A1[2] | reg);
			WriteMemory<uint32_t>(addr + 4, jump_hex::A64_A1[3] | (reg << 5));
		}
		//addr[8] dest
		WriteMemory<uint64_t>(addr + 8, dest);
		return 16;
	}

	int8_t MakeArm64AbsoluteJump32(uintptr_t addr, uintptr_t dest, REG::ARM64 reg)
	{
		//addr[0] ADRP X17, dest (ADRP reg, dest)
		//addr[4] BR X17 (BR reg)
		intptr_t imm = PAGE_START(dest, PAGE_SIZE) - PAGE_START(addr, PAGE_SIZE);
		uintptr_t immlo = (imm >> 12) & 0x3;
		uintptr_t immhi = (imm >> 14) & 0x7FFFFul;
		WriteMemory<uint32_t>(addr, jump_hex::A64_A2[0] | reg | (immlo << 29) | (immhi << 5));
		WriteMemory<uint32_t>(addr + 4, jump_hex::A64_A2[1] | (reg << 5));
		return 8;
	}
	
	uintptr_t GetArm64BranchDestination(uintptr_t addr)
	{
		uintptr_t PC = GET_ARM_PC(addr);
		uint32_t hex = ReadMemory<uint32_t>(addr);
		uint64_t x, imm64 = NULL;

		switch (GetArm64InstructionType(addr))
		{
		case B_COND_ARM64:
		{
			uint32_t imm19 = (hex & 0xFFFFE0) >> 5;
			imm64 = PC + imm19 * 4;
			if ((imm19 >> 18) == 1)
				imm64 = PC - (0x7FFFF - imm19 + 1) * 4;
			/*
			uint64_t imm19 = (hex << 8) >> 13;
			x = imm19 << 2;
			imm64 = ((x << 43) >> 63) > 0 ? (x | (0xFFFFFFFFFFFFFFFF << 21)) : x;
			*/
			break;
		}
		case B_ARM64:
		case BL_ARM64:
		{
			uint32_t imm26 = hex & 0x3FFFFFF;
			imm64 = PC + imm26 * 4;
			if ((imm26 >> 25) == 1)
				imm64 = PC - (0x3FFFFFF - imm26 + 1) * 4;
			/*
			uint64_t imm26 = (hex << 6) >> 6;
			x = imm26 << 2;
			imm64 = ((x << 36) >> 63) > 0 ? (x | (0xFFFFFFFFFFFFFFFF << 28)) : x;
			*/
			break;
		}
		default:
			break;
		}
		return imm64;
	}
	
	i_type GetArm64CondInstType(uintptr_t addr)
	{
		i_type type = GetArm64InstructionType(addr);
		if (type == B_COND_ARM64) {
			uint32_t hex32 = ReadMemory<uint32_t>(addr, false);

			if ((hex32 & 0xFF00001F) == 0x54000000)
				return BEQ_ARM64;
			else if ((hex32 & 0xFF00001F) == 0x54000001)
				return BNE_ARM64;
			else if ((hex32 & 0xFF00001F) == 0x54000002)
				return BCS_ARM64;
			else if ((hex32 & 0xFF00001F) == 0x54000003)
				return BCC_ARM64;
			else if ((hex32 & 0xFF00001F) == 0x54000004)
				return BMI_ARM64;
			else if ((hex32 & 0xFF00001F) == 0x54000005)
				return BPL_ARM64;
			else if ((hex32 & 0xFF00001F) == 0x54000006)
				return BVS_ARM64;
			else if ((hex32 & 0xFF00001F) == 0x54000007)
				return BVC_ARM64;
			else if ((hex32 & 0xFF00001F) == 0x54000008)
				return BHI_ARM64;
			else if ((hex32 & 0xFF00001F) == 0x54000009)
				return BLS_ARM64;
			else if ((hex32 & 0xFF00001F) == 0x5400000A)
				return BGE_ARM64;
			else if ((hex32 & 0xFF00001F) == 0x5400000B)
				return BLT_ARM64;
			else if ((hex32 & 0xFF00001F) == 0x5400000C)
				return BGT_ARM64;
			else if ((hex32 & 0xFF00001F) == 0x5400000D)
				return BLE_ARM64;
			else
				return B_COND_ARM64;
		}
		else
			return UNDEFINE;
	}
	
	i_type GetArm64InstructionType(uintptr_t addr)
	{
		uint32_t hex32 = ReadMemory<uint32_t>(addr, false);

		if ((hex32 & 0xFC000000) == 0x14000000)
			return B_ARM64;
		else if ((hex32 & 0xFF000010) == 0x54000000)
			return B_COND_ARM64;
		else if ((hex32 & 0xFC000000) == 0x94000000)
			return BL_ARM64;
		else if ((hex32 & 0x9F000000) == 0x10000000)
			return ADR_ARM64;
		else if ((hex32 & 0x9F000000) == 0x90000000)
			return ADRP_ARM64;
		else if ((hex32 & 0xFF000000) == 0x58000000)
			return LDR_ARM64;
		else if ((hex32 & 0xFF000000) == 0x18000000)
			return LDR_ARM64_32;
		else if ((hex32 & 0xFF000000) == 0x98000000)
			return LDRSW_ARM64;
		else if ((hex32 & 0xFF000000) == 0x5C000000)
			return LDR_SIMD_ARM64;
		else if ((hex32 & 0xFF000000) == 0x1C000000)
			return LDR_SIMD_ARM64_32;
		else if ((hex32 & 0xFF000000) == 0x9C000000)
			return LDR_SIMD_ARM64_128;
		else if ((hex32 & 0xFF000000) == 0xD8000000)
			return PRFM_ARM64;
		else if ((hex32 & 0x7F000000) == 0x35000000)
			return CBNZ_ARM64;
		else if ((hex32 & 0x7F000000) == 0x34000000)
			return CBZ_ARM64;
		else if ((hex32 & 0x7F000000) == 0x37000000)
			return TBNZ_ARM64;
		else if ((hex32 & 0x7F000000) == 0x36000000)
			return TBZ_ARM64;
		else
			return UNDEFINE;
	}


#endif // __arm__

	
}


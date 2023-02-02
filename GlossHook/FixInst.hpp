#pragma once
#include "GlossHook.h"
#include "Instruction.h"

namespace Inst
{
	typedef struct
	{
		i_set inst_mode;
		uintptr_t start_addr;
		uintptr_t end_addr;
		uint8_t fix_inst_len[13];

		union un_addr
		{
			uint16_t* thumb;
			uint32_t* arm;
		} buf_addr;

	} fix_inst_info;

	static uint32_t ror(uint32_t val, uint32_t n, uint32_t shift)
	{
		uint32_t m = shift % n;
		return (val >> m) | (val << (n - m));
	}

	static uint32_t arm_expand_imm(uint32_t opcode)
	{
		uint32_t imm = GET_BITS_32(opcode, 7, 0);
		uint32_t amt = 2 * GET_BITS_32(opcode, 11, 8);
		return amt == 0 ? imm : ror(imm, 32, amt);
	}

	static bool IsAddrInBackup(uintptr_t addr, fix_inst_info* fix_info)
	{
		if (TEST_BIT0(addr)) addr = CLEAR_BIT0(addr);
		return (addr >= fix_info->start_addr && addr < fix_info->end_addr);
	}

	static uintptr_t FixBackupToBackup(uintptr_t addr, fix_inst_info* fix_info)
	{
		bool is_thumb = TEST_BIT0(addr);
		if (is_thumb) addr = CLEAR_BIT0(addr);

		if (addr >= fix_info->start_addr && addr < fix_info->end_addr)
		{
			uintptr_t cursor_addr = fix_info->start_addr;

			if (fix_info->inst_mode == $THUMB) {
				int cnt = (addr - fix_info->start_addr) / 2;
				size_t offset = 0;
				for (size_t i = 0; i < cnt; i++) {
					if (cursor_addr >= addr) break;
					cursor_addr += 2;
					offset += fix_info->fix_inst_len[i];
				}
				uintptr_t fix_addr = (uintptr_t)fix_info->buf_addr.thumb + offset;
				if (is_thumb) fix_addr = SET_BIT0(fix_addr);
				return fix_addr;
			}
			else {
				int cnt = (addr - fix_info->start_addr) / 4;
				size_t offset = 0;
				for (size_t i = 0; i < cnt; i++) {
					if (cursor_addr >= addr) break;
					cursor_addr += 4;
					offset += fix_info->fix_inst_len[i];
				}
				uintptr_t fix_addr = (uintptr_t)fix_info->buf_addr.arm + offset;
				if (is_thumb) fix_addr = SET_BIT0(fix_addr);
				return fix_addr;
			}
		}

		if (is_thumb) addr = SET_BIT0(addr);
		return addr;
	}

	static size_t GetThumb16FixInstLen(i_type type)
	{
		switch (type)
		{
		case IT_THUMB16: return 0;
		case B_COND_THUMB16: return 12;
		case B_THUMB16: return 8;
		case BX_PC_THUMB16: return 8;
		case ADD_PC_THUMB16: return 16;
		case MOV_PC_THUMB16: return 12;
		case ADR_THUMB16: return 8;
		case LDR_THUMB16: return 12;
		case CBZ_THUMB16: return 12;
		case CBNZ_THUMB16: return 12;
		case UNDEFINE: return 4;
		}
	}
	
	static size_t GetThumb32FixInstLen(i_type type)
	{
		switch (type)
		{
		case B_COND_THUMB32: return 12;
		case B_THUMB32: return 8;
		case BL_THUMB32: return 12;
		case BLX_THUMB32: return 12;
		case ADR_BEFORE_THUMB32: return 12;
		case ADR_AFTER_THUMB32: return 12;
		case LDR_THUMB32: return 16;
		case LDR_PC_THUMB32: return 24;
		case LDRB_THUMB32: return 16;
		case LDRD_THUMB32: return 16;
		case LDRH_THUMB32: return 16;
		case LDRSB_THUMB32: return 16;
		case LDRSH_THUMB32: return 16;
		case PLD_THUMB32: return 20;
		case PLI_THUMB32: return 20;
		case TBB_THUMB32: return 32;
		case TBH_THUMB32: return 32;
		case VLDR_THUMB32: return 24;
		case UNDEFINE: return 4;
		}
	}

	static size_t GetArmFixInstLen(i_type type)
	{
		switch (type)
		{
		case B_ARM: return 12;
		case BX_PC_ARM: return 12;
		case BL_ARM: return 16;
		case BLX_ARM: return 16;


		case ADD_ARM: return 32;
		case ADD_PC_ARM: return 32;
		case SUB_ARM: return 32;
		case SUB_PC_ARM: return 32;

		case ADR_AFTER_ARM: return 12;
		case ADR_BEFORE_ARM: return 12;

		case MOV_ARM: return 32;
		case MOV_PC_ARM: return 12;

		case LDR_ARM: return 24;
		case LDR_PC_ARM: return 36;
		case LDRB_ARM: return 24;
		case LDRD_ARM: return 24;
		case LDRH_ARM: return 24;
		case LDRSB_ARM: return 24;
		case LDRSH_ARM: return 24;
		
		case LDR_REG_ARM: return 32;
		case LDR_PC_REG_ARM: return 36;
		case LDRB_REG_ARM: return 32;
		case LDRD_REG_ARM: return 32;
		case LDRH_REG_ARM: return 32;
		case LDRSB_REG_ARM: return 32;
		case LDRSH_REG_ARM: return 32;

		case UNDEFINE: return 4;
		}
	}

	static size_t FixThumb16_B(uint16_t* buf, uint16_t inst, uintptr_t pc, i_type type, fix_inst_info* fix_info)
	{
		uint32_t addr;
		if (type == B_COND_THUMB16) {
			uint32_t imm8 = GET_BITS_16(inst, 7, 0);
			addr = pc + SIGN_EXTEND_32(imm8 << 1u, 9u);
			addr = SET_BIT0(addr);  // thumb -> thumb
		}
		else if (type == B_THUMB16) {
			uint32_t imm11 = GET_BITS_16(inst, 10, 0);
			addr = pc + SIGN_EXTEND_32(imm11 << 1u, 12u);
			addr = SET_BIT0(addr);  // thumb -> thumb
		}
		else {
			// type == BX_PC_THUMB16
			addr = pc;  // thumb -> arm
		}
		addr = FixBackupToBackup(addr, fix_info);
		size_t idx = 0;
		if (type == B_COND_THUMB16) {
			buf[idx++] = inst & 0xFF00u;  // B<c> #0
			buf[idx++] = 0xE003;          // B PC, #6
		}
		buf[idx++] = 0xF8DF;  // LDR.W PC, [PC]
		buf[idx++] = 0xF000;  // ...
		buf[idx++] = addr & 0xFFFFu;
		buf[idx++] = addr >> 16u;
		return idx * 2;  // 8 or 12
	}

	static size_t FixThumb16_ADD(uint16_t* buf, uint16_t inst, uintptr_t pc)
	{
		// ADD<c> <Rdn>, PC
		uint16_t dn = GET_BIT_16(inst, 7);
		uint16_t rdn = GET_BITS_16(inst, 2, 0);
		uint16_t rd = (uint16_t)(dn << 3u) | rdn;
		uint16_t rx = (rd == 0) ? 1 : 0;  // r0 - r1

		buf[0] = (uint16_t)(0xB400u | (1u << rx));         // PUSH {Rx}
		buf[1] = 0x4802u | (uint16_t)(rx << 8u);           // LDR Rx, [PC, #8]
		buf[2] = (inst & 0xFF87u) | (uint16_t)(rx << 3u);  // ADD Rd, Rx
		buf[3] = (uint16_t)(0xBC00u | (1u << rx));         // POP {Rx}
		buf[4] = 0xE002;                                   // B #4
		buf[5] = 0xBF00;
		buf[6] = pc & 0xFFFFu;
		buf[7] = pc >> 16u;
		return 16;
	}

	static size_t FixThumb16_MOV(uint16_t* buf, uint16_t inst, uintptr_t pc)
	{
		// MOV<c> <Rd>, PC
		uint16_t D = GET_BIT_16(inst, 7);
		uint16_t rd = GET_BITS_16(inst, 2, 0);
		uint16_t d = (uint16_t)(D << 3u) | rd;  // r0 - r15

		buf[0] = 0xF8DF;                     // LDR.W Rd, [PC, #4]
		buf[1] = (uint16_t)(d << 12u) + 4u;  // ...
		buf[2] = 0xE002;                     // B #4
		buf[3] = 0xBF00;                     // NOP
		buf[4] = pc & 0xFFFFu;
		buf[5] = pc >> 16u;
		return 12;
	}

	static size_t FixThumb16_ADR(uint16_t* buf, uint16_t inst, uintptr_t pc, fix_inst_info* fix_info)
	{
		uint16_t rd = GET_BITS_16(inst, 10, 8);  // r0 - r7
		uint16_t imm8 = GET_BITS_16(inst, 7, 0);
		uint32_t addr = PC_ALIGN_4(pc) + (uint32_t)(imm8 << 2u);
		if (IsAddrInBackup(addr, fix_info)) return 0;

		buf[0] = 0x4800u | (uint16_t)(rd << 8u);  // LDR Rd, [PC]
		buf[1] = 0xE001;                          // B #2
		buf[2] = addr & 0xFFFFu;
		buf[3] = addr >> 16u;
		return 8;
	}

	static size_t FixThumb16_LDR(uint16_t* buf, uint16_t inst, uintptr_t pc, fix_inst_info* fix_info)
	{
		uint16_t rt = GET_BITS_16(inst, 10, 8);  // r0 - r7
		uint16_t imm8 = GET_BITS_16(inst, 7, 0);
		uint32_t addr = PC_ALIGN_4(pc) + (uint32_t)(imm8 << 2u);
		if (IsAddrInBackup(addr, fix_info)) return 0;

		buf[0] = 0x4800u | (uint16_t)(rt << 8u);  // LDR Rt, [PC]
		buf[1] = 0xE001;                          // B #2
		buf[2] = addr & 0xFFFFu;
		buf[3] = addr >> 16u;
		buf[4] = 0x6800u | (uint16_t)(rt << 3u) | rt;  // LDR Rt, [Rt]
		buf[5] = 0xBF00;                               // NOP
		return 12;
	}

	static size_t FixThumb16_CB(uint16_t* buf, uint16_t inst, uintptr_t pc, fix_inst_info* fix_info)
	{
		uint16_t i = GET_BIT_16(inst, 9);
		uint16_t imm5 = GET_BITS_16(inst, 7, 3);
		uint32_t imm32 = (uint32_t)(i << 6u) | (uint32_t)(imm5 << 1u);
		uint32_t addr = SET_BIT0(pc + imm32);  // thumb -> thumb
		addr = FixBackupToBackup(addr, fix_info);

		buf[0] = inst & 0xFD07u;  // CB(N)Z Rn, #0
		buf[1] = 0xE003;          // B PC, #6
		buf[2] = 0xF8DF;          // LDR.W PC, [PC]
		buf[3] = 0xF000;          // ...
		buf[4] = addr & 0xFFFFu;
		buf[5] = addr >> 16u;
		return 12;
	}

	static size_t FixThumb32_B(uint16_t* buf, uint16_t high_inst, uint16_t low_inst, uintptr_t pc, i_type type, fix_inst_info* fix_info)
	{
		uint32_t j1 = GET_BIT_16(low_inst, 13);
		uint32_t j2 = GET_BIT_16(low_inst, 11);
		uint32_t s = GET_BIT_16(high_inst, 10);
		uint32_t i1 = !(j1 ^ s);
		uint32_t i2 = !(j2 ^ s);

		uint32_t addr;
		if (type == B_COND_THUMB32) {
			uint32_t x =
				(s << 20u) | (j2 << 19u) | (j1 << 18u) | ((high_inst & 0x3Fu) << 12u) | ((low_inst & 0x7FFu) << 1u);
			uint32_t imm32 = SIGN_EXTEND_32(x, 21u);
			addr = SET_BIT0(pc + imm32);  // thumb -> thumb
		}
		else if (type == B_THUMB32) {
			uint32_t x =
				(s << 24u) | (i1 << 23u) | (i2 << 22u) | ((high_inst & 0x3FFu) << 12u) | ((low_inst & 0x7FFu) << 1u);
			uint32_t imm32 = SIGN_EXTEND_32(x, 25u);
			addr = SET_BIT0(pc + imm32);  // thumb -> thumb
		}
		else if (type == BL_THUMB32) {
			uint32_t x =
				(s << 24u) | (i1 << 23u) | (i2 << 22u) | ((high_inst & 0x3FFu) << 12u) | ((low_inst & 0x7FFu) << 1u);
			uint32_t imm32 = SIGN_EXTEND_32(x, 25u);
			addr = SET_BIT0(pc + imm32);  // thumb -> thumb
		}
		else                              // type == BLX_THUMB32
		{
			uint32_t x =
				(s << 24u) | (i1 << 23u) | (i2 << 22u) | ((high_inst & 0x3FFu) << 12u) | ((low_inst & 0x7FEu) << 1u);
			uint32_t imm32 = SIGN_EXTEND_32(x, 25u);
			addr = PC_ALIGN_4(pc) + imm32;  // thumb -> arm, align4
		}
		addr = FixBackupToBackup(addr, fix_info);

		size_t idx = 0;
		if (type == B_COND_THUMB32) {
			uint32_t cond = GET_BITS_16(high_inst, 9, 6);
			buf[idx++] = 0xD000u | (uint16_t)(cond << 8u);  // B<c> #0
			buf[idx++] = 0xE003;                            // B #6
		}
		else if (type == BL_THUMB32 || type == BLX_THUMB32) {
			buf[idx++] = 0xF20F;  // ADD LR, PC, #9
			buf[idx++] = 0x0E09;  // ...
		}
		buf[idx++] = 0xF8DF;  // LDR.W PC, [PC]
		buf[idx++] = 0xF000;  // ...
		buf[idx++] = addr & 0xFFFFu;
		buf[idx++] = addr >> 16u;
		return idx * 2;  // 8 or 12
	}

	static size_t FixThumb32_ADR(uint16_t* buf, uint16_t high_inst, uint16_t low_inst, uintptr_t pc, i_type type, fix_inst_info* fix_info)
	{
		uint32_t rt = GET_BITS_16(low_inst, 11, 8);  // r0 - r15
		uint32_t i = GET_BIT_16(high_inst, 10);
		uint32_t imm3 = GET_BITS_16(low_inst, 14, 12);
		uint32_t imm8 = GET_BITS_16(low_inst, 7, 0);
		uint32_t imm32 = (i << 11u) | (imm3 << 8u) | imm8;
		uint32_t addr = (type == ADR_BEFORE_THUMB32 ? (PC_ALIGN_4(pc) - imm32) : (PC_ALIGN_4(pc) + imm32));
		if (IsAddrInBackup(addr, fix_info)) return 0;

		buf[0] = 0xF8DF;                      // LDR.W Rt, [PC, #4]
		buf[1] = (uint16_t)(rt << 12u) + 4u;  // ...
		buf[2] = 0xE002;                      // B #4
		buf[3] = 0xBF00;                      // NOP
		buf[4] = addr & 0xFFFFu;
		buf[5] = addr >> 16u;
		return 12;
	}

	static size_t FixThumb32_LDR(uint16_t* buf, uint16_t high_inst, uint16_t low_inst, uintptr_t pc, i_type type, fix_inst_info* fix_info)
	{
		uint32_t u = GET_BIT_16(high_inst, 7);
		uint32_t rt = GET_BITS_16(low_inst, 15, 12);  // r0 - r15
		uint32_t rt2 = 0;                             // r0 - r15
		uint32_t addr;

		if (type == LDRD_THUMB32) {
			rt2 = GET_BITS_16(low_inst, 11, 8);
			uint32_t imm8 = GET_BITS_16(low_inst, 7, 0);
			addr = (u ? PC_ALIGN_4(pc) + (imm8 << 2u) : PC_ALIGN_4(pc) - (imm8 << 2u));
		}
		else {
			uint32_t imm12 = (uint32_t)GET_BITS_16(low_inst, 11, 0);
			addr = (u ? PC_ALIGN_4(pc) + imm12 : PC_ALIGN_4(pc) - imm12);
		}
		if (IsAddrInBackup(addr, fix_info)) return 0;

		if (type == LDR_PC_THUMB32 && rt == 0xF)  // Rt == PC
		{
			buf[0] = 0xB403;          // PUSH {R0, R1}
			buf[1] = 0xBF00;          // NOP
			buf[2] = 0xF8DF;          // LDR.W R0, [PC, #4]
			buf[3] = 0x0004;          // ...
			buf[4] = 0xE002;          // B #4
			buf[5] = 0xBF00;          // NOP
			buf[6] = addr & 0xFFFFu;  //
			buf[7] = addr >> 16u;     //
			buf[8] = 0xF8D0;          // LDR.W R0, [R0]
			buf[9] = 0x0000;          // ...
			buf[10] = 0x9001;         // STR R0, [SP, #4]
			buf[11] = 0xBD01;         // POP {R0, PC}
			return 24;
		}
		else {
			buf[0] = 0xF8DF;                      // LDR.W Rt, [PC, #4]
			buf[1] = (uint16_t)(rt << 12u) | 4u;  // ...
			buf[2] = 0xE002;                      // B #4
			buf[3] = 0xBF00;                      // NOP
			buf[4] = addr & 0xFFFFu;
			buf[5] = addr >> 16u;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wswitch"
			switch (type) {
			case LDR_THUMB32:
				buf[6] = (uint16_t)(0xF8D0 + rt);  // LDR.W Rt, [Rt]
				buf[7] = (uint16_t)(rt << 12u);    // ...
				break;
			case LDRB_THUMB32:
				buf[6] = (uint16_t)(0xF890 + rt);  // LDRB.W Rt, [Rt]
				buf[7] = (uint16_t)(rt << 12u);    // ...
				break;
			case LDRD_THUMB32:
				buf[6] = (uint16_t)(0xE9D0 + rt);                        // LDRD Rt, Rt2, [Rt]
				buf[7] = (uint16_t)(rt << 12u) + (uint16_t)(rt2 << 8u);  // ...
				break;
			case LDRH_THUMB32:
				buf[6] = (uint16_t)(0xF8B0 + rt);  // LDRH.W Rt, [Rt]
				buf[7] = (uint16_t)(rt << 12u);    // ...
				break;
			case LDRSB_THUMB32:
				buf[6] = (uint16_t)(0xF990 + rt);  // LDRSB.W Rt, [Rt]
				buf[7] = (uint16_t)(rt << 12u);    // ...
				break;
			case LDRSH_THUMB32:
				buf[6] = (uint16_t)(0xF9B0 + rt);  // LDRSH.W Rt, [Rt]
				buf[7] = (uint16_t)(rt << 12u);    // ...
				break;
			}
#pragma clang diagnostic pop
			return 16;
		}
	}

	static size_t FixThumb32_PL(uint16_t* buf, uint16_t high_inst, uint16_t low_inst, uintptr_t pc, i_type type, fix_inst_info* fix_info)
	{
		uint32_t u = GET_BIT_16(high_inst, 7);
		uint32_t imm12 = GET_BITS_16(low_inst, 11, 0);
		uint32_t addr = (u ? PC_ALIGN_4(pc) + imm12 : PC_ALIGN_4(pc) - imm12);
		addr = FixBackupToBackup(addr, fix_info);

		buf[0] = 0xB401;  // PUSH {R0}
		buf[1] = 0xBF00;  // NOP
		buf[2] = 0xF8DF;  // LDR.W R0, [PC, #8]
		buf[3] = 0x0008;  // ...
		if (type == PLD_THUMB32) {
			buf[4] = 0xF890;  // PLD [R0]
			buf[5] = 0xF000;  // ...
		}
		else {
			buf[4] = 0xF990;  // PLI [R0]
			buf[5] = 0xF000;  // ...
		}
		buf[6] = 0xBC01;  // POP {R0}
		buf[7] = 0xE001;  // B #2
		buf[8] = addr & 0xFFFFu;
		buf[9] = addr >> 16u;
		return 20;
	}

	static size_t FixThumb32_TB(uint16_t* buf, uint16_t high_inst, uint16_t low_inst, uintptr_t pc, i_type type, fix_inst_info* fix_info)
	{
		// If TBB/TBH is not the last instruction that needs to be rewritten,
		// the rewriting can NOT be completed.
		uintptr_t target_addr = CLEAR_BIT0(pc - 4);
		if (target_addr + 4 != fix_info->end_addr) return 0;

		uint32_t rn = GET_BITS_16(high_inst, 3, 0);
		uint32_t rm = GET_BITS_16(low_inst, 3, 0);
		uint32_t rx, ry;  // r0 - r7
		for (rx = 7;; --rx)
			if (rx != rn && rx != rm) break;
		for (ry = 7;; --ry)
			if (ry != rn && ry != rm && ry != rx) break;

		buf[0] = (uint16_t)(0xB500u | (1u << rx) | (1u << ry));  // PUSH {Rx, Ry, LR}
		buf[1] = 0xBF00;                                         // NOP
		buf[2] = 0xF8DF;                                         // LDR.W Rx, [PC, #20]
		buf[3] = (uint16_t)(rx << 12u) | 20u;                    // ...
		if (type == TBB_THUMB32) {
			buf[4] = (uint16_t)(0xEB00u | (rn == 0xF ? rx : rn));  // ADD.W Ry, Rx|Rn, Rm
			buf[5] = (uint16_t)(0x0000u | (ry << 8u) | rm);        // ...
			buf[6] = (uint16_t)(0x7800u | (ry << 3u) | ry);        // LDRB Ry, [Ry]
			buf[7] = 0xBF00;                                       // NOP
		}
		else {
			buf[4] = (uint16_t)(0xEB00u | (rn == 0xF ? rx : rn));  // ADD.W Ry, Rx|Rn, Rm, LSL #1
			buf[5] = (uint16_t)(0x0040u | (ry << 8u) | rm);        // ...
			buf[6] = (uint16_t)(0x8800u | (ry << 3u) | ry);        // LDRH Ry, [Ry]
			buf[7] = 0xBF00;                                       // NOP
		}
		buf[8] = (uint16_t)(0xEB00u | rx);                        // ADD Rx, Rx, Ry, LSL #1
		buf[9] = (uint16_t)(0x0040u | (rx << 8u) | ry);           // ...
		buf[10] = (uint16_t)(0x3001u | (rx << 8u));               // ADD Rx, #1
		buf[11] = (uint16_t)(0x9002u | (rx << 8u));               // STR Rx, [SP, #8]
		buf[12] = (uint16_t)(0xBD00u | (1u << rx) | (1u << ry));  // POP {Rx, Ry, PC}
		buf[13] = 0xBF00;                                         // NOP
		buf[14] = pc & 0xFFFFu;
		buf[15] = pc >> 16u;
		return 32;
	}

	static size_t FixThumb32_VLDR(uint16_t* buf, uint16_t high_inst, uint16_t low_inst, uintptr_t pc, fix_inst_info* fix_info)
	{
		uint32_t u = GET_BIT_16(high_inst, 7);
		uint32_t D = GET_BIT_16(high_inst, 6);
		uint32_t vd = GET_BITS_16(low_inst, 15, 12);
		uint32_t size = GET_BITS_16(low_inst, 9, 8);
		uint32_t imm8 = GET_BITS_16(low_inst, 7, 0);
		uint32_t esize = (8u << size);
		uint32_t imm32 = (esize == 16 ? imm8 << 1u : imm8 << 2u);
		uint32_t addr = (u ? PC_ALIGN_4(pc) + imm32 : PC_ALIGN_4(pc) - imm32);
		if (IsAddrInBackup(addr, fix_info)) return 0;

		buf[0] = 0xB401;                                       // PUSH {R0}
		buf[1] = 0xBF00;                                       // NOP
		buf[2] = 0xF8DF;                                       // LDR.W R0, [PC, #4]
		buf[3] = 0x0004;                                       // ...
		buf[4] = 0xE002;                                       // B #4
		buf[5] = 0xBF00;                                       // NOP
		buf[6] = addr & 0xFFFFu;                               //
		buf[7] = addr >> 16u;                                  //
		buf[8] = (uint16_t)(0xED90u | D << 6u);                // VLDR Sd|Dd, [R0]
		buf[9] = (uint16_t)(0x800u | vd << 12u | size << 8u);  // ...
		buf[10] = 0xBC01;                                      // POP {R0}
		buf[11] = 0xBF00;                                      // NOP
		return 24;
	}

	static size_t FixThumb16Inst(uint16_t* buf, uint16_t inst, uintptr_t pc, i_type type, fix_inst_info* fix_info)
	{
		switch (type)
		{
		case B_COND_THUMB16:
		case B_THUMB16:
		case BX_PC_THUMB16:
			return FixThumb16_B(buf, inst, pc, type, fix_info);

		case ADD_PC_THUMB16:
			return FixThumb16_ADD(buf, inst, pc);
		
		case MOV_PC_THUMB16:
			return FixThumb16_MOV(buf, inst, pc);

		case ADR_THUMB16:
			return FixThumb16_ADR(buf, inst, pc, fix_info);

		case LDR_THUMB16:
			return FixThumb16_LDR(buf, inst, pc, fix_info);

		case CBZ_THUMB16:
		case CBNZ_THUMB16:
			return FixThumb16_CB(buf, inst, pc, fix_info);
		default:
			// IGNORED
			buf[0] = inst;
			buf[1] = _NOP.T1;  // NOP
			break;
		}
		return 4;
	}

	static size_t FixThumb32Inst(uint16_t* buf, uint16_t high_inst, uint16_t low_inst, uintptr_t pc, i_type type, fix_inst_info* fix_info)
	{
		switch (type)
		{
		case B_COND_THUMB32:
		case B_THUMB32:
		case BL_THUMB32:
		case BLX_THUMB32:
			return FixThumb32_B(buf, high_inst, low_inst, pc, type, fix_info);

		case ADR_BEFORE_THUMB32:
		case ADR_AFTER_THUMB32:
			return FixThumb32_ADR(buf, high_inst, low_inst, pc, type, fix_info);

		case LDR_THUMB32:
		case LDR_PC_THUMB32:
		case LDRB_THUMB32:
		case LDRD_THUMB32:
		case LDRH_THUMB32:
		case LDRSB_THUMB32:
		case LDRSH_THUMB32:
			return FixThumb32_LDR(buf, high_inst, low_inst, pc, type, fix_info);

		case PLD_THUMB32:
		case PLI_THUMB32:
			return FixThumb32_PL(buf, high_inst, low_inst, pc, type, fix_info);

		case TBB_THUMB32:
		case TBH_THUMB32:
			return FixThumb32_TB(buf, high_inst, low_inst, pc, type, fix_info);

		case VLDR_THUMB32:
			return FixThumb32_VLDR(buf, high_inst, low_inst, pc, fix_info);
		default:
			// IGNORED
			buf[0] = high_inst;
			buf[1] = low_inst;
			break;
		}
		return 4;
	}

	static size_t FixARM_B(uint32_t* buf, uint32_t inst, uintptr_t pc, i_type type, fix_inst_info* fix_info)
	{
		uint32_t cond;
		if (type == B_ARM || type == BL_ARM || type == BX_PC_ARM)
			cond = GET_BITS_32(inst, 31, 28);
		else
			// type == BLX_ARM
			cond = 0xE;  // 1110 None (AL)

		uint32_t addr;
		if (type == B_ARM || type == BL_ARM) {
			uint32_t imm24 = GET_BITS_32(inst, 23, 0);
			uint32_t imm32 = SIGN_EXTEND_32(imm24 << 2u, 26u);
			addr = pc + imm32;  // arm -> arm
		}
		else if (type == BLX_ARM) {
			uint32_t h = GET_BIT_32(inst, 24);
			uint32_t imm24 = GET_BITS_32(inst, 23, 0);
			uint32_t imm32 = SIGN_EXTEND_32((imm24 << 2u) | (h << 1u), 26u);
			addr = SET_BIT0(pc + imm32);  // arm -> thumb
		}
		else {
			// type == BX_PC_ARM
			addr = pc;  // arm -> arm, BX PC
		}
		addr = FixBackupToBackup(addr, fix_info);

		size_t idx = 0;
		if (type == BL_ARM || type == BLX_ARM) {
			buf[idx++] = 0x028FE008u | (cond << 28u);  // ADD<c> LR, PC, #8
		}
		buf[idx++] = 0x059FF000u | (cond << 28u);  // LDR<c> PC, [PC, #0]
		buf[idx++] = 0xEA000000;                   // B #0
		buf[idx++] = addr;
		return idx * 4;  // 12 or 16
	}

	static size_t FixARM_ADD_OR_SUB(uint32_t* buf, uint32_t inst, uintptr_t pc)
	{
		// ADD{S}<c> <Rd>, <Rn>, PC{, <shift>}  or  ADD{S}<c> <Rd>, PC, <Rm>{, <shift>}
		// SUB{S}<c> <Rd>, <Rn>, PC{, <shift>}  or  SUB{S}<c> <Rd>, PC, <Rm>{, <shift>}
		uint32_t cond = GET_BITS_32(inst, 31, 28);
		uint32_t rn = GET_BITS_32(inst, 19, 16);
		uint32_t rm = GET_BITS_32(inst, 3, 0);
		uint32_t rd = GET_BITS_32(inst, 15, 12);

		uint32_t rx;  // r0 - r3
		for (rx = 3;; --rx)
			if (rx != rn && rx != rm && rx != rd) break;

		if (rd == 0xF)  // Rd == PC
		{
			uint32_t ry;  // r0 - r4
			for (ry = 4;; --ry)
				if (ry != rn && ry != rm && ry != rd && ry != rx) break;

			buf[0] = 0x0A000000u | (cond << 28u);           // B<c> #0
			buf[1] = 0xEA000005;                            // B #20
			buf[2] = 0xE92D8000 | (1u << rx) | (1u << ry);  // PUSH {Rx, Ry, PC}
			buf[3] = 0xE59F0008 | (rx << 12u);              // LDR Rx, [PC, #8]
			if (rn == 0xF)
				// Rn == PC
				buf[4] =
				(inst & 0x0FF00FFFu) | 0xE0000000 | (ry << 12u) | (rx << 16u);  // ADD/SUB Ry, Rx, Rm{, <shift>}
			else
				// Rm == PC
				buf[4] = (inst & 0x0FFF0FF0u) | 0xE0000000 | (ry << 12u) | rx;  // ADD/SUB Ry, Rn, Rx{, <shift>}
			buf[5] = 0xE58D0008 | (ry << 12u);                                // STR Ry, [SP, #8]
			buf[6] = 0xE8BD8000 | (1u << rx) | (1u << ry);                    // POP {Rx, Ry, PC}
			buf[7] = pc;
			return 32;
		}
		else {
			buf[0] = 0x0A000000u | (cond << 28u);  // B<c> #0
			buf[1] = 0xEA000005;                   // B #20
			buf[2] = 0xE52D0004 | (rx << 12u);     // PUSH {Rx}
			buf[3] = 0xE59F0008 | (rx << 12u);     // LDR Rx, [PC, #8]
			if (rn == 0xF)
				// Rn == PC
				buf[4] = (inst & 0x0FF0FFFFu) | 0xE0000000 | (rx << 16u);  // ADD/SUB{S} Rd, Rx, Rm{, <shift>}
			else
				// Rm == PC
				buf[4] = (inst & 0x0FFFFFF0u) | 0xE0000000 | rx;  // ADD/SUB{S} Rd, Rn, Rx{, <shift>}
			buf[5] = 0xE49D0004 | (rx << 12u);                  // POP {Rx}
			buf[6] = 0xEA000000;                                // B #0
			buf[7] = pc;
			return 32;
		}
	}

	static size_t FixARM_ADR(uint32_t* buf, uint32_t inst, uintptr_t pc, i_type type, fix_inst_info* fix_info)
	{
		uint32_t cond = GET_BITS_32(inst, 31, 28);
		uint32_t rd = GET_BITS_32(inst, 15, 12);
		uint32_t imm12 = GET_BITS_32(inst, 11, 0);
		uint32_t imm32 = arm_expand_imm(imm12);

		uint32_t addr = (type == ADR_AFTER_ARM ? (PC_ALIGN_4(pc) + imm32) : (PC_ALIGN_4(pc) - imm32));
		if (IsAddrInBackup(addr, fix_info)) return 0;  // rewrite failed

		buf[0] = 0x059F0000u | (cond << 28u) | (rd << 12u);  // LDR<c> Rd, [PC, #0]
		buf[1] = 0xEA000000;                                 // B #0
		buf[2] = addr;
		return 12;
	}

	static size_t FixARM_MOV(uint32_t* buf, uint32_t inst, uintptr_t pc)
	{
		// MOV{S}<c> <Rd>, PC
		uint32_t cond = GET_BITS_32(inst, 31, 28);
		uint32_t rd = GET_BITS_32(inst, 15, 12);
		uint32_t rx = (rd == 0) ? 1 : 0;

		if (rd == 0xF)  // Rd == PC (MOV PC, PC)
		{
			buf[0] = 0x059FF000u | (cond << 28u);  // LDR<c> PC, [PC, #0]
			buf[1] = 0xEA000000;                   // B #0
			buf[2] = pc;
			return 12;
		}
		else {
			buf[0] = 0x0A000000u | (cond << 28u);             // B<c> #0
			buf[1] = 0xEA000005;                              // B #20
			buf[2] = 0xE52D0004 | (rx << 12u);                // PUSH {Rx}
			buf[3] = 0xE59F0008 | (rx << 12u);                // LDR Rx, [PC, #8]
			buf[4] = (inst & 0x0FFFFFF0u) | 0xE0000000 | rx;  // MOV{S} Rd, Rx{, <shift> #<amount>/RRX}
			buf[5] = 0xE49D0004 | (rx << 12u);                // POP {Rx}
			buf[6] = 0xEA000000;                              // B #0
			buf[7] = pc;
			return 32;
		}
	}

	static size_t FixARM_LDR(uint32_t* buf, uint32_t inst, uintptr_t pc, i_type type, fix_inst_info* fix_info)
	{
		uint32_t cond = GET_BITS_32(inst, 31, 28);
		uint32_t u = GET_BIT_32(inst, 23);
		uint32_t rt = GET_BITS_16(inst, 15, 12);

		uint32_t imm32;
		if (type == LDR_ARM || type == LDR_PC_ARM || type == LDRB_ARM)
			imm32 = GET_BITS_32(inst, 11, 0);
		else
			imm32 = (GET_BITS_32(inst, 11, 8) << 4u) + GET_BITS_32(inst, 3, 0);
		uint32_t addr = (u ? (PC_ALIGN_4(pc) + imm32) : (PC_ALIGN_4(pc) - imm32));
		if (IsAddrInBackup(addr, fix_info)) return 0;  // rewrite failed

		if (type == LDR_PC_ARM && rt == 0xF) {
			// Rt == PC
			buf[0] = 0x0A000000u | (cond << 28u);  // B<c> #0
			buf[1] = 0xEA000006;                   // B #24
			buf[2] = 0xE92D0003;                   // PUSH {R0, R1}
			buf[3] = 0xE59F0000;                   // LDR R0, [PC, #0]
			buf[4] = 0xEA000000;                   // B #0
			buf[5] = addr;                         //
			buf[6] = 0xE5900000;                   // LDR R0, [R0]
			buf[7] = 0xE58D0004;                   // STR R0, [SP, #4]
			buf[8] = 0xE8BD8001;                   // POP {R0, PC}
			return 36;
		}
		else {
			buf[0] = 0x0A000000u | (cond << 28u);  // B<c> #0
			buf[1] = 0xEA000003;                   // B #12
			buf[2] = 0xE59F0000 | (rt << 12u);     // LDR Rt, [PC, #0]
			buf[3] = 0xEA000000;                   // B #0
			buf[4] = addr;                         //
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wswitch"
			switch (type) {
			case LDR_ARM:
				buf[5] = 0xE5900000 | (rt << 16u) | (rt << 12u);  // LDR Rt, [Rt]
				break;
			case LDRB_ARM:
				buf[5] = 0xE5D00000 | (rt << 16u) | (rt << 12u);  // LDRB Rt, [Rt]
				break;
			case LDRD_ARM:
				buf[5] = 0xE1C000D0 | (rt << 16u) | (rt << 12u);  // LDRD Rt, [Rt]
				break;
			case LDRH_ARM:
				buf[5] = 0xE1D000B0 | (rt << 16u) | (rt << 12u);  // LDRH Rt, [Rt]
				break;
			case LDRSB_ARM:
				buf[5] = 0xE1D000D0 | (rt << 16u) | (rt << 12u);  // LDRSB Rt, [Rt]
				break;
			case LDRSH_ARM:
				buf[5] = 0xE1D000F0 | (rt << 16u) | (rt << 12u);  // LDRSH Rt, [Rt]
				break;
			}
#pragma clang diagnostic pop
			return 24;
		}
	}

	static size_t FixARM_LDR_REG(uint32_t* buf, uint32_t inst, uintptr_t pc, i_type type)
	{
		// LDR<c> <Rt>, [PC,+/-<Rm>{, <shift>}]{!}
		// ......
		uint32_t cond = GET_BITS_32(inst, 31, 28);
		uint32_t rt = GET_BITS_16(inst, 15, 12);
		uint32_t rt2 = rt + 1;
		uint32_t rm = GET_BITS_16(inst, 3, 0);
		uint32_t rx;  // r0 - r3
		for (rx = 3;; --rx)
			if (rx != rt && rx != rt2 && rx != rm) break;

		if (type == LDR_PC_REG_ARM && rt == 0xF) {
			// Rt == PC
			uint32_t ry;  // r0 - r4
			for (ry = 4;; --ry)
				if (ry != rt && ry != rt2 && ry != rm && ry != rx) break;

			buf[0] = 0x0A000000u | (cond << 28u);           // B<c> #0
			buf[1] = 0xEA000006;                            // B #24
			buf[2] = 0xE92D8000 | (1u << rx) | (1u << ry);  // PUSH {Rx, Ry, PC}
			buf[3] = 0xE59F0000 | (rx << 12u);              // LDR Rx, [PC, #8]
			buf[4] = 0xEA000000;                            // B #0
			buf[5] = pc;
			buf[6] =
				(inst & 0x0FF00FFFu) | 0xE0000000 | (rx << 16u) | (ry << 12u);  // LDRxx Ry, [Rx],+/-Rm{, <shift>}
			buf[7] = 0xE58D0008 | (ry << 12u);                                  // STR Ry, [SP, #8]
			buf[8] = 0xE8BD8000 | (1u << rx) | (1u << ry);                      // POP {Rx, Ry, PC}
			return 36;
		}
		else {
			buf[0] = 0x0A000000u | (cond << 28u);  // B<c> #0
			buf[1] = 0xEA000005;                   // B #20
			buf[2] = 0xE52D0004 | (rx << 12u);     // PUSH {Rx}
			buf[3] = 0xE59F0000 | (rx << 12u);     // LDR Rx, [PC, #0]
			buf[4] = 0xEA000000;                   // B #0
			buf[5] = pc;
			buf[6] = (inst & 0x0FF0FFFFu) | 0xE0000000 | (rx << 16u);  // LDRxx Rt, [Rx],+/-Rm{, <shift>}
			buf[7] = 0xE49D0004 | (rx << 12u);                         // POP {Rx}
			return 32;
		}
	}

	static size_t FixArmInst(uint32_t* buf, uint32_t inst, uintptr_t pc, i_type type, fix_inst_info* fix_info)
	{
		// We will only overwrite 4 to 8 bytes on A32, so PC cannot be in the coverage.
		// In this case, the add/sub/mov/ldr_reg instruction does not need to consider
		// the problem of PC in the coverage area when rewriting.

		switch (type)
		{
		case B_ARM:
		case BX_PC_ARM:
		case BL_ARM:
		case BLX_ARM:
			return FixARM_B(buf, inst, pc, type, fix_info);

		case ADD_ARM:
		case ADD_PC_ARM:
		case SUB_ARM:
		case SUB_PC_ARM:
			return FixARM_ADD_OR_SUB(buf, inst, pc);

		case ADR_AFTER_ARM:
		case ADR_BEFORE_ARM:
			return FixARM_ADR(buf, inst, pc, type, fix_info);

		case MOV_ARM:
		case MOV_PC_ARM:
			return FixARM_MOV(buf, inst, pc);

		case LDR_ARM:
		case LDR_PC_ARM:
		case LDRB_ARM:
		case LDRD_ARM:
		case LDRH_ARM:
		case LDRSB_ARM:
		case LDRSH_ARM:
			return FixARM_LDR(buf, inst, pc, type, fix_info);

		case LDR_REG_ARM:
		case LDR_PC_REG_ARM:
		case LDRB_REG_ARM:
		case LDRD_REG_ARM:
		case LDRH_REG_ARM:
		case LDRSB_REG_ARM:
		case LDRSH_REG_ARM:
			return FixARM_LDR_REG(buf, inst, pc, type);

		default:
			// IGNORED
			buf[0] = inst;
			break;
		}
		return 4;
	}
}

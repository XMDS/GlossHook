#ifndef ARMHOOK_INST_H
#define ARMHOOK_INST_H

#include <stdint.h>

#define PAGE_START(addr, size) ((uintptr_t)addr & ~(size - 1))                             
#define PAGE_END(addr, size) PAGE_START(addr + size - 1, size)

#ifdef __arm__
#define SET_BIT0(addr) (addr | 1)
#define CLEAR_BIT0(addr) (addr & 0xFFFFFFFE)
#define TEST_BIT0(addr) (addr & 1)

#define PC_ALIGN_4(pc) (pc & 0xFFFFFFFC)
#define IS_ADDR_ALIGN_4(addr) (addr % 4 == 0)
#define MAKE_THUMB32_HEX(a, b) (uint32_t)(a << 16 | b)

#define GET_BIT_16(n, idx)        ((uint16_t)((n) << (15u - (idx))) >> 15u)
#define GET_BITS_16(n, high, low) ((uint16_t)((n) << (15u - (high))) >> (15u - (high) + (low)))
#define GET_BIT_32(n, idx)        ((uint32_t)((n) << (31u - (idx))) >> 31u)
#define GET_BITS_32(n, high, low) ((uint32_t)((n) << (31u - (high))) >> (31u - (high) + (low)))
#define SIGN_EXTEND_32(n, len) ((GET_BIT_32(n, len - 1) > 0) ? ((n) | (0xFFFFFFFF << (len))) : n)

#define GET_THUMB_PC(addr) (addr + 4)
#define GET_ARM_PC(addr) (addr + 8)
#elif __aarch64__
#define GET_ARM_PC(addr) (addr + 0)
#define cacheflush(addr, byte, n) __builtin___clear_cache((char*)addr, (char*)byte)
#endif

namespace Inst
{
	namespace REG
	{
#ifdef __arm__
		enum ARM
		{
			//thumb, arm
			R0, R1, R2, R3,
			R4, R5, R6, R7,
			//arm only
			R8,
			R9,
			R10,
			R11,
			R12, IP = R12,
			//thumb, arm
			R13, SP = R13,
			R14, LR = R14,
			R15, PC = R15,
			//
			CPRS
		};
#elif __aarch64__
		enum ARM64
		{
			//64 bits reg: X0 - X31
			//32 bits reg: W0 - W31
			// vetcor reg: V0 - V31
			//64 bits double reg: D0 - D31
			//32 bits float reg: S0 - S31
			X0, W0 = X0,
			X1, W1 = X1,
			X2, W2 = X2,
			X3, W3 = X3,
			X4, W4 = X4,
			X5, W5 = X5,
			X6, W6 = X6,
			X7, W7 = X7,

			X8, W8 = X8,
			X9, W9 = X9,
			X10, W10 = X10,
			X11, W11 = X11,
			X12, W12 = X12,
			X13, W13 = X13,
			X14, W14 = X14,
			X15, W15 = X15,
			//IPx
			X16, W16 = X16,
			X17, W17 = X17,
			//Platform reg
			X18, W18 = X18,

			X19, W19 = X19,
			X20, W20 = X20,
			X21, W21 = X21,
			X22, W22 = X22,
			X23, W23 = X23,
			X24, W24 = X24,
			X25, W25 = X25,
			X26, W26 = X26,
			X27, W27 = X27,
			X28, W28 = X28,

			X29, W29 = X29, FP = X29,
			X30, W30 = X30, LR = X30,
			X31, W31 = X31, SP = X31,
			PC, //no use
		};
#endif
	}

	enum class conds //IT_THUMB16 || B_COND_THUMB16 || BW_COND_THUMB32 || B_ARM
	{
		EQ, NE, CS, HS = CS, CC, LO = CC, MI, PL, VS, VC, HI, LS, GE, LT, GT, LE,
		AL,//no cond(see B_THUMB16), AL is an optional mnemonic extension for always, except in IT instructions
		//BNV,//1111  ???
		MAX_CONDS
	};
	
	typedef enum : uint8_t
	{
		UNDEFINE,

#ifdef __arm__
		/*********************************************************************THUMB16***********************************************************************/

		/*
		* IT{<x>{<y>{<z>}}} <firstcond> (see enum cond_type)
		* name: IT_T1
		* page: A8.8.55
		* preview: <IT EQ> <ITT NE> <ITTT MI>....
		*/
		IT_THUMB16,

		/* B<c> <label> (see enum cond_type)
		* name: B_T1
		* page: A8.8.18
		* range: -256 to 254
		* preview: { <BNE loc_000006> <BEQ loc_666666> <BLT loc_233333>.... }
		*/
		B_COND_THUMB16,
		BEQ_THUMB16,
		BNE_THUMB16,
		BCS_THUMB16,
		BCC_THUMB16,
		BMI_THUMB16,
		BPL_THUMB16,
		BVS_THUMB16,
		BVC_THUMB16,
		BHI_THUMB16,
		BLS_THUMB16,
		BGE_THUMB16,
		BLT_THUMB16,
		BGT_THUMB16,
		BLE_THUMB16,

		/* B<c> <label> (not cond)
		* name: B_T2
		* page: A8.8.18
		* range: -2048 to 2046
		* preview: <B loc_000006> <B loc_666666> <B loc_233333>....
		*/
		B_THUMB16,

		/* BX<c> <Rm>
		* name: BX_T1
		* page: A8.8.27
		* preview: <BX PC>
		*/
		BX_PC_THUMB16,

		/* ADD<c> <Rdn>, <Rm>  (ADD <reg>, PC)
		* name: ADD_T2
		* page: A8.8.6
		* preview: <ADD R0,PC> <ADD R1,PC>....
		*/
		ADD_PC_THUMB16,

		/* MOV<c> <Rd>, <Rm>
		* name: MOV_T1
		* page: A8.8.104
		* preview: <MOV R0,PC> <MOV R1,PC>....
		*/
		MOV_PC_THUMB16,

		/* ADR<c> <Rd>, <label>
		* name: ADR_T1
		* page: A8.8.12
		* range: 0 to 1024
		* preview: <ADR R1, dword_666666> <ADR R0, str>....
		*/
		ADR_THUMB16,

		/* LDR<c><Rt>, <label>
		* name: LDR_T1
		* page: A8.8.65
		* range: 0 to 1020
		* preview: <LDR R0, =(xxxx_ptr - 0x123456)> <LDR R1, =(dword_233333 - 0x123456)> <LDR R2, =(unk_666666 - 0x123456)>....
		*/
		LDR_THUMB16,

		/* LDR <reg>, <reg...>
		* preview: <LDR R2, [R0]> <LDR R0, [R0,#0x10]> <LDR R1, [R5,#0x2C]> <LDR R2, [R0,R1]> <LDR R0, [SP,#0x58+var_48]>....
		*/
		//LDR_REG_THUMB16,

		/* CB{N}Z <Rn>, <label>
		* name: CB_T1
		* page: A8.8.29
		* range: 0 to 126
		*/
		CB_THUMB16,
		/* preview: <CBZ R0, loc_123456> <CBZ R4, loc_233333>.... */
		CBZ_THUMB16,
		/* preview: <CBNZ R0, loc_123456> <CBNZ R4, loc_233333>.... */
		CBNZ_THUMB16,

		/* ADDS <reg>, #num || ADDS <reg>, <reg>, #num || ADDS <reg>, <reg>, <reg>
		* preview: <ADDS R0, #1> <ADDS R1, R2, #4> <ADDS R0, R5, R4>....
		*/
		//ADDS_THUMB16,

		/* MOVS <reg>, #num
		* preview: <MOVS R3, #0> <MOVS R6, #0xFF>....
		*/
		//MOVS_THUMB16,

		/* ADD <reg>, SP, #num
		* preview: <ADD R7, SP, #8> <ADD SP, SP, #8> <ADD R0, SP, #0x100+var_200>....
		*/
		//ADD_REG_THUMB16,

		/*******************THUMB32******************/

		/* B<c>.W <label> (see enum cond_type)
		* name: B_T3
		* page: A8.8.18
		* range: -1048576 to 1048574
		* preview: { <BNE.W loc_000006> <BEQ.W loc_666666> <BLT.W loc_233333>.... }
		*/
		B_COND_THUMB32,
		BEQ_THUMB32,
		BNE_THUMB32,
		BCS_THUMB32,
		BCC_THUMB32,
		BMI_THUMB32,
		BPL_THUMB32,
		BVS_THUMB32,
		BVC_THUMB32,
		BHI_THUMB32,
		BLS_THUMB32,
		BGE_THUMB32,
		BLT_THUMB32,
		BGT_THUMB32,
		BLE_THUMB32,

		/* B<c>.W <label> (not cond)
		* name: B_T4
		* page: A8.8.18
		* range: -16777216 to 16777214
		* preview: <B.W loc_000006> <B.W loc_666666> <B.W loc_233333> <B.W func>....
		*/
		B_THUMB32,

		/* BL<c> <label>
		* name: BL_T1
		* page: A8.8.25
		* range: Multiples of 4 in the range -16777216 to 16777212
		* preview: <BL loc_000006> <BL loc_666666> <BL loc_233333> <BL func>....
		*/
		BL_THUMB32,

		/* BLX<c> <label>
		* name: BLX_T2
		* page: A8.8.25
		* range: -16777216 to 16777212
		* preview: <BLX loc_000006> <BLX loc_666666> <BLX loc_233333> <BLX func>....
		*/
		BLX_THUMB32,

		/* ADR<c>.W <Rd>, <label> (before)
		* name: ADR_T2
		* page: A8.8.12
		* range: 0 to 4095
		* preview: <ADR.W R1, dword_666666> <ADR.W R0, str>....
		*/
		ADR_BEFORE_THUMB32,

		/* ADR<c>.W <Rd>, <label> (after)
		* name: ADR_T3
		* page: A8.8.12
		* range: 0 to 4095
		* preview: <ADR.W R1, dword_666666> <ADR.W R0, str>....
		*/
		ADR_AFTER_THUMB32,

		/* LDR<c>.W <Rt>, <label>
		* name: LDR_T2
		* page: A8.8.65
		* range: -4095 to 4095
		* preview: <LDR.W R0, =(xxxx_ptr - 0x123456)> <LDR.W R1, =(dword_233333 - 0x123456)> <LDR.W R2, =(unk_666666 - 0x123456)>....
		*/
		LDR_THUMB32,

		/* LDR<c>.W <Rt>, [PC, #-0]
		* name: LDR_T2
		* page: A8.8.65
		* range: no limit
		* preview: <LDR.W R0, [PC, #0]> <LDR.W PC, [PC, #0]>....
		*/
		LDR_PC_THUMB32,

		/* LDRB<c> <Rt>, <label> | LDRB<c> <Rt>, [PC, #-0]
		* name: LDRB_T1(literal)
		* page: A8.8.70
		* range: -4095 to 4095
		* preview: <LDRB R0, [PC, #0]> <LDRB R0, =(xxxx_ptr - 0x123456)>....
		*/
		LDRB_THUMB32,

		/* LDRD<c> <Rt>, <Rt2>, <label> | LDRD<c> <Rt>, <Rt2>, [PC, #-0]
		* name: LDRD_T1(literal)
		* page: A8.8.74
		* range: Multiples of 4 in the range -1020 to 1020
		* preview: <LDRD R0, R1, [PC, #0]> <LDRD R0, R1, =(xxxx_ptr - 0x123456)>....
		*/
		LDRD_THUMB32,

		/* LDRH<c> <Rt>, <label> | LDRH<c> <Rt>, [PC, #-0]
		* name: LDRH_T1(literal)
		* page: A8.8.82
		* range: -4095 to 4095
		* preview: <LDRH R0, [PC, #0]> <LDRH R0, =(xxxx_ptr - 0x123456)>....
		*/
		LDRH_THUMB32,

		/* LDRSB<c> <Rt>, <label> | LDRSB<c> <Rt>, [PC, #-0]
		* name: LDRSB_T1(literal)
		* page: A8.8.86
		* range: -4095 to 4095
		* preview: <LDRSB R0, [PC, #0]> <LDRSB R0, =(xxxx_ptr - 0x123456)>....
		*/
		LDRSB_THUMB32,

		/* LDRSH<c> <Rt>, <label> | LDRSH<c> <Rt>, [PC, #-0]
		* name: LDRSH_T1(literal)
		* page: A8.8.90
		* range: -4095 to 4095
		* preview: <LDRSH R0, [PC, #0]> <LDRSH R0, =(xxxx_ptr - 0x123456)>....
		*/
		LDRSH_THUMB32,

		/* PLD<c> <label> | PLD<c> [PC, #-0]
		* name: PLD_T1(literal)
		* page: A8.8.128
		* range: -4095 to 4095
		* preview: <PLD loc_000006> <PLD [PC, #0]>....
		*/
		PLD_THUMB32,

		/* PLI<c> <label> | PLI<c> [PC, #-0]
		* name: PLI_T3(literal)
		* page: A8.8.130
		* range: 0 to 4095
		* preview: <PLI loc_000006> <PLI [PC, #0]>....
		*/
		PLI_THUMB32,

		/* TBB<c> [<Rn>, <Rm>]
		* name: TBB_T1
		* page: A8.8.237
		* range: no limit
		* preview: TBB.W [PC, R0]....
		*/
		TBB_THUMB32,

		/* TBH<c> [<Rn>, <Rm>, LSL #1]
		* name: TBH_T1
		* page: A8.8.237
		* range: no limit
		* preview: TBH.W [PC, R1, LSL #1]....
		*/
		TBH_THUMB32,

		/* VLDR<c> <Dd>, [<Rn>{, #+/-<imm>}] | VLDR<c> <Dd>, <label> | VLDR<c> <Dd>, [PC, #-0]
		* name: VLDR_T1
		* page: A8.8.334
		* range: -1020 to 1020(<label>) 0 to 1020(<imm>)
		* preview: <VLDR S0, [PC, #0]> <VLDR S0, dword_666666>....
		*/
		VLDR_THUMB32,

		/*******************ARM******************/

		/* B<c> <label>
		* name: B_A1
		* page: A8.8.18
		* range: Multiples of 4 in the range ¨C33554432 to 33554428
		* preview: <B loc_000006> <B loc_666666> <B loc_233333> <BNE loc_000006> <BEQ loc_666666> <BLT loc_233333>....
		*/
		B_ARM,
		BEQ_ARM,
		BNE_ARM,
		BCS_ARM,
		BCC_ARM,
		BMI_ARM,
		BPL_ARM,
		BVS_ARM,
		BVC_ARM,
		BHI_ARM,
		BLS_ARM,
		BGE_ARM,
		BLT_ARM,
		BGT_ARM,
		BLE_ARM,

		/* BX<c> <Rm>
		* name: BX_A1
		* page: A8.8.27
		* preview: <BX PC>
		*/
		BX_PC_ARM,

		/* BL<c> <label>
		* name: BL_A1
		* page: A8.8.25
		* range: Multiples of 4 in the range ¨C33554432 to 33554428
		* preview: <BL loc_000006> <BL loc_666666> <BL loc_233333> <BL func>....
		*/
		BL_ARM,

		/* BLX <label>
		* name: BLX_A2
		* page: A8.8.25
		* range: -33554432 to 33554430
		* preview: <BLX loc_000006> <BLX loc_666666> <BLX loc_233333> <BLX func>....
		*/
		BLX_ARM,

		/* ADD{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}
		* name: ADD_A1
		* page: A8.8.7
		* preview: <ADD R0,R1,R2> <ADD R0,PC,R1> <ADD R0,R1,PC>....
		*/
		ADD_ARM,

		/* ADD{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}
		* name: ADD_A1
		* page: A8.8.7
		* preview: <ADD PC, R0, R1>....
		*/
		ADD_PC_ARM,

		/* SUB{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}
		* name: SUB_A1
		* page: A8.8.224
		* preview: <SUB R0,R1,R2> <SUB R0,PC,R1> <SUB R0,R1,PC>....
		*/
		SUB_ARM,

		/* SUB{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}
		* name: SUB_A1
		* page: A8.8.224
		* preview: <SUB PC, R0, R1>....
		*/
		SUB_PC_ARM,

		/* ADR<c> <Rd>, <label> (after)
		* name: ADR_A1
		* page: A8.8.12
		* range: ???
		* preview: <ADR R1, dword_666666> <ADR R0, str>....
		*/
		ADR_AFTER_ARM,

		/* ADR<c> <Rd>, <label> (before)
		* name: ADR_A2
		* page: A8.8.12
		* range: ???
		* preview: <ADR R1, dword_666666> <ADR R0, str>....
		*/
		ADR_BEFORE_ARM,

		/* MOV{S}<c> <Rd>, <Rm>
		* name: MOV_A1
		* page: A8.8.105
		* preview: <MOV R0,PC> <MOV R1,PC>....
		*/
		MOV_ARM,

		/* MOV{S}<c> <Rd>, <Rm>
		* name: MOV_A1
		* page: A8.8.105
		* preview: <MOV PC,PC>
		*/
		MOV_PC_ARM,

		/* LDR<c> <Rt>, <label>
		* name: LDR_A1
		* page: A8.8.65
		* range: -4095 to 4095
		* preview: <LDR R0, =(xxxx_ptr - 0x123456)> <LDR R1, =(dword_233333 - 0x123456)> <LDR R2, =(unk_666666 - 0x123456)>....
		*/
		LDR_ARM,

		/* LDR<c> <Rt>, [PC, #-0]
		* name: LDR_A1
		* page: A8.8.65
		* range: no limit
		* preview: <LDR R0, [PC, #-0]> <LDR PC, [PC, #-0]>....
		*/
		LDR_PC_ARM,

		/* LDRB<c> <Rt>, <label> | LDRB<c> <Rt>, [PC, #-0]
		* name: LDRB_A1(literal)
		* page: A8.8.70
		* range: -4095 to 4095
		* preview: <LDRB R0, [PC, #0]> <LDRB R0, =(xxxx_ptr - 0x123456)>....
		*/
		LDRB_ARM,

		/* LDRD<c> <Rt>, <Rt2>, <label> | LDRD<c> <Rt>, <Rt2>, [PC, #-0]
		* name: LDRD_A1(literal)
		* page: A8.8.74
		* range: -255 to 255
		* preview: <LDRD R0, R1, [PC, #0]> <LDRD R0, R1, =(xxxx_ptr - 0x123456)>....
		*/
		LDRD_ARM,

		/* LDRH<c> <Rt>, <label> | LDRH<c> <Rt>, [PC, #-0]
		* name: LDRH_A1(literal)
		* page: A8.8.82
		* range: -255 to 255
		* preview: <LDRH R0, [PC, #0]> <LDRH R0, =(xxxx_ptr - 0x123456)>....
		*/
		LDRH_ARM,

		/* LDRSB<c> <Rt>, <label> | LDRSB<c> <Rt>, [PC, #-0]
		* name: LDRSB_A1(literal)
		* page: A8.8.86
		* range: -255 to 255
		* preview: <LDRSB R0, [PC, #0]> <LDRSB R0, =(xxxx_ptr - 0x123456)>....
		*/
		LDRSB_ARM,

		/* LDRSH<c> <Rt>, <label> | LDRSH<c> <Rt>, [PC, #-0]
		* name: LDRSH_A1(literal)
		* page: A8.8.90
		* range:  -255 to 255
		* preview: <LDRSH R0, [PC, #0]> <LDRSH R0, =(xxxx_ptr - 0x123456)>....
		*/
		LDRSH_ARM,

		/* LDR<c> <Rt>, [<Rn>,+/-<Rm>{, <shift>}]{!} | LDR<c> <Rt>, [<Rn>],+/-<Rm>{, <shift>}
		* name: LDR_A1
		* page: A8.8.67
		* preview: <LDR R0, [PC, R1]> <LDRNE R0, [PC, R1]> <LDR R0, [PC], R1> <LDREQ R0, [PC], R1>....
		*/
		LDR_REG_ARM,

		/* LDR<c> <Rt>, [<Rn>,+/-<Rm>{, <shift>}]{!} | LDR<c> <Rt>, [<Rn>],+/-<Rm>{, <shift>}
		* name: LDR_A1
		* page: A8.8.67
		* preview: <LDR PC, [PC, R1]> <LDRNE PC, [PC, R1]> <LDR PC, [PC], R1> <LDREQ PC, [PC], R1>....
		*/
		LDR_PC_REG_ARM,

		/* LDRB<c> <Rt>, [<Rn>,+/-<Rm>{, <shift>}]{!} | LDRB<c> <Rt>, [<Rn>],+/-<Rm>{, <shift>}
		* name: LDRB_A1(register)
		* page: A8.8.71
		* preview: <LDRB R0, [PC, R1]> <LDRBNE R0, [PC, R1]> <LDRB R0, [PC], R1> <LDRBEQ R0, [PC], R1>....
		*/
		LDRB_REG_ARM,

		/* LDRD<c> <Rt>, <Rt2>, [<Rn>,+/-<Rm>]{!} | LDRD<c> <Rt>, <Rt2>, [<Rn>],+/-<Rm>
		* name: LDRD_A1(register)
		* page: A8.8.75
		* preview: <LDRD R0, R1, [PC, R2]> <LDRDNE R0, R1, [PC, R2]> <LDRD R0, R1, [PC], R2> <LDRDEQ R0, R1, [PC], R2>....
		*/
		LDRD_REG_ARM,

		/* LDRH<c> <Rt>, [<Rn>,+/-<Rm>]{!} | LDRH<c> <Rt>, [<Rn>],+/-<Rm>
		* name: LDRH_A1(register)
		* page: A8.8.83
		* preview: <LDRH R0, [PC, R1]> <LDRHNE R0, [PC, R1]> <LDRH R0, [PC], R1> <LDRHEQ R0, [PC], R1>....
		*/
		LDRH_REG_ARM,

		/* LDRSB<c> <Rt>, [<Rn>,+/-<Rm>]{!} | LDRSB<c> <Rt>, [<Rn>],+/-<Rm>
		* name: LDRSB_A1(register)
		* page: A8.8.87
		* preview: <LDRSB R0, [PC, R1]> <LDRSBNE R0, [PC, R1]> <LDRSB R0, [PC], R1> <LDRSBEQ R0, [PC], R1>....
		*/
		LDRSB_REG_ARM,

		/* LDRSH<c> <Rt>, [<Rn>,+/-<Rm>]{!} | LDRSH<c> <Rt>, [<Rn>],+/-<Rm>
		* name: LDRSH_A1(register)
		* page: A8.8.91
		* preview: <LDRSH R0, [PC, R1]> <LDRSHNE R0, [PC, R1]> <LDRSH R0, [PC], R1> <LDRSHEQ R0, [PC], R1>....
		*/
		LDRSH_REG_ARM,

#elif __aarch64__

		/*******************ARM64******************/ //C3.1.1

		/* B <label> (not cond)
		* page: C6.2.25
		* range: +/-128MB
		* preview: <B loc_000006> <B loc_666666> <B loc_233333>....
		*/
		B_ARM64,

		/* B.<cond> <label> (see enum cond_type)
		* page: C6.2.26
		* range: +/-1MB
		* preview: <B.NE loc_000006> <B.EQ loc_666666> <B.LT loc_233333>....
		*/
		B_COND_ARM64,
		BEQ_ARM64,
		BNE_ARM64,
		BCS_ARM64,
		BCC_ARM64,
		BMI_ARM64,
		BPL_ARM64,
		BVS_ARM64,
		BVC_ARM64,
		BHI_ARM64,
		BLS_ARM64,
		BGE_ARM64,
		BLT_ARM64,
		BGT_ARM64,
		BLE_ARM64,

		/* BL <label>
		* page: C6.2.34
		* range: +/-128MB
		* preview: <BL loc_000006> <BL loc_666666> <BL loc_233333> <BL func>....
		*/
		BL_ARM64,

		/* ADR <Xd>, <label>
		* page: C6.2.10
		* range: +/-1MB
		* preview: <ADR X1, dword_666666> <ADR X0, str>....
		*/
		ADR_ARM64,

		/* ADRP <Xd>, <label>
		* page: C6.2.11
		* range: +/-4GB
		* preview: <ADRP X0, dword_666666> <ADRP X0, str>....
		*/
		ADRP_ARM64,

		/* LDR <Xt>, <label>
		* page: C6.2.167
		* range: +/-1MB
		* preview: <LDR X0, dword_666666> <LDR X0, str> ....
		*/
		LDR_ARM64,

		/* LDR <Wt>, <label>
		* page: C6.2.167
		* range: +/-1MB
		* preview: <LDR W0, dword_666666> <LDR W0, str> ....
		*/
		LDR_ARM64_32,

		/* LDRSW <Xt>, <label>
		* page: C6.2.179
		* range: +/-1MB
		* preview: <LDRSW X0, dword_666666> <LDRSW X0, str> ....
		*/
		LDRSW_ARM64,

		/* LDR <Dt>, <label>
		* page: C7.2.192
		* range: +/-1MB
		* preview: <LDR D0, dword_666666> <LDR D1, str> ....
		*/
		LDR_SIMD_ARM64,

		/* LDR <St>, <label>
		* page: C7.2.192
		* range: +/-1MB
		* preview: <LDR S0, dword_666666> <LDR S1, str> ....
		*/
		LDR_SIMD_ARM64_32,

		/* LDR <Qt>, <label> (LDR <Vt>, <label>)
		* page: C7.2.192
		* range: +/-1MB
		* preview: <LDR Q0, dword_666666> <LDR Q1, str> ....
		*/
		LDR_SIMD_ARM64_128,

		/* PRFM (<prfop>|#<imm5>), <label>
		* page: C6.2.248
		* range: +/-1MB
		* preview: <PRFM PLDL1KEEP [X0, dword_666666]> <PRFM PLDL2STRM [X0, dword_666666]> <PRFM PLIL3KEEP [X0, str]> <PRFM PSTL1STRM [X0, str]>....
		*/
		PRFM_ARM64,

		/* CBNZ <Xt>, <label> | CBNZ <Wt>, <label>
		* page: C6.2.46
		* range: +/-1MB
		* preview: <CBNZ X0, loc_123456> <CBNZ W0, loc_233333>....
		*/
		CBNZ_ARM64,

		/* CBZ <Wt>, <label> | CBZ <Xt>, <label>
		* page: C6.2.47
		* range: +/-1MB
		* preview: <CBZ X0, loc_123456> <CBZ W0, loc_233333>....
		*/
		CBZ_ARM64,

		/* TBNZ <R><t>, #<imm>, <label>
		* page: C6.2.374
		* range: +/-32KB
		* preview: <TBNZ X0, #0, loc_123456> <TBNZ X0, #4, loc_233333> <TBNZ W0, #4, loc_123456>....
		*/
		TBNZ_ARM64,

		/* TBZ <R><t>, #<imm>, <label>
		* page: C6.2.375
		* range: +/-32KB
		* preview: <TBZ X0, #0, loc_123456> <TBZ X0, #4, loc_233333> <TBZ W0, #4, loc_123456>....
		*/
		TBZ_ARM64,
#endif
	} i_type;

	static const struct nop_hex {
#ifdef __arm__
		static constexpr uint16_t T1 = 0xBF00; //NOP<c>
		static constexpr uint32_t T2 = 0x8000F3AF; //NOP<c>.W
		static constexpr uint32_t A1 = 0xE320F000; //NOP
#elif __aarch64__
		static constexpr uint32_t A64 = 0xD503201F; //NOP
#endif // __arm__
	} _NOP; //page: A8.8.120

	static const struct ret_hex {
#ifdef __arm__
		static constexpr uint16_t T1 = 0x4770; //BX LR
		static constexpr uint16_t T2 = 0x46F7; //MOV PC, LR
		static constexpr uint32_t A1 = 0xE12FFF1E; //BX LR
		static constexpr uint32_t A2 = 0xE1A0F00E; //MOV PC, LR
#elif __aarch64__
		static constexpr uint32_t A64_A1 = 0xD61F03C0; //BR X30(LR)
		static constexpr uint32_t A64_A2 = 0xD65F03C0; //RET
#endif
	} _RET;

	static const struct jump_hex {
#ifdef __arm__
		static constexpr uint32_t T1 = 0xF000F8DF; //LDR.W PC, [PC, #0]
		static constexpr uint32_t A1 = 0xE51FF004; //LDR PC, [PC, #-4]
#elif __aarch64__
		static constexpr uint32_t A64_A1[] =
		{
			0x58000051, //LDR X17, #8
			0xD61F0220, //BR X17

			0x58000040, //LDR REG, #8
			0xD61F0000, //BR REG
		};

		static constexpr uint32_t A64_A2[] =
		{
			0x90000000, //ADRP REG, dest
			0xD61F0000, //BR REG
		};
#endif
	} _JUMP;

#ifdef __arm__

	bool IsThumb32(uintptr_t addr);
	int CheckAbsoluteJump(uintptr_t addr);

	void MakeThumb16NOP(uintptr_t addr, size_t size);
	void MakeThumb32NOP(uintptr_t addr, size_t size);
	void MakeThumbRET(uintptr_t addr, uint8_t type);
	void MakeThumb16B(uintptr_t addr, uintptr_t dest);
	void MakeThumb16BCond(uintptr_t addr, uintptr_t dest, conds cond);
	void MakeThumb32B(uintptr_t addr, uintptr_t dest);
	void MakeThumb32BCond(uintptr_t addr, uintptr_t dest, conds cond);
	void MakeThumbBL(uintptr_t addr, uintptr_t func);
	void MakeThumbBLX(uintptr_t addr, uintptr_t func);
	void MakeThumbCB(uintptr_t addr, uintptr_t dest, uint8_t reg, bool is_cbnz);
	int8_t MakeThumbAbsoluteJump(uintptr_t addr, uintptr_t dest);

	uintptr_t GetThumb16BranchDestination(uintptr_t addr);
	uintptr_t GetThumb32BranchDestination(uintptr_t addr);

	i_type GetThumb16CondInstType(uintptr_t addr);
	i_type GetThumb32CondInstType(uintptr_t addr);
	i_type GetThumb16InstType(uintptr_t addr);
	i_type GetThumb32InstType(uintptr_t addr);

	void MakeArmNOP(uintptr_t addr, size_t size);
	void MakeArmRET(uintptr_t addr, uint8_t type);
	void MakeArmB(uintptr_t addr, uintptr_t dest);
	void MakeArmBCond(uintptr_t addr, uintptr_t dest, conds cond);
	void MakeArmBL(uintptr_t addr, uintptr_t func);
	void MakeArmBLX(uintptr_t addr, uintptr_t func);
	int8_t MakeArmAbsoluteJump(uintptr_t addr, uintptr_t dest);

	uintptr_t GetArmBranchDestination(uintptr_t addr);

	i_type GetArmCondInstType(uintptr_t addr);
	i_type GetArmInstType(uintptr_t addr);

#elif __aarch64__

	void MakeArm64NOP(uintptr_t addr, size_t size);
	void MakeArm64RET(uintptr_t addr, uint8_t type);
	void MakeArm64B(uintptr_t addr, uintptr_t dest);
	void MakeArm64BCond(uintptr_t addr, uintptr_t dest, conds cond);
	void MakeArm64BL(uintptr_t addr, uintptr_t func);
	void MakeArm64CB(uintptr_t addr, uintptr_t dest, uint8_t reg, bool is_cbnz, bool is64reg);
	int8_t MakeArm64AbsoluteJump(uintptr_t addr, uintptr_t dest, REG::ARM64 reg = REG::ARM64::X17);
	int8_t MakeArm64AbsoluteJump32(uintptr_t addr, uintptr_t dest, REG::ARM64 reg = REG::ARM64::X17);

	uintptr_t GetArm64BranchDestination(uintptr_t addr);

	i_type GetArm64CondInstType(uintptr_t addr);
	i_type GetArm64InstructionType(uintptr_t addr);

#endif


}


#endif
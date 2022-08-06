#pragma once

#ifdef __arm__
#define GetArmPC(addr) (addr + 8)
#elif __aarch64__
#define GetArmPC(addr) (addr + 4)
#endif

#define GetThumbPC(addr) (addr + 4)


enum eInstructionSet
{
	SET_UNDEFINED,
	SET_ARM,
	SET_THUMB,
};

namespace REG {
#ifdef __arm__
	//enum thumb_reg { R0, R1, R2, R3, R4, R5, R6, R7, SP = 13, LR, PC };
	enum arm_reg { R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, SP, LR, PC };
#elif __aarch64__
	enum arm64_32 { W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14, W15, W16, W17, W18, W19, W20, W21, W22, W23, W24, W25, W26, W27, W28, W29, W30 };
	enum arm64_64 { X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, X16, X17, X18, X19, X20, X21, X22, X23, X24, X25, X26, X27, X28, FP, LR, SP };
#endif
}


enum cond_type //IT_THUMB16 || B_COND_THUMB16 || BW_COND_THUMB32 || B_ARM
{
	EQ,//0000
	NE,//0001
	CS,//0010
	HS = 2,
	CC,//0011
	LO = 3,
	MI,//0100
	PL,//0101
	VS,//0110
	VC,//0111
	HI,//1000
	LS,//1001
	GE,//1010
	LT,//1011
	GT,//1100
	LE,//1101
	AL,//1110  no cond(see B_THUMB16), AL is an optional mnemonic extension for always, except in IT instructions
	BNV,//1111  ???
};

enum InstructionType
{
	UNDEFINE,

	/*******************THUMB16******************/

	/* IT <cond> (see enum cond_type)
	* preview: <IT EQ> <ITT NE> <ITTT MI>....
	*/
	IT_THUMB16,

	/* Bxx <label> (see enum cond_type)
	* preview: { <BNE loc_000006> <BEQ loc_666666> <BLT loc_233333>.... }
	*/
	B_COND_THUMB16,

	/* B <label> (not cond)
	* preview: <B loc_000006> <B loc_666666> <B loc_233333>....
	*/
	B_THUMB16,

	/* BX <reg>
	* preview: <BX PC> <BX LR> <BX R1>....
	*/
	BX_THUMB16,

	/* ADD <reg>, PC
	* preview: <ADD R0,PC> <ADD R1,PC>....
	*/
	ADD_PC_THUMB16,

	/* MOV <reg>, <reg>
	* preview: <MOV R0,R1> <MOV R4,R8>....
	*/
	MOV_REG_THUMB16,

	/* ADR <reg>, <label>
	* preview: <ADR R1, dword_666666> <ADR R0, str>....
	*/
	ADR_THUMB16,

	/* LDR <reg>, <label>
	* preview: <LDR R0, =(xxxx_ptr - 0x123456)> <LDR R1, =(dword_233333 - 0x123456)> <LDR R2, =(unk_666666 - 0x123456)>....
	*/
	LDR_THUMB16,

	/* LDR <reg>, <reg...>
	* preview: <LDR R2, [R0]> <LDR R0, [R0,#0x10]> <LDR R1, [R5,#0x2C]> <LDR R2, [R0,R1]> <LDR R0, [SP,#0x58+var_48]>....
	*/
	LDR_REG_THUMB16,

	/* CBZ <reg>, <label>
	* preview: <CBZ R0, loc_123456> <CBZ R4, loc_233333>....
	*/
	CBZ_THUMB16,

	/* CBNZ <reg>, <label>
	* preview: <CBNZ R0, loc_123456> <CBNZ R4, loc_233333>....
	*/
	CBNZ_THUMB16,

	/* ADDS <reg>, #num || ADDS <reg>, <reg>, #num || ADDS <reg>, <reg>, <reg>
	* preview: <ADDS R0, #1> <ADDS R1, R2, #4> <ADDS R0, R5, R4>....
	*/
	ADDS_THUMB16,

	/* MOVS <reg>, #num
	* preview: <MOVS R3, #0> <MOVS R6, #0xFF>....
	*/
	MOVS_THUMB16,

	/* ADD <reg>, SP, #num
	* preview: <ADD R7, SP, #8> <ADD SP, SP, #8> <ADD R0, SP, #0x100+var_200>....
	*/
	ADD_REG_THUMB16,

	/*******************THUMB32******************/

	/* Bxx.W <label> (see enum cond_type)
	* preview: { <BNE.W loc_000006> <BEQ.W loc_666666> <BLT.W loc_233333>.... }
	*/
	BW_COND_THUMB32,

	/* B.W <label> (not cond)
	* preview: <B.W loc_000006> <B.W loc_666666> <B.W loc_233333> <B.W func>....
	*/
	BW_THUMB32,

	/* BL <label>
	* preview: <BL loc_000006> <BL loc_666666> <BL loc_233333> <BL func>....
	*/
	BL_THUMB32,

	/* BLX <label>
	* preview: <BLX loc_000006> <BLX loc_666666> <BLX loc_233333> <BLX func>....
	*/
	BLX_THUMB32,

	/* LDR.W <reg>, <label>
	* preview: <LDR.W R0, =(xxxx_ptr - 0x123456)> <LDR.W R1, =(dword_233333 - 0x123456)> <LDR.W R2, =(unk_666666 - 0x123456)>....
	*/
	LDRW_THUMB32,

	/*******************ARM******************/

	/* B <label> || Bxx <label> (see enum cond_type)
	* preview: <B loc_000006> <B loc_666666> <B loc_233333> <BNE loc_000006> <BEQ loc_666666> <BLT loc_233333>....
	*/
	B_ARM,

	/* BX <reg>
	* preview: <BX PC> <BX LR> <BX R1>....
	*/
	BX_ARM,

	/* BL <label>
	* preview: <BL loc_000006> <BL loc_666666> <BL loc_233333> <BL func>....
	*/
	BL_ARM,

	/* BLX <label>
	* preview: <BLX loc_000006> <BLX loc_666666> <BLX loc_233333> <BLX func>....
	*/
	BLX_ARM,

	/* LDR <reg>, <label>
	* preview: <LDR R0, =(xxxx_ptr - 0x123456)> <LDR R1, =(dword_233333 - 0x123456)> <LDR R2, =(unk_666666 - 0x123456)>....
	*/
	LDR_ARM,

};
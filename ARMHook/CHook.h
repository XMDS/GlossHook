#pragma once
#include <vector>
#include <sys/mman.h>

struct bytePattern
{
	struct byteEntry
	{
		uint8_t nValue;
		bool bUnknown;
	};
	std::vector<byteEntry> vBytes;
};

enum thumb_reg { R0, R1, R2, R3, R4, R5, R6, R7 };

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

namespace ARMHook
{
	class CHook
	{
	public:
		static uintptr_t GetLibraryAddress(const char* library);
		static uintptr_t GetLibraryLength(const char* library);
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

		static uintptr_t InitialiseTrampolines(uintptr_t addr, size_t size);
		static void ReplaceThumbCall(uintptr_t addr, uintptr_t func);
		static void ReplaceArmCall(uintptr_t addr, uintptr_t func);
		static void HookThumbFunc(void* func, uint32_t startSize, void* func_to, void** func_orig);
		static void HookArmFunc(void* func, uint32_t startSize, void* func_to, void** func_orig);
	};	
}
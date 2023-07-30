#ifndef __GLOSSHOOK_INST_H__
#define __GLOSSHOOK_INST_H__

#include "Gloss.h"

namespace Gloss {

	namespace Inst {
		
		enum class conds { EQ, NE, CS, HS = CS, CC, LO = CC, MI, PL, VS, VC, HI, LS, GE, LT, GT, LE, AL, NV, MAX_COND };
		
		const int CheckAbsoluteJump(uintptr_t addr);
		const int CheckRelativeJump(uintptr_t addr);

#ifdef __arm__

		bool IsThumb32(uint32_t addr);
		int GetThumb32Count(uint32_t addr) noexcept;

		void MakeThumb16NOP(uint32_t addr, size_t size);
		void MakeThumb32NOP(uint32_t addr, size_t size);
		void MakeThumbRET(uint32_t addr, uint8_t type);

		const uint16_t MakeThumb16B(uint32_t addr, uint32_t dest);
		const uint16_t MakeThumb16BCond(uint32_t addr, uint32_t dest, conds cond);
		const uint32_t MakeThumb32B(uint32_t addr, uint32_t dest);
		const uint32_t MakeThumb32BCond(uint32_t addr, uint32_t dest, conds cond);
		const uint32_t MakeThumbBL(uint32_t addr, uint32_t func);
		const uint32_t MakeThumbBL_W(uint32_t addr, uint32_t func);
		const uint32_t MakeThumbBLX(uint32_t addr, uint32_t func);
		const uint32_t MakeThumbBLX_W(uint32_t addr, uint32_t func);
		const uint16_t MakeThumbCB(uint32_t addr, uint32_t dest, gloss_reg::e_reg reg, bool is_cbnz);
		int8_t MakeThumbAbsoluteJump(uint32_t addr, uint32_t dest);

		uint32_t GetThumb16BranchDestination(uint32_t addr);
		uint32_t GetThumb32BranchDestination(uint32_t addr);

		void MakeArmNOP(uint32_t addr, size_t size);
		void MakeArmRET(uint32_t addr, uint8_t type);

		const uint32_t MakeArmB(uint32_t addr, uint32_t dest, conds cond = conds::AL);
		const uint32_t MakeArmBL(uint32_t addr, uint32_t func, conds cond = conds::AL);
		const uint32_t MakeArmBLX(uint32_t addr, uint32_t func);
		int8_t MakeArmAbsoluteJump(uint32_t addr, uint32_t dest);

		uint32_t GetArmBranchDestination(uint32_t addr);

#elif __aarch64__

		void MakeArm64NOP(uint64_t addr, size_t size);
		void MakeArm64RET(uint64_t addr, uint8_t type);
		const uint32_t MakeArm64B(uint64_t addr, uint64_t dest);
		const uint32_t MakeArm64BCond(uint64_t addr, uint64_t dest, conds cond);
		const uint32_t MakeArm64BL(uint64_t addr, uint64_t func);
		const uint32_t MakeArm64CB(uint64_t addr, uint64_t dest, uint8_t reg, bool is_cbnz, bool is64);
		int8_t MakeArm64AbsoluteJump(uint64_t addr, uint64_t dest, gloss_reg::e_reg reg = gloss_reg::e_reg::X17);
		int8_t MakeArm64AbsoluteJump32(uint64_t addr, uint64_t dest, gloss_reg::e_reg reg = gloss_reg::e_reg::X17);

		uint64_t GetArm64BranchDestination(uint64_t addr);

#endif // __arm__

		
	}
}
#endif // !__GLOSSHOOK_INST_H__






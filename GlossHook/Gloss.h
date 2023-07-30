#ifndef __GLOSSHOOK_H__
#define __GLOSSHOOK_H__

#ifndef __ANDROID__
#error error GlossHook only support android
#else
#if !(defined __arm__) && !(defined __aarch64__)
#error error GlossHook only support arm and arm64
#endif
#endif // __ANDROID__

#ifdef __cplusplus
extern "C" {
#endif                                           

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#ifdef __arm__
#define GET_INST_SET(addr) (addr & 1 ? i_set::$THUMB : i_set::$ARM)
#define INST_SET i_set mode = $THUMB
#elif __aarch64__
#define INST_SET i_set mode = $ARM64
#endif

	typedef enum { NONE, $THUMB, $ARM, $ARM64 } i_set; //InstructionSet
	typedef void* gloss_lib;
	typedef struct PermissionFlags
	{
		int8_t bRead : 1;
		int8_t bWrite : 1;
		int8_t bExecute : 1;
		int8_t bPrivate : 1;
		int8_t bShared : 1;
		int8_t align : 3;
	} p_flag;


	union gloss_reg
	{
#ifdef __arm__
		enum e_reg { R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, R12, R13, SP = R13, R14, LR = R14, R15, PC = R15, CPSR };

		uint32_t reg[17];
		struct { uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, sp, lr, pc, cpsr; } regs;
#elif __aarch64__
		enum e_reg {
			X0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, X16, X17, X18, X19, X20, X21, X22, X23, X24, X25, X26, X27, X28, X29, FP = X29,
			Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7, Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15, Q16, Q17, Q18, Q19, Q20, Q21, Q22, Q23, Q24, Q25, Q26, Q27, Q28, Q29, Q30, Q31,
			X30, LR = X30, X31, SP = X31, PC, CPSR
		};

		uint64_t reg[66];
		struct {
			uint64_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29;
			double q0, q1, q2, q3, q4, q5, q6, q7, q8, q9, q10, q11, q12, q13, q14, q15, q16, q17, q18, q19, q20, q21, q22, q23, q24, q25, q26, q27, q28, q29, q30, q31;
			uint64_t lr, sp, pc, cpsr;
		} regs;
#endif // __arm__
	};

	// library
	uintptr_t GlossGetLibBase(const char* libName, pid_t pid = -1);
	
	size_t GlossGetLibLength(const char* libName, pid_t pid = -1);
	uintptr_t GlossGetLibBias(const char* libName);
	uintptr_t GlossGetLibBiasEx(gloss_lib handle);

	gloss_lib GlossOpen(const char* libName);
	int GlossClose(gloss_lib handle, bool is_dlclose = false);

	const char* GlossGetLibPath(gloss_lib handle);
	const char* GlossGetLibPathEx(uintptr_t libAddr);
	size_t GlossGetLibFileSize(const char* libName);

	uintptr_t GlossSymbol(gloss_lib handle, const char* name, size_t* sym_size);
	uintptr_t GlossSymbolEx(uintptr_t libAddr, const char* name, size_t* sym_size);
	const char* GlossAddrInfo(uintptr_t sym_addr, size_t* sym_size);

	const char* GlossGetLibMachine(const char* libName);
	const int GlossGetLibBit(const char* libName);

	// memory
	bool SetMemoryPermission(uintptr_t addr, size_t len, p_flag* type);
	inline bool Unprotect(uintptr_t addr, size_t len = PAGE_SIZE)
	{
		return SetMemoryPermission(addr, len, NULL);
	}

	bool GetMemoryPermission(uintptr_t addr, p_flag* type, pid_t pid = -1);
	inline bool IsAddrExecute(uintptr_t addr)
	{
		p_flag type{0,0,0};
		GetMemoryPermission(addr, &type);
		return type.bExecute;
	}
	
	void WriteMemory(void* addr, void* data, size_t size, bool vp = true);
	void* ReadMemory(void* addr, void* data, size_t size, bool vp = true);
	void MemoryFill(void* addr, uint8_t value, size_t size, bool vp = true);
	
	// inline hook
	void* GlossHook(void* sym_addr, void* new_func, void** old_func);
	typedef void (*GlossHookExCallback)(void* hook);
	void* GlossHookEx(const char* lib_name, const char* sym_name, void* new_func, void** old_func, GlossHookExCallback call_back_func);
	
	void* GlossHookAddr(void* func_addr, void* new_func, void** old_func, bool is_short_func, INST_SET);
	
	void* GlossHookBranchB(void* branch_addr, void* new_func, void** old_func, INST_SET);
	void* GlossHookBranchBL(void* branch_addr, void* new_func, void** old_func, INST_SET);
#ifdef __arm__
	void* GlossHookBranchBLX(void* branch_addr, void* new_func, void** old_func, INST_SET);
#endif // __arm__

	typedef void (*GlossHookPatchCallback)(gloss_reg* regs, void* hook);
	void* GlossHookPatch(void* patch_addr, GlossHookPatchCallback new_func, bool is_short_func, INST_SET);

	void* GlossHookRedirect(void* redirect_addr, void* new_addr, INST_SET);

	// got hook
	void* GlossGotHook(void* got_addr, void* new_func, void** old_func);

	typedef void (*GlossGotHookExCallback)(void* hook);
	void* GlossGotHookEx(const char* lib_name, const char* sym_name, void* new_func, void** old_func, GlossGotHookExCallback call_back_func);
	
	
	void GlossHookDisable(void* hook);
	void GlossHookEnable(void* hook);
	void GlossHookDelete(void* hook);
	void GlossHookDisableAll(void* addr, INST_SET);
	void GlossHookEnableAll(void* addr, INST_SET);
	void GlossHookDeleteAll(void* addr, INST_SET);

	int GlossHookGetCount(void* hook);
	int GlossHookGetTotalCount(void* addr, INST_SET);

	void* GlossHookGetPtr(void* addr, INST_SET);
	void* GlossHookGetPtrEx(void* addr, int count, INST_SET);
	int GlossHookGetStatus(void* hook);
	void* GlossHookGetPrev(void* hook);
	void* GlossHookGetNext(void* hook);

	void GlossHookSetNewFunc(void* hook, void* new_func);

#ifdef __cplusplus
}
	/*
	* Write any type of value to memory.
	*/
	template <typename T1>
	inline static void WriteMemory(uintptr_t addr, T1 value, bool vp = true)
	{
		WriteMemory((void*)addr, &value, sizeof(T1), vp);
	}

	/*
	* Read any type of value from memory.
	*/
	template <typename T1>
	inline static T1 ReadMemory(uintptr_t addr, bool vp = true)
	{
		if (vp) Unprotect((uintptr_t)addr, sizeof(T1));
		return *reinterpret_cast<T1*>(addr);
	}

	/*
	* GOTHook template, complete type conversion.
	*/
	template <class A, class B, class C>
	inline static void* GOTHook(A addr, B func, C original)
	{
		return GlossGotHook(reinterpret_cast<void*>(addr), reinterpret_cast<void*>(func), reinterpret_cast<void**>(original));
	}
	template <class A, class B>
	inline static void* GOTHook(A addr, B func)
	{
		return GlossGotHook(reinterpret_cast<void*>(addr), reinterpret_cast<void*>(func), NULL);
	}

	/*
	* InlineHook template, complete type conversion.
	*/
	template <class A, class B, class C>
	inline static void* InlineHook(A addr, B func, C original)
	{
		return GlossHook(reinterpret_cast<void*>(addr), reinterpret_cast<void*>(func), reinterpret_cast<void**>(original));
	}
	template <class A, class B>
	inline static void* InlineHook(A addr, B func)
	{
		return GlossHook(reinterpret_cast<void*>(addr), reinterpret_cast<void*>(func), NULL);
	}
#endif
#endif
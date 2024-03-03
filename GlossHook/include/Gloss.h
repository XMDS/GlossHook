#ifndef __GLOSSHOOK_H__
#define __GLOSSHOOK_H__

#ifndef __ANDROID__
#error GlossHook only support android
#else
#if !(defined __arm__) && !(defined __aarch64__)
#error GlossHook only support arm and arm64
#endif
#endif // __ANDROID__

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h> 

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __arm__
#define GET_INST_SET(addr) (addr & 1 ? i_set::$THUMB : i_set::$ARM)
#endif // __arm__

	typedef enum { $NONE = 0, $THUMB, $ARM, $ARM64 } i_set; //InstructionSet
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

	typedef struct
	{
#ifdef __arm__
		enum e_reg { R0 = 0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10, R11, FP = R11, R12, IP = R12, R13, SP = R13, R14, LR = R14, R15, PC = R15, CPSR };

		union {
			uint32_t reg[17];
			struct { uint32_t r0, r1, r2, r3, r4, r5, r6, r7, r8, r9, r10, r11, r12, sp, lr, pc, cpsr; } regs;
		};
#elif __aarch64__
		enum e_reg {
			X0 = 0, X1, X2, X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, X16, X17, X18, X19, X20, X21, X22, X23, X24, X25, X26, X27, X28, X29, FP = X29,
			Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7, Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15, Q16, Q17, Q18, Q19, Q20, Q21, Q22, Q23, Q24, Q25, Q26, Q27, Q28, Q29, Q30, Q31,
			X30, LR = X30, X31, SP = X31, PC, CPSR
		};

		union {
			uint64_t reg[66];
			struct {
				uint64_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29;
				double q0, q1, q2, q3, q4, q5, q6, q7, q8, q9, q10, q11, q12, q13, q14, q15, q16, q17, q18, q19, q20, q21, q22, q23, q24, q25, q26, q27, q28, q29, q30, q31;
				uint64_t lr, sp, pc, cpsr;
			} regs;
		};
#endif // __arm__
	} gloss_reg;

	// library
	uintptr_t GlossGetLibInfo(const char* lib_name, pid_t pid, char* lib_path, size_t* lib_mem_len);

	gloss_lib GlossOpen(const char* lib_name);
	int GlossClose(gloss_lib handle, bool is_dlclose);

	uintptr_t GlossGetLibBias(const char* lib_name);
	uintptr_t GlossGetLibBiasEx(gloss_lib handle);

	const char* GlossGetLibPath(gloss_lib handle);
	bool GlossGetLibPathEx(uintptr_t lib_addr, char* path);
	size_t GlossGetLibFileSize(const char* lib_name);

	uintptr_t GlossSymbol(gloss_lib handle, const char* name, size_t* sym_size);
	uintptr_t GlossSymbolEx(uintptr_t lib_addr, const char* name, size_t* sym_size);
	bool GlossAddr(uintptr_t lib_addr, uintptr_t* sym_addr, size_t* sym_size, char* sym_name);

	const char* GlossGetLibMachine(const char* libName);
	const int GlossGetLibBit(const char* libName);

	uintptr_t GlossGetLibSection(const char* libName, const char* sec_name, size_t* sec_size);
	uintptr_t GlossGetLibSegment(const char* libName, unsigned int seg_type, size_t* seg_size);

	// memory
	bool SetMemoryPermission(uintptr_t addr, size_t len, p_flag* type);
	inline bool Unprotect(uintptr_t addr, size_t len)
	{
		return SetMemoryPermission(addr, len, NULL);
	}

	bool GetMemoryPermission(uintptr_t addr, p_flag* type, pid_t pid, const char* lib_name);
	inline bool IsAddrExecute(uintptr_t addr)
	{
		p_flag type = { 0,0,0 };
		GetMemoryPermission(addr, &type, -1, NULL);
		return type.bExecute;
	}

	void WriteMemory(void* addr, void* data, size_t size, bool vp);
	void* ReadMemory(void* addr, void* data, size_t size, bool vp);
	void MemoryFill(void* addr, uint8_t value, size_t size, bool vp);

	// inline hook function head
	void* GlossHook(void* sym_addr, void* new_func, void** old_func);
	void* GlossHookAddr(void* func_addr, void* new_func, void** old_func, bool is_4_byte_hook, i_set mode);

	// inline hook branch B/BL/BLX
	void* GlossHookBranchB(void* branch_addr, void* new_func, void** old_func, i_set mode);
	void* GlossHookBranchBL(void* branch_addr, void* new_func, void** old_func, i_set mode);
#ifdef __arm__
	void* GlossHookBranchBLX(void* branch_addr, void* new_func, void** old_func, i_set mode);
#endif // __arm__

	// inline hook internal any position
	typedef void (*GlossHookInternalCallback)(gloss_reg* regs, void* hook);
	void* GlossHookInternal(void* addr, GlossHookInternalCallback new_func, bool is_4_byte_hook, i_set mode);

	// inline hook redirect code
	void* GlossHookRedirect(void* redirect_addr, void* new_addr, bool is_4_byte_hook, i_set mode);

	// got hook
	void* GlossGotHook(void* got_addr, void* new_func, void** old_func);

	// linker hook
	// support function: dlopen, dlsym, other linker(libdl) function
	union GlossLinkerFuncProxy
	{
		struct GlossDlopenProxy
		{
			// API Level 23 (Android 6.0) and below
			void* (*dlopen)(const char* filename, int flags);
			void** orig_dlopen;
			// API Level 21 - 23 (Android 5.x - 6.0) Only
			void* (*android_dlopen_ext)(const char* filename, int flags, const void* extinfo);
			void** orig_android_dlopen_ext;

			// API Level 24 - 25 (Android 7.x)
			void* (*do_dlopen_n)(const char* name, int flags, const void* extinfo, void* caller_addr);
			void** orig_do_dlopen_n;

			// API Level 26 - 27 (Android 8.x)
			void* (*do_dlopen_o)(const char* name, int flags, const void* extinfo, const void* caller_addr);
			void** orig_do_dlopen_o;

			// API Level 28 (Android 9.0) and above
			void* (*__loader_dlopen)(const char* filename, int flags, const void* caller_addr);
			void* (*__loader_android_dlopen_ext)(const char* filename, int flags, const void* extinfo, const void* caller_addr);
			void** orig__loader_dlopen;
			void** orig__loader_android_dlopen_ext;
		} DlopenProxy;

		struct GlossDlsymProxy
		{
			// API Level 23 (Android 6.0) and below
			void* (*dlsym)(void* handle, const char* symbol);
			void** orig_dlsym;

			// API Level 24 - 25 (Android 7.x)
			bool (*do_dlsym)(void* handle, const char* sym_name, const char* sym_ver, void* caller_addr, void** symbol);
			void** orig_do_dlsym;

			// API Level 26 (Android 8.0) and above
			void* (*__loader_dlsym)(void* handle, const char* symbol, const void* caller_addr);
			void* (*__loader_dlvsym)(void* handle, const char* symbol, const char* version, const void* caller_addr);
			void** orig__loader_dlsym;
			void** orig__loader_dlvsym;
		} DlsymProxy;

		// Other Linker Function
		struct GlossFuncProxy
		{
			void* linker_func;
			void** orig_linker_func;
		} FuncProxy;
	};
	// dlfuc: dlopen, dlsym, and symbol name
	// new_dlfunc: see GlossLinkerFuncProxy
	// hook: return hook pointer (__loader_dlopen, __loader_dlsym)
	// hook2: return hook2 pointer （__loader_android_dlopen_ext, __loader_dlvsym）
	bool GlossLinkerHook(const char* dlfunc, GlossLinkerFuncProxy new_dlfunc, void** hook, void** hook2);

	// pre inline/got hook
	typedef void (*GlossHookCallback)(void* hook);
	void* GlossHookEx(const char* lib_name, const char* sym_name, void* new_func, void** old_func, GlossHookCallback call_back_func);
	void* GlossGotHookEx(const char* lib_name, const char* sym_name, void* new_func, void** old_func, GlossHookCallback call_back_func);

	// pre inline hook .init_array/.init / hook constructor
	void* GlossHookConstructor(const char* lib_name, void* offset_addr, void* new_func, void** old_func, bool is_4_byte_hook, i_set mode, GlossHookCallback call_back_func);

	// Disable/Enable/Delete
	void GlossHookDisable(void* hook);
	void GlossHookEnable(void* hook);
	void GlossHookDelete(void* hook);
	void GlossHookDisableAll(void* addr, i_set mode);
	void GlossHookEnableAll(void* addr, i_set mode);
	void GlossHookDeleteAll(void* addr, i_set mode);

	// other func
	int GlossHookGetCount(void* hook);
	int GlossHookGetTotalCount(void* addr, i_set mode);

	void* GlossHookGetPtr(void* addr, i_set mode);
	void* GlossHookGetPtrEx(void* addr, int count, i_set mode);
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
		if (vp) Unprotect(addr, sizeof(T1));
		return *reinterpret_cast<T1*>(addr);
	}

	/*
	* GOTHook template, complete type conversion.
	*/
	template <class A, class B, class C>
	inline static void* GotHook(A addr, B func, C original)
	{
		return GlossGotHook(reinterpret_cast<void*>(addr), reinterpret_cast<void*>(func), reinterpret_cast<void**>(original));
	}
	template <class A, class B>
	inline static void* GotHook(A addr, B func)
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

//GlossHook Inst.h
#ifndef __GLOSSHOOK_INST_H__
#define __GLOSSHOOK_INST_H__

#ifdef __arm__
#define GLOSS_WRITE_T32(addr, inst) \
		do { \
		Gloss::Inst::WriteByte((uintptr_t)addr, []() __attribute__((target("thumb"))) {  \
			__asm volatile (".thumb\n" inst "\n"); }, sizeof(uint32_t)); \
		} while (0)

#define GLOSS_WRITE_T16(addr, inst) \
		do { \
		Gloss::Inst::WriteByte((uintptr_t)addr, []() __attribute__((target("thumb"))) {  \
			__asm volatile (".thumb\n" inst "\n"); }, sizeof(uint16_t)); \
		} while (0)

#define GLOSS_WRITE_A32(addr, inst) \
		do { \
		Gloss::Inst::WriteByte((uintptr_t)addr, []() __attribute__((target("arm"))) {  \
			__asm volatile (".arm\n" inst "\n"); }, sizeof(uint32_t)); \
		} while (0)
#elif __aarch64__
#define GLOSS_WRITE_A64(addr, inst) \
		do { \
		Gloss::Inst::WriteByte((uintptr_t)addr, []() __attribute__((target("aarch64"))) {  \
			__asm volatile (".arm64\n" inst "\n"); }, sizeof(uint32_t)); \
		} while (0)
#endif // __arm__

	namespace Gloss {

		namespace Inst {

			enum class conds { EQ, NE, CS, HS = CS, CC, LO = CC, MI, PL, VS, VC, HI, LS, GE, LT, GT, LE, AL, NV, MAX_COND };

			const int CheckAbsoluteJump(uintptr_t addr);
			const int CheckRelativeJump(uintptr_t addr);

			enum class branchs { B_COND16, B_COND, B_16, B, BL, BLX, MAX_BRANCH };
			const branchs GetBranch(uintptr_t addr, i_set mode);

#ifdef __arm__

			bool IsThumb32(uint32_t addr);

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
			int8_t MakeArm64AbsoluteJumpRet(uint64_t addr, uint64_t dest, gloss_reg::e_reg reg = gloss_reg::e_reg::X17);

			uint64_t GetArm64BranchDestination(uint64_t addr);

#endif // __arm__

			const int WriteByte(uintptr_t addr, void (*inst_func)(), size_t len);
		}
	}
#endif // !__GLOSSHOOK_INST_H__
#endif // !__cplusplus
#endif // !__GLOSSHOOK_H__
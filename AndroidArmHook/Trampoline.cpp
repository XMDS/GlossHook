#include "Trampoline.h"
#include "AndroidArmHook.h"

__attribute__((section(".text"))) __attribute__((visibility("hidden"))) extern void* thumb_trampoline_manage_func_end;
__attribute__((section(".text"))) __attribute__((target("thumb")))
__attribute__((naked)) static void thumb_trampoline_manage_func()
{
	asm(
		".thumb                                   \n"
		".hidden thumb_trampoline_manage_func_end \n"

		"PUSH     {R0}	                          \n"
		"LDR      IP, inline_hook_info_t          \n"
		"LDR      R0, [IP, #0x4]                  \n"
		"CBZ      R0, loc_thumb_02                \n"//等于0则跳转
		"POP      {R0}                            \n"
		"LDR      PC, [IP, #0xC]                  \n"

		"loc_thumb_02:                            \n"
		"POP      {R0}                            \n"
		"LDR      PC, [IP, #0x10]                 \n"
		
		"inline_hook_info_t:"
		".word 0x123;"

		"thumb_trampoline_manage_func_end:"
		".global thumb_trampoline_manage_func_end;"
	);
}


__attribute__((section(".text"))) __attribute__((visibility("hidden"))) extern void* arm_trampoline_manage_func_end;
__attribute__((section(".text"))) __attribute__((target("no-thumb-mode")))
__attribute__((naked)) static void arm_trampoline_manage_func()
{
	asm(
		".arm                                     \n"
		".hidden arm_trampoline_manage_func_end   \n"

		"PUSH     {R0}	                          \n"
		"LDR      IP, inline_hook_info_a          \n"
		"LDR      R0, [IP, #0x4]                  \n"
		"CMP      R0, #0                          \n"
		"BEQ      loc_arm_02                      \n"//R0 = 0则跳转
		"POP      {R0}                            \n"
		"LDR      PC, [IP, #0xC]                  \n"

		"loc_arm_02:                              \n"
		"POP      {R0}                            \n"
		"LDR      PC, [IP, #0x10]                 \n"

		"inline_hook_info_a:"
		".word 0x456;"

		"arm_trampoline_manage_func_end:"
		".global arm_trampoline_manage_func_end;"
	);
}

uint8_t ThumbTrampolineManageFuncSize = ((uintptr_t)&thumb_trampoline_manage_func_end) - CLEAR_BIT0((uintptr_t)thumb_trampoline_manage_func);
uint8_t ArmTrampolineManageFuncSize = ((uintptr_t)&arm_trampoline_manage_func_end) - (uintptr_t)arm_trampoline_manage_func;


uint8_t MakeThumbTrampolineManageFunc(InlineHookInfo* info)
{
	uintptr_t func_addr = CLEAR_BIT0((uintptr_t)thumb_trampoline_manage_func);
	uint8_t func_size = ThumbTrampolineManageFuncSize;
	ReadMemory((void*)func_addr, info->trampoline_func, func_size, false);

	uintptr_t trampoline_func_end_addr = (uintptr_t)info->trampoline_func + func_size;
	uintptr_t trampoline_inline_hook_info_ptr = trampoline_func_end_addr - 4;
	WriteMemory<InlineHookInfo*>(trampoline_inline_hook_info_ptr, info);

	return func_size;
}

uint8_t MakeArmTrampolineManageFunc(InlineHookInfo* info)
{
	uintptr_t func_addr = (uintptr_t)arm_trampoline_manage_func;
	uint8_t func_size = ArmTrampolineManageFuncSize;
	ReadMemory((void*)func_addr, info->trampoline_func, func_size, false);

	uintptr_t trampoline_func_end_addr = (uintptr_t)info->trampoline_func + func_size;
	uintptr_t trampoline_inline_hook_info_ptr = trampoline_func_end_addr - 4;
	WriteMemory<InlineHookInfo*>(trampoline_inline_hook_info_ptr, info);

	return func_size;
}



/*
__attribute__((section(".text"))) __attribute__((naked)) static void thumb_trampoline_manage_func()
{
	asm(
		".thumb                                   \n"
		".hidden thumb_trampoline_manage_func_end \n"
		/*
		"PUSH     {R0 - R3}	                      \n"
		"LDR      R1, inline_hook_info            \n"
		"LDR      R0, [R1]                        \n"
		"CBZ      R0, loc_01                      \n"//等于0则跳转
		"POP      {R0 - R3}                       \n"
		"LDR      PC, new_func_addr               \n"

		"loc_01:                                  \n"
		"POP      {R0 - R3}                       \n"
		"LDR      PC, orig_inst_addr              \n"
		*/ /*
		"PUSH     {R0}	                          \n"
		"LDR      IP, inline_hook_info            \n"
		"LDR      R0, [IP, #0x4]                  \n"
		"CBZ      R0, loc_01                      \n"//等于0则跳转
		"POP      {R0}                            \n"
		"LDR      PC, [IP, #0xC]                  \n"

		"loc_01:                                  \n"
		"POP      {R0}                            \n"
		"LDR      PC, [IP, #0x10]                 \n"


		"inline_hook_info:"
		".word 0x123;"
		/*
		"new_func_addr:"
		".word 0x456;"

		"orig_inst_addr:"
		".word 0x789;"
		*/ /*
		"thumb_trampoline_manage_func_end:"
		".global thumb_trampoline_manage_func_end;"
	);*/

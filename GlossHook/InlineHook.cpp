//Android (thumb/arm/arm64) Inline Hook
//by: XMDS 2022-12-14
#include "InlineHook.h"
#include "GlossHook.h"
#include "Instruction.h"
#include "Trampoline.h"
#include "GLog.h"

__attribute__((section(".inline_hook"))) InlineHookList HookLists;

static InlineHookInfo* AllocateInlineHookInfo()
{
	if (HookLists.id >= MAX_NUM_INLINE_HOOK)
	{
		GLOGE("The number of InlineHook has reached the memory limit, the maximum number is %d.", MAX_NUM_INLINE_HOOK);
		return NULL;
	}
	
	InlineHookInfo* info = &HookLists.info[HookLists.id++];
	MemoryFill(info, NULL, sizeof(InlineHookInfo), false);
	return info;
}

static int SetInlineHookInfo(InlineHookInfo* info, void* addr, void* func, i_set inst_set)
{
	SetInlineHookState(info, ENABLE_HOOK);
	info->hook_addr = (uintptr_t)addr;
	info->func_addr = func;
	info->prev = nullptr, info->next = nullptr;
	Unprotect((uintptr_t)info->fix_inst_buf, sizeof(info->fix_inst_buf));

	auto jump = CheckAbsoluteJump(info->hook_addr);//Has the current address been Hooked.
	if (jump == -2) {
		if (inst_set == $THUMB) {
			info->orig_addr = (void*)SET_BIT0((uintptr_t)info->fix_inst_buf); //thumb + 1
			MakeThumbTrampolineManageFunc(info);
		}
		else {
			info->orig_addr = info->fix_inst_buf;
			MakeArmTrampolineManageFunc(info);
		}
		info->hook_count = 1;
		info->result_addr = info->orig_addr;
		HookLists.list[info->orig_addr] = info; //
	}
	else if (jump == 0) {
		if (inst_set == $THUMB) {
			info->orig_addr = (void*)SET_BIT0((uintptr_t)info->fix_inst_buf); //thumb + 1
			info->result_addr = ReadMemory<void*>(info->hook_addr + (IS_ADDR_ALIGN_4(info->hook_addr) ? 4 : 2 + 4), false);
			uint8_t size = MakeThumbTrampolineManageFunc(info);
			info->prev = ReadMemory<InlineHookInfo*>(CLEAR_BIT0((uintptr_t)info->result_addr) + size - 4, false);
		}
		else {
			info->orig_addr = info->fix_inst_buf;
			info->result_addr = ReadMemory<void*>(info->hook_addr + 4, false);
			uint8_t size = MakeArmTrampolineManageFunc(info);
			info->prev = ReadMemory<InlineHookInfo*>((uintptr_t)info->result_addr + size - 4, false);
		}
		HookLists.list[info->orig_addr] = info;
		info->hook_count = info->prev->hook_count + 1;
		info->prev->next = info;
		info->backups_len = info->prev->backups_len;
		ReadMemory(info->prev->backups_inst, info->backups_inst, info->backups_len, false);
		ReadMemory(info->prev->fix_inst_buf, info->fix_inst_buf, MAX_INST_BUF_SIZE, false);
		return 0;
	}
	else {
		GLOGE("Hook failed. Please do not overwrite the previous or next instruction of Trampoline (currently: %d), this will cause the hook to crash.", jump);
		return -1;
	}

	if (inst_set == $THUMB) {
		//thumb16 + thumb32
		int8_t is_thumb32_count = 0;
		for (int i = 5; i >= 0; i--) {
			uintptr_t inst_addr = info->hook_addr + i * 2;
			if (IsThumb32(inst_addr))
				is_thumb32_count += 1;
			else
				break;
		}
		if (is_thumb32_count % 2 == 1) {
			info->backups_len = 10;
		}
		else {
			info->backups_len = 12;
		}
	}
	else {
		info->backups_len = 8;
	}
	
	ReadMemory((void*)info->hook_addr, info->backups_inst, info->backups_len, false);
	
	uintptr_t current_addr = info->fix_info.start_addr = info->hook_addr;
	info->fix_info.end_addr = info->hook_addr + info->backups_len;
	info->fix_info.buf_addr.arm = (uint32_t*)info->fix_inst_buf;
	info->fix_info.inst_mode = inst_set;

	int count = 0;
	for (int backups_pos = 0; backups_pos < info->backups_len; current_addr = info->hook_addr + backups_pos)
	{
		if (inst_set == $THUMB) {
			if (IsThumb32(current_addr)) {
				i_type type = GetThumb32InstType(current_addr);
				size_t len = GetThumb32FixInstLen(type);
				info->fix_info.fix_inst_len[count++] = len;
				info->fix_info.fix_inst_len[count++] = 0; //thumb32 fix
				backups_pos += 4;
				GLOGI("inst_len = %10p", len);

			}
			else {
				i_type type = GetThumb16InstType(current_addr);
				size_t len = GetThumb16FixInstLen(type);
				info->fix_info.fix_inst_len[count++] = len;
				backups_pos += 2;
				GLOGI("inst_len = %10p", len);
			}
		}
		else {
			i_type type = GetArmInstType(current_addr);
			size_t len = GetArmFixInstLen(type);
			info->fix_info.fix_inst_len[count++] = len;
			backups_pos += 4;
			GLOGI("inst_len = %10p", len);
		}
	}
	GLOGI("backups_len = %10p", info->backups_len);
	return 1;
}

static size_t FixOriginalInst(InlineHookInfo* info, fix_inst_info* fix_info, i_set inst_set)
{
	size_t fix_len = 0;
	int fix_pos = 0;
	uintptr_t backups_addr = (uintptr_t)info->backups_inst;
	union { uint16_t t_buf[16]; uint32_t a_buf[9]{ 0 }; } buf;

	if (inst_set == $THUMB) {
		uintptr_t pc = GET_THUMB_PC(info->hook_addr);

		for (int backups_pos = 0; backups_pos < info->backups_len; backups_addr = (uintptr_t)info->backups_inst + backups_pos, fix_pos += fix_len)
		{
			if (IsThumb32(backups_addr))
			{
				GLOGD("backups_inst = %10p", ReadMemory<uint32_t>((backups_addr)));
				i_type type = GetThumb32InstType(backups_addr);
				uint16_t high = ReadMemory<uint16_t>(backups_addr, false);
				uint16_t low = ReadMemory<uint16_t>(backups_addr + 2, false);
				fix_len = FixThumb32Inst(buf.t_buf, high, low, pc, type, fix_info);
				backups_pos += 4;
				pc += 4;
				ReadMemory(buf.t_buf, info->fix_inst_buf + fix_pos, fix_len, false);
				GLOGD("fix_inst_t32 = %10p", ReadMemory<uint32_t>((uintptr_t)(info->fix_inst_buf + fix_pos)));
			}
			else {
				GLOGD("backups_inst = %10p", ReadMemory<uint16_t>((backups_addr)));
				i_type type = GetThumb16InstType(backups_addr);
				uint16_t inst = ReadMemory<uint16_t>(backups_addr, false);
				fix_len = FixThumb16Inst(buf.t_buf, inst, pc, type, fix_info);
				backups_pos += 2;
				pc += 2;
				ReadMemory(buf.t_buf, info->fix_inst_buf + fix_pos, fix_len, false);
				GLOGD("fix_inst_t16 = %10p", ReadMemory<uint16_t>((uintptr_t)(info->fix_inst_buf + fix_pos)));
			}
		}

	}
	else { //arm
		uintptr_t pc = GET_ARM_PC(info->hook_addr);

		for (int backups_pos = 0; backups_pos < info->backups_len; backups_addr = (uintptr_t)info->backups_inst + backups_pos, fix_pos += fix_len)
		{
			GLOGD("backups_inst = %10p", ReadMemory<uint32_t>((backups_addr)));
			i_type type = GetArmInstType(backups_addr);
			uint32_t inst = ReadMemory<uint32_t>(backups_addr, false);
			fix_len = FixArmInst(buf.a_buf, inst, pc, type, fix_info);
			backups_pos += 4;
			pc += 4;
			ReadMemory(buf.a_buf, info->fix_inst_buf + fix_pos, fix_len, false);
			GLOGD("fix_inst_t16 = %10p", ReadMemory<uint32_t>((uintptr_t)(info->fix_inst_buf + fix_pos)));
		}
	}


	GLOGD("fix_pos = %10p", fix_pos);
	return fix_pos;
}

InlineHookInfo* InlineHookThumb(void* addr, void* func, void** original)
{
	if (addr == NULL || func == NULL) {
		WLOGE("Inline Hook failed, address is empty.");
		return nullptr;
	}

	InlineHookInfo* info = AllocateInlineHookInfo();
	if (NULL == info) {
		WLOGE("Failed to allocate InlineHook information!!!");
		return nullptr;
	}
	int ret = SetInlineHookInfo(info, addr, func, $THUMB);
	if (ret == -1) {
		--HookLists.id;
		return nullptr;
	}
	
	
	if (original != NULL) *original = info->orig_addr;

	if (!ret && info->prev != nullptr) {
		MakeThumbAbsoluteJump(info->hook_addr, SET_BIT0((uintptr_t)info->trampoline_func));
		return info;
	}

	size_t fix_len = FixOriginalInst(info, &info->fix_info, $THUMB);
	

	int jump_len = IS_ADDR_ALIGN_4(info->hook_addr) ? 8 : 2 + 8;
	MakeThumbAbsoluteJump((uintptr_t)info->fix_inst_buf + fix_len, SET_BIT0(info->hook_addr + jump_len));
	int nop_len = info->backups_len - jump_len;
	if (nop_len == 4) MakeThumb32NOP(info->hook_addr + jump_len, nop_len); //12-8=4  
	else if (nop_len == 2) MakeThumb16NOP(info->hook_addr + jump_len, nop_len); //12-10=2 10-8=2
	MakeThumbAbsoluteJump(info->hook_addr, SET_BIT0((uintptr_t)info->trampoline_func));
	return info;
}

InlineHookInfo* InlineHookARM(void* addr, void* func, void** original)
{
	if (addr == NULL || func == NULL) {
		WLOGE("Inline Hook failed, address is empty.");
		return nullptr;
	}

	InlineHookInfo* info = AllocateInlineHookInfo();
	if (NULL == info) {
		WLOGE("Failed to allocate InlineHook information!!!");
		return nullptr;
	}

	int ret = SetInlineHookInfo(info, addr, func, $ARM);
	if (ret == -1) {
		--HookLists.id;
		return nullptr;
	}
	if (original != NULL) *original = info->orig_addr;

	if (!ret && info->prev != nullptr) {
		MakeArmAbsoluteJump(info->hook_addr, (uintptr_t)info->trampoline_func);
		return info;
	}

	size_t fix_len = FixOriginalInst(info, &info->fix_info, $ARM);

	MakeArmAbsoluteJump((uintptr_t)info->fix_inst_buf + fix_len, info->hook_addr + info->backups_len);
	MakeArmAbsoluteJump(info->hook_addr, (uintptr_t)info->trampoline_func);
	return info;
}

InlineHookInfo* GetLastInlineHook(void* addr, i_set inst_set)
{
	if (CheckAbsoluteJump((uintptr_t)addr) == 0) {
		if (inst_set == $THUMB) {
			uintptr_t result_addr = ReadMemory<uintptr_t>((uintptr_t)addr + (IS_ADDR_ALIGN_4(CLEAR_BIT0((uintptr_t)addr)) ? 4 : 2 + 4), false);
			return ReadMemory<InlineHookInfo*>(CLEAR_BIT0(result_addr) + GetThumbTrampolineManageFuncSize() - 4, false);
		}
		else {
			uintptr_t result_addr = ReadMemory<uintptr_t>((uintptr_t)addr + 4, false);
			return ReadMemory<InlineHookInfo*>(result_addr + GetArmTrampolineManageFuncSize() - 4, false);
		}
	}
	return nullptr;
}

static void SetNextInlineHookCount(InlineHookInfo* info) {
	InlineHookInfo* next = info->next;
	while (next != nullptr) {
		--next->hook_count;
		next = next->next;
	}
}


void DeleteInlineHook(InlineHookInfo* hook)
{
	InlineHookInfo* current = hook;
	if (current->hook_count == 1 && current->prev == nullptr) {
		if (current->next == nullptr) { //没有下一个
			ReadMemory(current->backups_inst, (void*)current->hook_addr, current->backups_len, false); //恢复原始指令
		}
		else {
			SetNextInlineHookCount(current);
			current->next->result_addr = current->next->orig_addr;
			TEST_BIT0((uintptr_t)current->next->result_addr) ? MakeThumbAbsoluteJump(current->hook_addr, SET_BIT0((uintptr_t)current->next->trampoline_func)) :
				MakeArmAbsoluteJump(current->hook_addr, (uintptr_t)current->next->trampoline_func);
			current->next->prev = nullptr;
		}
	}
	else {
		if (current->next == nullptr) {
			current->prev->next = nullptr;
			(TEST_BIT0((uintptr_t)current->result_addr) ? MakeThumbAbsoluteJump : MakeArmAbsoluteJump)(current->hook_addr, (uintptr_t)current->result_addr);
		}
		else{
			SetNextInlineHookCount(current);
			current->next->result_addr = current->result_addr;
			current->next->prev = current->prev;
			current->prev->next = current->next;
		}
	}
	MemoryFill(current, NULL, sizeof(InlineHookInfo), false);
}


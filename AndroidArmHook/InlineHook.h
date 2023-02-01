#pragma once
#include "FixInst.hpp"
#include <map>

#define MAX_NUM_INLINE_HOOK 2048
#define MAX_BACKUPS_LEN 12
#define MAX_INST_BUF_SIZE 100
#define ENABLE_HOOK true
#define DISABLE_HOOK false

using namespace Inst;

__attribute__((aligned(4))) struct InlineHookInfo
{
	/* 0x00 */int hook_count;
	/* 0x04 */bool hook_state; //hook\unhook
	/* 0x08 */uintptr_t hook_addr;
	/* 0x0C */void* func_addr;
	/* 0x10 */void* result_addr;
	/* 0x14 */void* orig_addr;
	/* 0x18 */unsigned char backups_inst[MAX_BACKUPS_LEN];
	/* 0x24 */uint8_t backups_len; //10 or 12
	/* 0x28 */fix_inst_info fix_info;
	/* 0x48 */InlineHookInfo* prev;
	/* 0x4C */InlineHookInfo* next;
	/* 0x50 */unsigned char trampoline_func[48];
	/* 0x80 */unsigned char fix_inst_buf[MAX_INST_BUF_SIZE];
};

struct InlineHookList
{
	InlineHookInfo info[MAX_NUM_INLINE_HOOK];
	int32_t id = 0;
	std::map<void*, InlineHookInfo*> list;
};

extern InlineHookList HookLists;


constexpr int a = offsetof(InlineHookInfo, fix_inst_buf);

InlineHookInfo* InlineHookThumb(void* addr, void* func, void** original);
InlineHookInfo* InlineHookARM(void* addr, void* func, void** original);

inline void SetInlineHookState(InlineHookInfo* info, bool state)
{
	info->hook_state = state;
}


void DeleteInlineHook(void* hook);
InlineHookInfo* GetLastInlineHook(void* addr, i_set inst_set);

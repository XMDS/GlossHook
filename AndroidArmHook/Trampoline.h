#pragma once
#include "InlineHook.h"

uint8_t MakeThumbTrampolineManageFunc(InlineHookInfo* info);
uint8_t MakeArmTrampolineManageFunc(InlineHookInfo* info);

extern uint8_t ThumbTrampolineManageFuncSize;
extern uint8_t ArmTrampolineManageFuncSize;
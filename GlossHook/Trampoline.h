#pragma once
#include "InlineHook.h"

uint8_t MakeThumbTrampolineManageFunc(InlineHookInfo* info);
uint8_t MakeArmTrampolineManageFunc(InlineHookInfo* info);

uint8_t GetThumbTrampolineManageFuncSize();
uint8_t GetArmTrampolineManageFuncSize();
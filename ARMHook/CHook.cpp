#include "CHook.h"
#include <android/log.h>
#include <dlfcn.h>
#include <ctype.h>
#include <unistd.h>
#include "Substrate/CydiaSubstrate.h"

#define HOOK_PROC_THUMB "\x01\xB4\x01\xB4\x01\x48\x01\x90\x01\xBD\x00\xBF\x00\x00\x00\x00"
/*
push{ r0 }
push{ r0 }
ldr r0, [pc, #4]
str r0, [sp, #4]
pop{ r0, pc }
nop
func
*/
#define HOOK_PROC_ARM "\x04\xF0\x1F\xE5\x00\x00\x00\x00" //ldr pc, [pc, #-4] func

uintptr_t hook_addr_start = 0;
uintptr_t hook_addr_end = 0;
uintptr_t arm_mmap_start = 0;
uintptr_t arm_mmap_end = 0;

namespace ARMHook
{
    uintptr_t CHook::GetLibraryAddress(const char* library)
    {
        uintptr_t address = 0;
        char buffer[2048] = { 0 };

        FILE* fp = fopen("/proc/self/maps", "rt");
        if (fp != NULL)
        {
            while (fgets(buffer, sizeof(buffer) - 1, fp))
            {
                if (strstr(buffer, library))
                {
                    address = (uintptr_t)strtoul(buffer, NULL, 16);
                    break;
                }
            }
            fclose(fp);
        }
        return address;
    }

    uintptr_t CHook::GetLibraryLength(const char* library)
    {
        uintptr_t address = 0, end_address = 0;
        char buffer[2048] = { 0 };
        
        FILE* fp = fopen("/proc/self/maps", "rt");
        if (fp != NULL)
        {
            while (fgets(buffer, sizeof(buffer) - 1, fp))
            {
                if (strstr(buffer, library))
                {
                    const char* secondPart = strchr(buffer, '-');
                    if (!address) end_address = address = (uintptr_t)strtoul(buffer, NULL, 16);
                    if (secondPart != NULL) end_address = (uintptr_t)strtoul(secondPart + 1, NULL, 16);
                }
            }
            fclose(fp);
        }
        return end_address - address;
    }

    const char* CHook::GetLibraryFilePath(uintptr_t LibAddr)
    {
        Dl_info info;
        if (dladdr((void*)LibAddr, &info) == 0)
            return NULL;
        return info.dli_fname;
    }
    
    uintptr_t CHook::GetSymbolAddress(void* handle, const char* name)
    {
        return (uintptr_t)dlsym(handle, name);
    }

    uintptr_t CHook::GetSymbolAddress(uintptr_t LibAddr, const char* name)
    {
        Dl_info info;
        if (dladdr((void*)LibAddr, &info) == 0)
            return 0;
        return (uintptr_t)dlsym(info.dli_fbase, name);
    }
    
    int CHook::unprotect(uintptr_t addr, size_t len)
    {
        return mprotect((void*)(addr & 0xFFFFF000), len, PROT_READ | PROT_WRITE | PROT_EXEC);
    }

    void CHook::WriteMemory(void* addr, void* data, size_t size)
    {
        unprotect((uintptr_t)addr, size);
        memcpy(addr, data, size);
        cacheflush((uintptr_t)addr, (uintptr_t)addr + size, 0);
    }

    void* CHook::ReadMemory(void* addr, void* data, size_t size)
    {
        unprotect((uintptr_t)addr, size);
        memcpy(data, addr, size);
        return data;
    }

    void CHook::PLTInternal(void* addr, void* func, void** original)
    {
        if (addr == NULL || func == NULL) return;
        unprotect((uintptr_t)addr, 4);
        if (original != NULL)
            *((uintptr_t*)original) = *(uintptr_t*)addr;
        *(uintptr_t*)addr = (uintptr_t)func;
    }

    void CHook::Internal(void* addr, void* func, void** original)
    {
        if (addr == NULL || func == NULL) return;
        unprotect((uintptr_t)addr);
        return MSHookFunction(addr, func, original);
    }

    void CHook::MakeThumbNOP(uintptr_t addr, size_t size)
    {
        unprotect(addr, size);
        for (int i = 0; i < size; i += 2)
        {
            *((uint8_t*)addr + i + 0) = 0x00;
            *((uint8_t*)addr + i + 1) = 0xBF;
        }
    }

    void CHook::MakeArmNOP(uintptr_t addr, size_t size)
    {
        unprotect(addr, size);
        for (int i = 0; i < size; i += 4)
        {
            *((uint8_t*)addr + i + 0) = 0x00;
            *((uint8_t*)addr + i + 1) = 0xF0;
            *((uint8_t*)addr + i + 2) = 0x20;
            *((uint8_t*)addr + i + 3) = 0xE3;
        }
    }

    void CHook::MakeThumbRET(uintptr_t addr, int type)
    {
        uint16_t ret[1];
        if (type == 0)
            *ret = 0x46F7;//MOV PC, LR
        else if (type == 1)
            *ret = 0x4770;//BX LR

        WriteMemory((void*)addr, ret, 2);
    }

    void CHook::MakeArmRET(uintptr_t addr, int type)
    {
        uint32_t ret[1];
        if (type == 0)
            *ret = 0xE1A0F00E;//MOV PC, LR
        else if (type == 1)
            *ret = 0xE12FFF1E;//BX LR

        WriteMemory((void*)addr, ret, 4);
    }
    
    void CHook::MakeThumbBL(uintptr_t addr, uintptr_t func)
    {
        uint32_t offset = (func - addr - 4) & 0x7FFFFF; //offset = func - PC   PC = addr + 4
        uint16_t high = offset >> 12;
        uint16_t low = (offset & 0xFFF) >> 1; //& 0xFFF go forward jump, clear sign bit
        uint32_t hex = ((0xF800 | low) << 16) | (0xF000 | high);
        
        WriteMemory((void*)addr, &hex, 4);
    }

    void CHook::MakeThumbBLX(uintptr_t addr, uintptr_t func)
    {
        uint32_t offset = (func - addr - 4) & 0x7FFFFF; //offset = func - PC   PC = addr + 4
        uint16_t high = offset >> 12;
        uint16_t low = (offset & 0xFFF) >> 1; //& 0xFFF go forward jump, clear sign bit
        if (low % 2 != 0) { //align
            low++;
        }
        uint32_t hex = ((0xE800 | low) << 16) | (0xF000 | high);

        WriteMemory((void*)addr, &hex, 4);
    }

    void CHook::MakeThumbB_W(uintptr_t addr, uintptr_t func) //B.W
    {
        uint32_t offset = (func - addr - 4) & 0x7FFFFF; //offset = func - PC   PC = addr + 4
        uint16_t high = offset >> 12;
        uint16_t low = (offset & 0xFFF) >> 1; //& 0xFFF go forward jump, clear sign bit
        uint32_t hex = ((0xB800 | low) << 16) | (0xF000 | high);

        WriteMemory((void*)addr, &hex, 4);
    }

    void CHook::MakeThumbB_W(uintptr_t addr, uintptr_t targe, cond_type cond) //B.W
    {
        uint16_t a, b;
        if (targe < addr)
        {
            a = 0xA800;
            switch (cond)
            {
            case EQ: b = 0xF43F;
                break;
            case NE: b = 0xF47F;
                break;
            case CS: b = 0xF4BF;//HS
                break;
            case CC: b = 0xF4FF;//LO
                break;
            case MI: b = 0xF53F;
                break;
            case PL: b = 0xF57F;
                break;
            case VS: b = 0xF5BF;
                break;
            case VC: b = 0xF5FF;
                break;
            case HI: b = 0xF63F;
                break;
            case LS: b = 0xF67F;
                break;
            case GE: b = 0xF6BF;
                break;
            case LT: b = 0xF6FF;
                break;
            case GT: b = 0xF73F;
                break;
            case LE: b = 0xF77F;
                break;
            case AL: b = 0xF7BF;
                break;
            case BNV: b = 0xF7FF;
                break;
            }
        }
        else
        {
            a = 0x8000;
            switch (cond)
            {
            case EQ: b = 0xF000;
                break;
            case NE: b = 0xF040;
                break;
            case CS: b = 0xF080;//HS
                break;
            case CC: b = 0xF0C0;//LO
                break;
            case MI: b = 0xF100;
                break;
            case PL: b = 0xF140;
                break;
            case VS: b = 0xF180;
                break;
            case VC: b = 0xF1C0;
                break;
            case HI: b = 0xF200;
                break;
            case LS: b = 0xF240;
                break;
            case GE: b = 0xF280;
                break;
            case LT: b = 0xF2C0;
                break;
            case GT: b = 0xF300;
                break;
            case LE: b = 0xF340;
                break;
            case AL: b = 0xF380;
                break;
            case BNV: b = 0xF3C0;
                break;
            }
        }
        uint32_t offset = (targe - addr - 4) & 0x7FFFFF; //offset = func - PC   PC = addr + 4
        uint16_t high = (offset & 0xFFF) >> 12;
        uint16_t low = (offset & 0xFFF) >> 1; //& 0xFFF go forward jump, clear sign bit
        uint32_t hex = ((a | low) << 16) | (b | high);

        WriteMemory((void*)addr, &hex, 4);
    }

    void CHook::MakeThumbB(uintptr_t addr, uintptr_t targe) //B
    {
        uint16_t offset = (targe - addr - 4) & 0x7FFFFF; //offset = func - PC   PC = addr + 4
        uint16_t hex = (offset & 0xFFF) >> 1 | 0xE000; //& 0xFFF go forward jump, clear sign bit

        WriteMemory((void*)addr, &hex, 2);
    }

    void CHook::MakeThumbB(uintptr_t addr, uintptr_t targe, cond_type cond) //B
    {
        uint16_t offset = (targe - addr - 4) & 0x7FFFFF; //offset = func - PC   PC = addr + 4
        int16_t n;
        switch (cond)
        {
        case EQ: n = 0xD000;
            break;
        case NE: n = 0xD100;
            break;
        case CS: n = 0xD200;//BHS
            break;
        case CC: n = 0xD300;//BLO
            break;
        case MI: n = 0xD400;
            break;
        case PL: n = 0xD500;
            break;
        case VS: n = 0xD600;
            break;
        case VC: n = 0xD700;
            break;
        case HI: n = 0xD800;
            break;
        case LS: n = 0xD900;
            break;
        case GE: n = 0xDA00;
            break;
        case LT: n = 0xDB00;
            break;
        case GT: n = 0xDC00;
            break;
        case LE: n = 0xDD00;
            break;
        case AL: n = 0xDE00;
            break;
        case BNV: n = 0xDF00;
            break;
        }
        uint16_t hex = (offset & 0xFFF) >> 1 & 0xFF | n; //& 0xFFF go forward jump, clear sign bit

        WriteMemory((void*)addr, &hex, 2);
    }

    void CHook::MakeThumbCBZ_CBNZ(uintptr_t addr, uintptr_t targe, uint8_t reg, bool nonzero) //CBZ CBNZ
    {
        int16_t n;
        if ((targe - addr < 0x4 && targe - addr >= -0x3C) || (targe - addr >= 0x44 && targe - addr < 0x84))
            n = nonzero ? 0xBB00 : 0xB300;
        else 
            n = nonzero ? 0xB900 : 0xB100;
        
        uint16_t offset = (targe - addr - 4) & 0x7FFFFF; //offset = func - PC   PC = addr + 4
        uint16_t hex = (offset & 0xFFF) << 2 & 0xFF | reg | n;

        WriteMemory((void*)addr, &hex, 2);

    }

    void CHook::MakeArmBL(uintptr_t addr, uintptr_t func)
    {
        uint32_t hex = ((func - addr - 8) / 4) & 0xFFFFFF | 0xEB000000; //offset = func - PC   PC = addr + 8  (/ 4 = align)
        WriteMemory((void*)addr, &hex, 4);
    }

    void CHook::MakeArmB(uintptr_t addr, uintptr_t targe) //B
    {
        uint32_t hex = ((targe - addr - 8) / 4) & 0xFFFFFF | 0xEA000000; //offset = func - PC   PC = addr + 8  (/ 4 = align)
        WriteMemory((void*)addr, &hex, 4);
    }

    void CHook::MakeArmB(uintptr_t addr, uintptr_t targe, cond_type cond)
    {
        int32_t n;
        switch (cond)
        {
        case EQ: n = 0x0A000000;
            break;
        case NE: n = 0x1A000000;
            break;
        case CS: n = 0x2A000000;//BHS
            break;
        case CC: n = 0x3A000000;//BLO
            break;
        case MI: n = 0x4A000000;
            break;
        case PL: n = 0x5A000000;
            break;
        case VS: n = 0x6A000000;
            break;
        case VC: n = 0x7A000000;
            break;
        case HI: n = 0x8A000000;
            break;
        case LS: n = 0x9A000000;
            break;
        case GE: n = 0xAA000000;
            break;
        case LT: n = 0xBA000000;
            break;
        case GT: n = 0xCA000000;
            break;
        case LE: n = 0xDA000000;
            break;
        case AL: n = 0xEA000000;//see MakeArmB(uintptr_t addr, uintptr_t targe)
            break;
        case BNV: n = 0xFA000000;
            break;
        }
        uint32_t hex = ((targe - addr - 8) / 4) & 0xFFFFFF | n; //offset = func - PC   PC = addr + 8  (/ 4 = align)
        WriteMemory((void*)addr, &hex, 4);
    }
    
    uintptr_t CHook::GetThumbCallAddr(uintptr_t addr)
    {
        InstructionType type = GetThumbInstructionType(addr, true);
        uint16_t high, low;
        ReadMemory((void*)addr, &high, 2);
        ReadMemory((void*)(addr + 2), &low, 2);

        int32_t offset = ((high & 0x7FF) << 12) | ((low & 0x7FF) << 1);
        if (offset & 0x400000) //go forward jump
        {
            offset = ~(offset - 1);
            offset &= 0x7FFFFF;
            if (type == BLX_THUMB32)
            {
                if (addr % 4 != 0)
                    return addr + 2 - offset;
                else
                    return addr + 4 - offset;
            }
            else if (type == BW_THUMB32 || type == BL_THUMB32)
                return addr + 4 - offset;
            else
                return 0;
        }
        offset &= 0x7FFFFF;
        if (type == BLX_THUMB32)
        {
            if (addr % 4 != 0)
                return addr + 2 + offset;
            else
                return addr + 4 + offset;
        }
        else if (type == BW_THUMB32 || type == BL_THUMB32)
            return addr + 4 + offset;
        else
            return 0;
    }

    uintptr_t CHook::GetArmCallAddr(uintptr_t addr)
    {
        InstructionType type = GetArmInstructionType(addr);
        uint32_t hex;
        ReadMemory((void*)addr, &hex, 4);

        int32_t a = (hex & 0xFFFFFF) << 2;
        if (type == BLX_ARM)
            a = a | ((hex & 0x1000000) >> 23);
        else if (type == B_ARM || type == BLX_ARM)
            goto xxx;
        else
            return 0;
    xxx:
        int32_t offset = a >> 25;
        offset = offset ? (a | (0xFFFFFFFF << 26)) : a;
        return addr + 8 + offset;
    }

    InstructionType CHook::GetThumbInstructionType(uintptr_t addr, bool isThumb32)
    {
        union 
        {
            uint16_t hex16; 
            struct
            {
                uint16_t high;
                uint16_t low;
            }bit;
            uint32_t hex32;
        }code;

        if (isThumb32)
        {
            ReadMemory((void*)addr, &code.bit.high, 2);
            ReadMemory((void*)addr, &code.bit.low, 2);
            code.hex32 = (code.bit.high << 16) | code.bit.low;
            if (((code.hex32 & 0xF800D000) == 0xF0008000) && ((code.hex32 & 0x03800000u) != 0x03800000u))
                return BW_COND_THUMB32;
            else if ((code.hex32 & 0xF800D000) == 0xF0009000)
                return BW_THUMB32;
            else if ((code.hex32 & 0xF800D000) == 0xF000D000)
                return BL_THUMB32;
            else if ((code.hex32 & 0xF800D000) == 0xF000C000)
                return BLX_THUMB32;
            else if ((code.hex32 & 0xFF7F0000) == 0xF85F0000)
                return LDRW_THUMB32;
            else
                return UNDEFINE;
        }
        else 
        {
            ReadMemory((void*)addr, &code, 2);
            if (((code.hex16 & 0xFF00u) == 0xBF00) && ((code.hex16 & 0x000Fu) != 0x0000) && ((code.hex16 & 0x00F0u) != 0x00F0))
                return IT_THUMB16;
            else if (((code.hex16 & 0xF000u) == 0xD000) && ((code.hex16 & 0x0F00u) != 0x0F00) && ((code.hex16 & 0x0F00u) != 0x0E00))
                return B_COND_THUMB16;
            else if ((code.hex16 & 0xF800u) == 0xE000)
                return B_THUMB16;
            else if /*((code.hex16 & 0xFFF8u) == 0x4778)*/ ((code.hex16 & 0xFF00u) == 0x4700)
                return BX_THUMB16;
            else if (((code.hex16 & 0xFF78u) == 0x4478) && ((code.hex16 & 0x0087u) != 0x0085))
                return ADD_PC_THUMB16;
            else if /*((code.hex16 & 0xFF78u) == 0x4678)*/ ((code.hex16 & 0xFF00u) == 0x4600)
                return MOV_REG_THUMB16;
            else if ((code.hex16 & 0xF800u) == 0xA000)
                return ADR_THUMB16;
            else if ((code.hex16 & 0xF800u) == 0x4800)
                return LDR_THUMB16;
            else if (((code.hex16 & 0xF800u) == 0x6800) || ((code.hex16 & 0xF800u) == 0x5800) || ((code.hex16 & 0xF800u) == 0x9800))
                return LDR_REG_THUMB16;
            else if ((code.hex16 & 0xFD00u) == 0xB100)
                return CBZ_THUMB16;
            else if ((code.hex16 & 0xFD00u) == 0xB900)
                return CBNZ_THUMB16;
            else if (((code.hex16 & 0xF800u) == 0x1800) || ((code.hex16 & 0xF800u) == 0x3000))
                return ADDS_THUMB16;
            else if ((code.hex16 & 0xF800u) == 0x2000)
                return MOVS_THUMB16;
            else if (((code.hex16 & 0xF800u) == 0xA800) || ((code.hex16 & 0xF800u) == 0xB000))
                return ADD_REG_THUMB16;
            else
                return UNDEFINE;
        }
    }

    InstructionType CHook::GetArmInstructionType(uintptr_t addr)
    {
        uint32_t code;
        ReadMemory((void*)addr, &code, 4);
        if (((code & 0x0F000000u) == 0x0A000000) && ((code & 0xF0000000) != 0xF0000000))
            return B_ARM;
        else if (((code & 0x0FFFFFFFu) == 0x012FFF1F) && ((code & 0xF0000000) != 0xF0000000) || ((code & 0x0FFFFFFFu) == 0x012FFF1E))
            return BX_ARM;
        else if (((code & 0x0F000000u) == 0x0B000000) && ((code & 0xF0000000) != 0xF0000000))
            return BL_ARM;
        else if ((code & 0xFE000000) == 0xFA000000)
            return BLX_ARM;
        else if (((code & 0xE5F0000) == 0x41F0000) && ((code & 0x0F7F0000u) == 0x051F0000) && ((code & 0xF0000000) != 0xF0000000))
            return LDR_ARM;
        else
            return UNDEFINE;
    }


    bool compareData(const uint8_t* data, const bytePattern::byteEntry* pattern, size_t patternlength)
    {
        int index = 0;
        for (size_t i = 0; i < patternlength; i++)
        {
            auto byte = *pattern;
            if (!byte.bUnknown && *data != byte.nValue) return false;

            ++data;
            ++pattern;
            ++index;
        }
        return index == patternlength;
    }

    uintptr_t CHook::GetAddressFromPattern(const char* pattern, const char* library)
    {
        bytePattern ret;
        const char* input = &pattern[0];
        while (*input)
        {
            bytePattern::byteEntry entry;
            if (isspace(*input)) ++input;
            if (isxdigit(*input))
            {
                entry.bUnknown = false;
                entry.nValue = (uint8_t)std::strtol(input, NULL, 16);
                input += 2;
            }
            else
            {
                entry.bUnknown = true;
                input += 2;
            }
            ret.vBytes.emplace_back(entry);
        }

        auto patternstart = ret.vBytes.data();
        auto length = ret.vBytes.size();

        uintptr_t pMemoryBase = GetLibraryAddress(library);
        size_t nMemorySize = GetLibraryLength(library) - length;

        for (size_t i = 0; i < nMemorySize; i++)
        {
            uintptr_t addr = pMemoryBase + i;
            if (compareData((const uint8_t*)addr, patternstart, length)) return addr;
        }
        return (uintptr_t)0;
    }
    
    uintptr_t CHook::GetAddressFromPattern(const char* pattern, uintptr_t libStart, uintptr_t scanLen)
    {
        bytePattern ret;
        const char* input = &pattern[0];
        while (*input)
        {
            bytePattern::byteEntry entry;
            if (isspace(*input)) ++input;
            if (isxdigit(*input))
            {
                entry.bUnknown = false;
                entry.nValue = (uint8_t)std::strtol(input, NULL, 16);
                input += 2;
            }
            else
            {
                entry.bUnknown = true;
                input += 2;
            }
            ret.vBytes.emplace_back(entry);
        }

        auto patternstart = ret.vBytes.data();
        auto length = ret.vBytes.size();

        uintptr_t scanSize = libStart + scanLen;
        for (size_t i = 0; i < scanSize; i++)
        {
            uintptr_t addr = libStart + i;
            if (compareData((const uint8_t*)addr, patternstart, length)) return addr;
        }
        return (uintptr_t)0;
    }

    






    //Trampolines hook
    uintptr_t CHook::InitialiseTrampolines(uintptr_t addr, size_t size)
    {
        hook_addr_start = addr;
        hook_addr_end = hook_addr_start + size;

        arm_mmap_start = (uintptr_t)mmap(0, PAGE_SIZE, PROT_WRITE | PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        mprotect((void*)(arm_mmap_start & 0xFFFFF000), PAGE_SIZE, PROT_READ | PROT_EXEC | PROT_WRITE);
        arm_mmap_end = arm_mmap_start + PAGE_SIZE;
        return  arm_mmap_end;
    }

    void CheckMemorySpaceLimit()
    {
        if (hook_addr_end < (hook_addr_start + 0x10) || arm_mmap_end < (arm_mmap_start + 0x20))
        {
            __android_log_write(ANDROID_LOG_ERROR, "ARMHook", "Error!!! Space limit reached.");
            exit(1);
        }
    }

    void CHook::ReplaceThumbCall(uintptr_t addr, uintptr_t func)
    {
        CheckMemorySpaceLimit();
        addr &= ~1;
        uint32_t hex = ((hook_addr_start - addr - 4) >> 12) & 0x7FF | 0xF000 | ((((hook_addr_start - addr - 4) >> 1) & 0x7FF | 0xF800) << 16);
        WriteMemory((void*)addr, &hex, 4);
        uintptr_t local = hook_addr_start & ~1;
        char code[16];
        memcpy(code, HOOK_PROC_THUMB, 16);
        *(uint32_t*)&code[12] = (func | 1);
        //*(uint32_t*)&code[4] = (func | 1);
        WriteMemory((void*)local, code, 16);
        unprotect(hook_addr_start, 16);
        hook_addr_start += 16;
    }

    void CHook::ReplaceArmCall(uintptr_t addr, uintptr_t func)
    {
        CheckMemorySpaceLimit();
        uintptr_t a = hook_addr_start - addr;
        uintptr_t b = a - 1;
        uintptr_t c = a - 4;
        if (c >= 0)
            b = c;
        uint32_t hex = ((b >> 2) - 1) & 0xFFFFFF | 0xEB000000;
        WriteMemory((void*)addr, &hex, 4);
        char code[8];
        memcpy(code, HOOK_PROC_ARM, 8);
        *(uint32_t*)&code[4] = (func | 1);
        WriteMemory((void*)hook_addr_start, code, 8);
        hook_addr_start += 16;
    }

    void CHook::HookThumbFunc(void* func, uint32_t startSize, void* func_to, void** func_orig)
    {
        CheckMemorySpaceLimit();
        uintptr_t addr = (uintptr_t)func & ~1;
        uintptr_t start = arm_mmap_start;
        WriteMemory((void*)arm_mmap_start, (void*)addr, startSize);
        if (startSize << 30)
            *(uint32_t*)(start + startSize) = 18112;
        uintptr_t size = start + startSize;
        if (startSize << 30)
            size += 2;
        char code[16];
        memcpy(code, HOOK_PROC_THUMB, 16);
        *(uint32_t*)&code[12] = ((addr + startSize) | 1);
        WriteMemory((void*)(size & ~1), code, 16);
        *func_orig = (void*)(arm_mmap_start + 1);
        arm_mmap_start += 32;
        addr &= ~1;
        uint32_t hex = ((hook_addr_start - addr - 4) >> 12) & 0x7FF | 0xF000 | ((((hook_addr_start - addr - 4) >> 1) & 0x7FF | 0xB800) << 16);
        WriteMemory((void*)addr, &hex, 4);
        char code2[16];
        memcpy(code2, HOOK_PROC_THUMB, 16);
        *(uint32_t*)&code2[12] = ((uintptr_t)func_to | 1);
        WriteMemory((void*)(hook_addr_start & ~1), code2, 16);
        hook_addr_start += 16;
    }

    void CHook::HookArmFunc(void* func, uint32_t startSize, void* func_to, void** func_orig)
    {
        CheckMemorySpaceLimit();
        uintptr_t start = arm_mmap_start;
        WriteMemory((void*)arm_mmap_start, func, startSize);
        if (startSize << 30)
            *(uint32_t*)(start + startSize) = 18112;
        uintptr_t size = start + startSize;
        if (startSize << 30)
            size += 2;
        char code[8];
        memcpy(code, HOOK_PROC_ARM, 8);
        *(uint32_t*)&code[4] = ((uintptr_t)func + startSize) & ~1;
        WriteMemory((void*)size, code, 8);
        *func_orig = (void*)arm_mmap_start;
        arm_mmap_start += 32;
        uintptr_t a = hook_addr_start - (uintptr_t)func;
        uintptr_t b = a - 1;
        uintptr_t c = a - 4;
        if (c >= 0)
            b = c;
        uint32_t hex = ((b >> 2) - 1) & 0xFFFFFF | 0xEA000000;
        WriteMemory(func, &hex, 4);
        char code2[8];
        memcpy(code2, HOOK_PROC_ARM, 8);
        *(uint32_t*)&code2[4] = ((uintptr_t)func_to | 1);
        WriteMemory((void*)hook_addr_start, code2, 8);
        hook_addr_start += 16;
    }

    
}

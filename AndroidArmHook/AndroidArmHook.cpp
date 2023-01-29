#include "AndroidArmHook.h"

#include <stdio.h> //snprintf fopen
#include <string.h> //strcpy strstr
#include <stdlib.h> //strtoul
#include <errno.h>
#include <sys/mman.h> //mprotect

#include "InlineHook.h"
#include "Instruction.h"
#include "HLog.h"
#include "xDL/xdl.h"

uintptr_t GetLibBase(const char* libName, pid_t pid)
{
    uintptr_t address = 0;
    char buffer[2048] = { 0 }, fname[2048] = { 0 };
    if (pid < 0)
        strcpy(fname, "/proc/self/maps");
    else
        snprintf(fname, sizeof(fname), "/proc/%d/maps", pid);
    FILE* fp = fopen(fname, "rt");
    if (fp != NULL)
    {
        while (fgets(buffer, sizeof(buffer) - 1, fp))
        {
            if (strstr(buffer, libName))
            {
                address = (uintptr_t)strtoul(buffer, NULL, 16);
                break;
            }
        }
        fclose(fp);
    }
    return address;
}

size_t GetLibLength(const char* libName, pid_t pid)
{
    uintptr_t address = 0, end_address = 0;
    char buffer[2048] = { 0 }, fname[2048] = { 0 };
    if (pid < 0)
        strcpy(fname, "/proc/self/maps");
    else
        snprintf(fname, sizeof(fname), "/proc/%d/maps", pid);
    FILE* fp = fopen(fname, "rt");
    if (fp != NULL)
    {
        while (fgets(buffer, sizeof(buffer) - 1, fp))
        {
            if (strstr(buffer, libName))
            {
                const char* secondPart = strchr(buffer, '-');
                if (!address)
                    end_address = address = (uintptr_t)strtoul(buffer, NULL, 16);
                if (secondPart != NULL)
                    end_address = (uintptr_t)strtoul(secondPart + 1, NULL, 16);
            }
        }
        fclose(fp);
    }
    return end_address - address;
}

lib_h GetLibHandle(const char* libName)
{
    void* xdl_handle = xdl_open(libName, XDL_TRY_FORCE_LOAD);
    if (NULL == xdl_handle) {
        if (NULL != dlopen(libName, RTLD_LAZY))
            xdl_handle = xdl_open(libName, XDL_DEFAULT);
    }
    return xdl_handle;
}

void CloseLib(lib_h handle)
{
    auto dl_handle = xdl_close(handle);
    if (NULL != dl_handle)
        dlclose(dl_handle);
    return;
}

uintptr_t GetLibBaseFromHandle(lib_h handle)
{
    xdl_info_t info;
    if (xdl_info(handle, XDL_DI_DLINFO, &info) == -1)
        return NULL;
    return (uintptr_t)info.dli_fbase;
}

const char* GetLibFilePath(uintptr_t libAddr)
{
    xdl_info_t info;
    void* cache = NULL;
    if (xdl_addr((void*)libAddr, &info, &cache) == 0)
        return NULL;
    xdl_addr_clean(&cache);
    return info.dli_fname;
}

const char* GetLibFilePathFromHandle(lib_h handle)
{
    xdl_info_t info;
    if (xdl_info(handle, XDL_DI_DLINFO, &info) == -1)
        return NULL;
    return info.dli_fname;
}

size_t GetLibFileSize(lib_h handle)
{
    size_t size = 0;
    FILE* file = fopen(GetLibFilePathFromHandle(handle), "r");
    if (file != NULL) {
        fseek(file, 0, SEEK_END);
        size = ftell(file);
        fclose(file);
    }
    return size;
}

uintptr_t GetSymbolAddress(lib_h handle, const char* name)
{
    void* addr = xdl_sym(handle, name, NULL);
    if (NULL == addr)
        addr = xdl_dsym(handle, name, NULL);
    return (uintptr_t)addr;
}

uintptr_t GetSymbolAddressEx(uintptr_t libAddr, const char* name)
{
    auto handle = GetLibHandle(GetLibFilePath(libAddr));
    return NULL != handle ? GetSymbolAddress(handle, name) : NULL;
}

size_t GetSymbolSize(lib_h handle, const char* name)
{
    size_t size = NULL;
    if (NULL == xdl_sym(handle, name, &size))
        xdl_dsym(handle, name, &size);
    return size;
}

size_t GetSymbolSizeEx(uintptr_t libAddr)
{
    xdl_info_t info;
    void* cache = NULL;
    if (xdl_addr((void*)libAddr, &info, &cache) == 0)
        return NULL;
    xdl_addr_clean(&cache);
    return info.dli_ssize;
}

const char* GetSymbolName(uintptr_t libAddr)
{
    xdl_info_t info;
    void* cache = NULL;
    if (xdl_addr((void*)libAddr, &info, &cache) == 0)
        return NULL;
    xdl_addr_clean(&cache);
    return info.dli_sname;
}

bool SetMemoryPermission(uintptr_t addr, size_t len, p_flag* type)
{
    if (addr == NULL || len == 0) return false;

    int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    if (type != NULL) {
        prot = PROT_NONE;
        if (type->bRead)
            prot |= PROT_READ;
        if (type->bWrite)
            prot |= PROT_WRITE;
        if (type->bExecute)
            prot |= PROT_EXEC;
        if (type->bPrivate)
            prot |= PROT_NONE;
        if (type->bShared)
            prot = PROT_READ | PROT_WRITE;
    }
    unsigned long PageSize = sysconf(_SC_PAGESIZE);
    const uintptr_t start = PAGE_START(addr, PageSize);
    const uintptr_t end = PAGE_END((addr + len - 1), PageSize);
    int ret = mprotect((void*)start, end - start, prot);
    if (ret == -1)
    {
        HLOGE("Description Failed to set memory permission: %d-%s", errno, strerror(errno));
        return false;
    }
    return true;
}

p_flag* GetMemoryPermission(uintptr_t addr, pid_t pid)
{
    char buffer[2048] = { 0 }, fname[2048] = { 0 };
    uintptr_t start_address, end_address;
    p_flag* type = (p_flag*)calloc(1, sizeof(p_flag));
    if (pid < 0)
        strcpy(fname, "/proc/self/maps");
    else
        snprintf(fname, sizeof(fname), "/proc/%d/maps", pid);

    FILE* fp = fopen(fname, "rt");
    if (fp != NULL) {
        while (fgets(buffer, sizeof(buffer) - 1, fp)) {
            if (strstr(buffer, "---p")) {
                start_address = strtoul(strtok(buffer, "-"), NULL, 16);
                end_address = strtoul(strtok(NULL, " "), NULL, 16);
                if (addr >= start_address && addr <= end_address) {
                    type->bPrivate = true;
                    break;
                }
            }
            else if (strstr(buffer, "r--p")) {
                start_address = strtoul(strtok(buffer, "-"), NULL, 16);
                end_address = strtoul(strtok(NULL, " "), NULL, 16);
                if (addr >= start_address && addr <= end_address) {
                    type->bRead = true;
                    type->bPrivate = true;
                    break;
                }
            }
            else if (strstr(buffer, "rw-p")) {
                start_address = strtoul(strtok(buffer, "-"), NULL, 16);
                end_address = strtoul(strtok(NULL, " "), NULL, 16);
                if (addr >= start_address && addr <= end_address) {
                    type->bRead = true;
                    type->bWrite = true;
                    type->bPrivate = true;
                    break;
                }
            }
            else if (strstr(buffer, "r-xp")) {
                start_address = strtoul(strtok(buffer, "-"), NULL, 16);
                end_address = strtoul(strtok(NULL, " "), NULL, 16);
                if (addr >= start_address && addr <= end_address) {
                    type->bRead = true;
                    type->bExecute = true;
                    type->bPrivate = true;
                    break;
                }
            }
            else if (strstr(buffer, "rwxp")) {
                start_address = strtoul(strtok(buffer, "-"), NULL, 16);
                end_address = strtoul(strtok(NULL, " "), NULL, 16);
                if (addr >= start_address && addr <= end_address) {
                    type->bRead = true;
                    type->bWrite = true;
                    type->bExecute = true;
                    type->bPrivate = true;
                    break;
                }
            }
            else if (strstr(buffer, "rw-s")) {
                start_address = strtoul(strtok(buffer, "-"), NULL, 16);
                end_address = strtoul(strtok(NULL, " "), NULL, 16);
                if (addr >= start_address && addr <= end_address) {
                    type->bRead = true;
                    type->bWrite = true;
                    type->bShared = true;
                    break;
                }
            }
        }
        fclose(fp);
    }
    return type;
}

void WriteMemory(void* addr, void* data, size_t size, bool vp)
{
    Unprotect((uintptr_t)addr, vp ? size : 0);
    memcpy(addr, data, size);
    cacheflush((uintptr_t)addr, (uintptr_t)addr + size, 0);
}

void* ReadMemory(void* addr, void* data, size_t size, bool vp)
{
    Unprotect((uintptr_t)addr, vp ? size : 0);
    memcpy(data, addr, size);
    return data;
}

void MemoryFill(void* addr, uint8_t value, size_t size, bool vp)
{
    Unprotect((uintptr_t)addr, vp ? size : 0);
    memset(addr, value, size);
    cacheflush((uintptr_t)addr, (uintptr_t)addr + size, 0);
}

void PLTInternal(void* addr, void* func, void** original)
{
    if (addr == NULL || func == NULL) return;
    Unprotect((uintptr_t)addr, sizeof(uintptr_t));
    if (original != NULL)
        *((uintptr_t*)original) = *(uintptr_t*)addr;
    *(uintptr_t*)addr = (uintptr_t)func;
    cacheflush((uintptr_t)addr, (uintptr_t)addr + sizeof(uintptr_t), 0);
}

//inline hook
void* InlineHookSymAddr(void* sym_addr, void* new_func, void** original)
{
    //1.检测addr是T还是A模式
    if (TEST_BIT0((uintptr_t)sym_addr)) {
        return InlineHookThumb((void*)CLEAR_BIT0((uintptr_t)sym_addr), new_func, original);
    }
    else {
        return InlineHookARM(sym_addr, new_func, original);
    }
    //2.检测符号大小
    //3.短函数hook
}

void* InlineHookFuncAddr(void* func_addr, void* new_func, void** original, i_set inst_set)
{

}

void CancelHook(void* hook)
{
    SetInlineHookState((InlineHookInfo*)hook, DISABLE_HOOK);
}

void RecoverHook(void* hook)
{
    SetInlineHookState((InlineHookInfo*)hook, ENABLE_HOOK);
}


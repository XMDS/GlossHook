#include "Gloss.h"

#include <stdio.h> //snprintf fopen
#include <string.h> //strcpy strstr
#include <stdlib.h> //strtoul
#include <errno.h>
#include <sys/mman.h> //mprotect

#include "GConst.h"
#include "GLog.h"
#include "xdl/xdl.h"

#ifdef __arm__
uintptr_t GlossGetLibBase(const char* libName, pid_t pid)
{
    if (libName == NULL) return 0;
    uintptr_t address = 0;
    char buffer[2048] = { 0 }, fname[256] = { 0 };
    bool is_self = (pid < 0);
    snprintf(fname, sizeof(fname), is_self ? "/proc/self/maps" : "/proc/%d/maps", pid);

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
#endif // __arm__

size_t GlossGetLibLength(const char* libName, pid_t pid)
{
    if (libName == NULL) return 0;
    uintptr_t start_address = 0, end_address = 0;
    size_t total_length = 0;
    char buffer[2048] = { 0 }, fname[2048] = { 0 };
    bool is_self = (pid < 0);
    snprintf(fname, sizeof(fname), is_self ? "/proc/self/maps" : "/proc/%d/maps", pid);

    FILE* fp = fopen(fname, "rt");
    if (fp != NULL)
    {
        while (fgets(buffer, sizeof(buffer) - 1, fp))
        {
            if (strstr(buffer, libName))
            {
                const char* secondPart = strchr(buffer, '-');
                start_address = (uintptr_t)strtoul(buffer, NULL, 16);
                if (secondPart != NULL) {
                    end_address = (uintptr_t)strtoul(secondPart + 1, NULL, 16);
                    total_length += end_address - start_address;
                }
            }
        }
        fclose(fp);
    }
    return total_length;
}

uintptr_t GlossGetLibBias(const char* libName)
{
    gloss_lib handle = GlossOpen(libName);
    if (NULL == handle) return 0;
    uintptr_t address = GlossGetLibBiasEx(handle);
    GlossClose(handle, false);
    return address;
}

uintptr_t GlossGetLibBiasEx(gloss_lib handle)
{
    xdl_info_t info;
    if (xdl_info(handle, XDL_DI_DLINFO, &info) == -1)
        return 0;
    return (uintptr_t)info.dli_fbase;
}

gloss_lib GlossOpen(const char* libName)
{
    gloss_lib xdl_handle = xdl_open(libName, XDL_TRY_FORCE_LOAD);
    if (NULL == xdl_handle) {
        if (NULL != dlopen(libName, RTLD_LAZY))
            xdl_handle = xdl_open(libName, XDL_DEFAULT);
    }
    return xdl_handle;
}

int GlossClose(gloss_lib handle, bool is_dlclose)
{
    auto dl_handle = xdl_close(handle);
    if (dl_handle) return is_dlclose ? dlclose(dl_handle) : 0;
    return 0;
}

const char* GlossGetLibPath(gloss_lib handle)
{
    xdl_info_t info;
    if (xdl_info(handle, XDL_DI_DLINFO, &info) == -1)
        return NULL;
    return info.dli_fname;
}

const char* GlossGetLibPathEx(uintptr_t libAddr)
{
    xdl_info_t info;
    void* cache = NULL;
    if (xdl_addr((void*)libAddr, &info, &cache) == 0)
        return NULL;
    xdl_addr_clean(&cache);
    return info.dli_fname;
}

size_t GlossGetLibFileSize(const char* libName)
{
    size_t size = 0;
    gloss_lib handle = GlossOpen(libName);
    if (NULL == handle) return 0;
    FILE* file = fopen(GlossGetLibPath(handle), "rb");
    if (file != NULL) {
        fseek(file, 0, SEEK_END);
        size = ftell(file);
        fclose(file);
    }
    GlossClose(handle, false);
    return size;
}

uintptr_t GlossSymbol(gloss_lib handle, const char* name, size_t* sym_size)
{
    void* addr = xdl_sym(handle, name, sym_size);
    if (NULL == addr)
        addr = xdl_dsym(handle, name, sym_size);
    return (uintptr_t)addr;
}

uintptr_t GlossSymbolEx(uintptr_t libAddr, const char* name, size_t* sym_size)
{
    auto handle = GlossOpen(GlossGetLibPathEx(libAddr));
    if (NULL == handle) return 0;
    auto addr = GlossSymbol(handle, name, sym_size);
    GlossClose(handle, false);
    return addr;
}

const char* GlossAddrInfo(uintptr_t sym_addr, size_t* sym_size)
{
    xdl_info_t info;
    void* cache = NULL;
    if (xdl_addr((void*)sym_addr, &info, &cache) == 0)
        return NULL;
    xdl_addr_clean(&cache);
    if (sym_size != NULL)
        *sym_size = info.dli_ssize;
    return info.dli_sname;
}


bool SetMemoryPermission(uintptr_t addr, size_t len, p_flag* type)
{
    if (!addr || !len) return false;

    int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
    if (type != NULL) {
        if (type->bPrivate)
            prot = PROT_NONE;
        if (type->bShared)
            prot = PROT_READ | PROT_WRITE;
        if (type->bRead)
            prot |= PROT_READ;
        if (type->bWrite)
            prot |= PROT_WRITE;
        if (type->bExecute)
            prot |= PROT_EXEC;

    }
    unsigned long PageSize = sysconf(_SC_PAGESIZE);
    const uintptr_t start = PAGE_START(addr, PageSize);
    const uintptr_t end = PAGE_END((addr + len - 1), PageSize);
    int ret = mprotect((void*)start, end - start, prot);
    if (ret == -1)
    {
        GLOGE("Description Failed to set memory permission: %d-%s", errno, strerror(errno));
        return false;
    }
    return true;
}

bool GetMemoryPermission(uintptr_t addr, p_flag* type, pid_t pid)
{
    bool status = false;
    if (!addr || !type) return status;
    char buffer[2048] = { 0 }, fname[2048] = { 0 };
    uintptr_t start_address, end_address;
    bool is_self = (pid < 0);
    snprintf(fname, sizeof(fname), is_self ? "/proc/self/maps" : "/proc/%d/maps", pid);

    FILE* fp = fopen(fname, "rt");
    if (fp != NULL) {
        while (fgets(buffer, sizeof(buffer) - 1, fp)) {
            if (strstr(buffer, "---p")) {
                start_address = strtoul(strtok(buffer, "-"), NULL, 16);
                end_address = strtoul(strtok(NULL, " "), NULL, 16);
                if (addr >= start_address && addr <= end_address) {
                    status = true;
                    type->bPrivate = true;
                    break;
                }
            }
            else if (strstr(buffer, "r--p")) {
                start_address = strtoul(strtok(buffer, "-"), NULL, 16);
                end_address = strtoul(strtok(NULL, " "), NULL, 16);
                if (addr >= start_address && addr <= end_address) {
                    status = true;
                    type->bRead = true;
                    type->bPrivate = true;
                    break;
                }
            }
            else if (strstr(buffer, "rw-p")) {
                start_address = strtoul(strtok(buffer, "-"), NULL, 16);
                end_address = strtoul(strtok(NULL, " "), NULL, 16);
                if (addr >= start_address && addr <= end_address) {
                    status = true;
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
                    status = true;
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
                    status = true;
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
                    status = true;
                    type->bRead = true;
                    type->bWrite = true;
                    type->bShared = true;
                    break;
                }
            }
        }
        fclose(fp);
    }
    return status;
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
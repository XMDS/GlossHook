#ifndef ANDROID_ARMHOOK_H
#define ANDROID_ARMHOOK_H

#ifndef __ANDROID__
#error error
#else
#if !(defined __arm__) && !(defined __aarch64__)
#error error
#endif
#endif // __ANDROID__

#ifdef __cplusplus
extern "C" {
#endif                                           

#include <unistd.h> //lseek PAGE_SIZE

#ifdef __arm__
#define GET_INST_SET(addr) (addr & 1 ? i_set::$THUMB : i_set::$ARM)
#endif
	
	typedef void* lib_h;
	typedef struct PermissionFlags
	{
		int8_t bRead : 1;
		int8_t bWrite : 1;
		int8_t bExecute : 1;
		int8_t bShared : 1;
		int8_t bPrivate : 1;
		int8_t align : 3;
	} p_flag;

	typedef enum { NONE, $THUMB, $ARM, $ARM64 } i_set; //InstructionSet

	/*
	* Get the starting address where the library was first loaded into memory(image base).
	* libName: Library filename.
	* pid: Process ID(Defaults to -1, the current process).
	* return: Absolute address.
	*/
	uintptr_t GetLibBase(const char* libName, pid_t pid = -1);

	/*
	* Get the length of the library loaded into memory.
	* libName: Library filename.
	* pid: Process ID(Defaults to -1, the current process).
	* return: Library length.
	*/
	size_t GetLibLength(const char* libName, pid_t pid = -1);

	/*
	* Get a handle to the library.
	* libName: Library filename or pathname.
	* return: Library handle.
	*/
	lib_h GetLibHandle(const char* libName);

	/*
	* Close a library loaded by the 'GetLibHandle' function.
	* handle: Library handle (from 'GetLibHandle' func).
	*/
	void CloseLib(lib_h handle);

	/*
	* According to the handle of the library, Get the starting address where the library was first loaded into memory(image base).
	* handle: Library handle (from 'GetLibHandle' func).
	* return: Absolute address.
	*/
	uintptr_t GetLibBaseFromHandle(lib_h handle);

	/*
	* Get the file path of the library based on the memory address of the library.
	* libAddr: Specifies a library-wide memory address.
	* return: Library file absolute path.
	*/
	const char* GetLibFilePath(uintptr_t libAddr);

	/*
	* Get the file path of the library based on the handle of the library.
	* handle: Library handle (from 'GetLibHandle' func).
	* return: Library file absolute path.
	*/
	const char* GetLibFilePathFromHandle(lib_h handle);

	/*
	* Get the file size of the library based on the handle of the library.
	* libName: Library filename or pathname.
	* return: Library file size.
	*/
	size_t GetLibFileSize(const char* libName);

	/*
	* Get the absolute address of symbol based on the symbol.
	* handle: Library handle(from 'GetLibHandle' func).
	* name: Symbol name.
	* return: Symbol absolute address.
	*/
	uintptr_t GetSymbolAddress(lib_h handle, const char* name);

	/*
	* Get the absolute address of symbol based on the symbol.
	* libAddr: Specifies a library-wide memory address.
	* name: Symbol name.
	* return: Symbol absolute address.
	*/
	uintptr_t GetSymbolAddressEx(uintptr_t libAddr, const char* name);

	/*
	* Get the size of the symbol code in memory based on the symbol(size in ELF, not the symbol itself).
	* handle: Library handle(from 'GetLibHandle' func).
	* name: Symbol name.
	* return: Symbol size.
	*/
	size_t GetSymbolSize(lib_h handle, const char* name);

	/*
	* According to the memory address of the library, obtain the size of the symbol code where the address is located in memory (the size in ELF, not the symbol itself).
	* SymAddr: Specifies a Symbol-wide memory address.
	* return: Symbol size.
	*/
	size_t GetSymbolSizeEx(uintptr_t SymAddr);

	/*
	* Get the symbolic name where the address is located.
	* SymAddr: Specifies a Symbol-wide memory address.
	* return: Symbol name.
	*/
	const char* GetSymbolName(uintptr_t SymAddr);

	/*
	* Set the access permission of the specified length of memory.
	* addr: The memory address for which permissions need to be set.
	* len: Address length.
	* type: Permission type(see 'PermissionFlags'), If NULL, the default settings are readable, writable, executable.
	* return: Returns 'true' on success, 'false' on failure.
	*/
	bool SetMemoryPermission(uintptr_t addr, size_t len, p_flag* type);

	/*
	* Cancel the protection permission of the specified length of memory, set to readable, writable, executable.
	* addr: The memory address for which permissions need to be set.
	* len: Address length(Defaults to a full page of memory).
	* return: Returns 'true' on success, 'false' on failure.
	*/
	inline bool Unprotect(uintptr_t addr, size_t len = PAGE_SIZE)
	{
		return SetMemoryPermission(addr, len, NULL);
	}

	/*
	* Get access rights to process memory address.
	* addr: The memory address where permission needs to be obtained.
	* pid: Process ID(Defaults to -1, the current process).
	* return: Permission type(see 'PermissionFlags').
	*/
	p_flag* GetMemoryPermission(uintptr_t addr, pid_t pid = -1);

	/*
	* Check whether the memory address access permission of the current process is executable.
	* addr: The memory address that needs to be checked.
	* return: Judging success returns 'true', 'false' on failure.
	*/
	inline bool IsAddrExecute(uintptr_t addr)
	{
		return GetMemoryPermission(addr)->bExecute ? true : false;
	}

	/*
	* Write the content of the specified 'size' 'data' into memory, and set whether to cancel the memory protection permission.
	* addr: The memory address where data needs to be written.
	* data: The content of the data to be written.
	* size: Length of data written.
	* vp: 'true' to cancel the memory protection permission, 'false' to keep the original permission. Defaults to 'true' (because ARM's memory is more strict and safe).
	*/
	void WriteMemory(void* addr, void* data, size_t size, bool vp = true);

	/*
	* Read the memory of the specified 'size' at the address, save the content to 'data', and set whether to cancel the memory protection permission.
	* addr: The memory address to read data from.
	* data: Where to save the data.
	* size: Length of read data.
	* vp: 'true' to cancel the memory protection permission, 'false' to keep the original permission. Defaults to 'true' (because ARM's memory is more strict and safe).
	* return: Read data.
	*/
	void* ReadMemory(void* addr, void* data, size_t size, bool vp = true);

	/*
	* Set all the contents of the specified size of memory to 'value', and set whether to cancel the memory protection permission.
	* addr: The memory address that needs to be set.
	* value: The value to be written.
	* size: Number of bytes to write.
	* vp: 'true' to cancel the memory protection permission, 'false' to keep the original permission. Defaults to 'true' (because ARM's memory is more strict and safe).
	*/
	void MemoryFill(void* addr, uint8_t value, size_t size, bool vp = true);

	/*
	* PLT Hook. But it is internal, it is not a real PLT Hook, it is actually a GOT Hook,
	  the hook is implemented by replacing the function pointer of the .GOT segment, and the original function pointer is retained.
	* addr: Requires the location of the Hook, the absolute address of the .GOT segment.
	* func: New function address.
	* original: Original function pointer, can be NULL.
	*/
	void PLTInternal(void* addr, void* func, void** original);

	void* InlineHookSymAddr(void* sym_addr, void* new_func, void** original);
	void CancelHook(void* hook);
	void RecoverHook(void* hook);

#ifdef __cplusplus
	}

	/*
	* Write any type of value to memory.
	*/
	template <typename T1, typename T2>
	inline static void WriteMemory(T2 addr, T1 value, bool vp = true)
	{
		WriteMemory((void*)addr, &value, sizeof(T1), vp);
	}

	/*
	* Read any type of value from memory.
	*/
	template <typename T1, typename T2>
	inline static T1 ReadMemory(T2 addr, bool vp = true)
	{
		if (vp) Unprotect((uintptr_t)addr, sizeof(T1));
		return *reinterpret_cast<T1*>(addr);
	}

	/*
	* GOTHook template, complete type conversion.
	*/
	template <class A, class B, class C>
	inline static void GOTHook(A addr, B func, C original)
	{
		return PLTInternal(reinterpret_cast<void*>(addr), reinterpret_cast<void*>(func), reinterpret_cast<void**>(original));
	}
	template <class A, class B>
	inline static void GOTHook(A addr, B func)
	{
		return PLTInternal(reinterpret_cast<void*>(addr), reinterpret_cast<void*>(func), NULL);
	}

	/*
	* InlineHook template, complete type conversion.
	*/
	template <class A, class B, class C>
	inline static void* InlineHook(A addr, B func, C original)
	{
		return InlineHookSymAddr(reinterpret_cast<void*>(addr), reinterpret_cast<void*>(func), reinterpret_cast<void**>(original));
	}
	template <class A, class B>
	inline static void* InlineHook(A addr, B func)
	{
		return InlineHookSymAddr(reinterpret_cast<void*>(addr), reinterpret_cast<void*>(func), NULL);
	}
#endif
#endif
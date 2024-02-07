#pragma once
#include "parsing.h"

struct _stack_params
{
	DWORD ReturnAddress;
	DWORD lpvReserved = NULL;
	DWORD fdwReason = DLL_PROCESS_ATTACH;
	DWORD hinstDLL;
}; 

//Forward Declarations

int GetProcessHandle(const char* const name);

int GetLoadedModules();

int MapDll(const MODULE* const target);

int HijackThread(const int cfg);

int CreateNewThread(const int cfg);

//Macros

#define wpm(lpBaseAddress, lpBuffer, nSize) WriteProcessMemory(process, reinterpret_cast<void*>(lpBaseAddress), lpBuffer, nSize, nullptr)

#define __VirtualAllocEx(dwSize, flProtect) VirtualAllocEx(process, nullptr, dwSize, MEM_COMMIT | MEM_RESERVE, flProtect)

#define GET_ENTRY_POINT(image, base) image.NT_HEADERS->OptionalHeader.AddressOfEntryPoint + base

#define HIJACK_THREAD 1

#define RUN_TLS_CALLBACKS 2
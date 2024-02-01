#pragma once
#include "parsing.h"

//Forward Declarations

int GetProcessHandle(const char* const name);

int GetLoadedModules();

int MapDll(const MODULE* const target);

int HijackThread();

//Macros

#define wpm(address, buffer, size) WriteProcessMemory(process, reinterpret_cast<void*>(address), buffer, size, nullptr)
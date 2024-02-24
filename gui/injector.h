#pragma once

#define HIJACK_THREAD        0x01

#define RUN_TLS_CALLBACKS    0x02

#define METHOD_LOADLIBRARY   0x04

#define METHOD_MANUAL_MAP    0x08

#define METHOD_HIJACK_THREAD 0x10

__declspec(dllimport) int InjectDll(const HANDLE process, const char* FilePath, int config);
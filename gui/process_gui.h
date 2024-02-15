#pragma once
#include "pch.h"

#define METHOD_LOADLIBRARY  0
#define METHOD_MANUAL_MAP   1

#define METHOD_CREATE_THREAD 0
#define METHOD_HIJACK_THREAD 1

struct _config
{
	bool SaveConfig = false;

	bool CheckHandles = true;
	bool CaseSensitiveFilter = false;

	int InjectionMethod = METHOD_LOADLIBRARY;
	int ExecutionMethod = METHOD_CREATE_THREAD;

	bool RunTlsCallbacks = true;
};

int HandlePidInput(const int pid);

bool GetProcessList(const std::string& filter, const _config& cfg);
#pragma once
#include "pch.h"
#include "injector.h"

#define _METHOD_LOADLIBRARY  0
#define _METHOD_MANUAL_MAP   1

#define _METHOD_CREATE_THREAD 0
#define _METHOD_HIJACK_THREAD 1

struct _config
{
	bool SaveConfig = false;

	bool CheckHandles = true;
	bool CaseSensitiveFilter = false;

	int InjectionMethod = _METHOD_LOADLIBRARY;
	int ExecutionMethod = _METHOD_CREATE_THREAD;

	bool RunTlsCallbacks = true;
};

int HandlePidInput(const int pid);

bool GetProcessList(const std::string& filter, const _config& cfg);
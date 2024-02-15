#include "pch.h"
#include "process_gui.h"
#include "gui_helpers.h"

#pragma warning(disable:4996)

extern std::vector<std::string> ProcessList;
extern std::vector<DWORD> PidList;


bool GetProcessList(const std::string& filter, const _config& cfg)
{
	const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snapshot == INVALID_HANDLE_VALUE) return 0;
	
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(snapshot, &pe32))
	{
		ProcessList.clear();
		PidList.clear();	

		static std::string LowercaseFilter;
		LowercaseFilter = filter;

		if (!cfg.CaseSensitiveFilter)
		{
			for (int x = 0; x < filter.size(); ++x) {
				LowercaseFilter[x] = std::tolower(filter[x]);
			}
		}

		static char ProcessName[MAX_PATH] = "\0";

		do
		{
			wcstombs(ProcessName, pe32.szExeFile, MAX_PATH);

			if (!filter.empty())
			{
				std::string cmp_ProcessName = ProcessName;

				if (!cfg.CaseSensitiveFilter)
				{
					for (char c : ProcessName) {
						cmp_ProcessName += std::tolower(c);
					}
				}
				else cmp_ProcessName = ProcessName;

				if (cmp_ProcessName.find(filter) == std::string::npos) continue;
			}


			if (cfg.CheckHandles)
			{
				const HANDLE process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, pe32.th32ProcessID);
				if (process == NULL) continue;
				else CloseHandle(process);
			}
			
			PidList.emplace_back(pe32.th32ProcessID);
			ProcessList.emplace_back(ProcessName);

			memset(ProcessName, '\0', sizeof(ProcessName));

		} while (Process32Next(snapshot, &pe32));
	}

	CloseHandle(snapshot);
	return 1;
}


int HandlePidInput(const int pid)
{
	const HANDLE process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, static_cast<DWORD>(pid));

	if (process != INVALID_HANDLE_VALUE)
	{
		static std::string buffer(MAX_PATH, NULL);
		K32GetProcessImageFileNameA(process, buffer.data(), MAX_PATH);
		CloseHandle(process);

		buffer.erase(0, buffer.find_last_of('\\') + 1);
		for (int x = 0; x < ProcessList.size(); ++x)
		{
			if (_stricmp(ProcessList[x].c_str(), buffer.c_str()) == 0)
			{
				return x;
			}
		}
	}

	return 0;
}
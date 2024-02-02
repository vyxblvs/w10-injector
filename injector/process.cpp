#include "pch.h"
#include "process.h"


int GetProcessHandle(const char* const name)
{
	const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (snapshot == INVALID_HANDLE_VALUE) return -5;

	wchar_t wName[MAX_PATH];
	mbstowcs_s(nullptr, wName, name, MAX_PATH);

	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	int status = 1;

	if (Process32First(snapshot, &pe32))
	{
		do
		{
			if (_wcsicmp(wName, pe32.szExeFile) == 0)
			{
				process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, false, pe32.th32ProcessID);
				if (!process) { status = -6; break; }

				BOOL is_x86;
				IsWow64Process(process, &is_x86);
				if (!is_x86) status = -7;
				
				break;
			}

		} while (Process32Next(snapshot, &pe32));
	}

	CloseHandle(snapshot);
	return status;
}


int GetLoadedModules()
{
	DWORD size;
	HMODULE handles[1024];

	if (!K32EnumProcessModules(process, handles, sizeof(handles), &size)) return -8;

	for (int x = 0; x < size / sizeof(HMODULE); ++x)
	{
		char path[MAX_PATH + 1];
		const UINT length = K32GetModuleFileNameExA(process, handles[x], path, MAX_PATH);
		if (!length || length > MAX_PATH) return -9;

		path[length] = '\0';
		MODULE ModuleStruct;
		
		ModuleStruct.image.path = new char[length + 1];
		strcpy_s(ModuleStruct.image.path, length + 1, path);

		ModuleStruct.ImageBase = reinterpret_cast<DWORD>(handles[x]);
		LoadedModules.emplace_back(ModuleStruct);
	}

	return true;
}


int MapDll(const MODULE* const target)
{
	const IMAGE_DATA* const image = &target->image;
	const IMAGE_SECTION_HEADER* const sections = image->sections;

	//Mapping headers
	if (!wpm(target->ImageBase, image->LocalBase, sections[0].PointerToRawData)) return -15;

	DWORD old;
	VirtualProtectEx(process, reinterpret_cast<void*>(target->ImageBase), sections[0].PointerToRawData, PAGE_READONLY, &old);

	//Mapping sections
	for (int x = 0; x < image->NT_HEADERS->FileHeader.NumberOfSections; ++x)
	{
		void* const address = reinterpret_cast<void*>(target->ImageBase + sections[x].VirtualAddress);
		const void* const section = image->LocalBase + sections[x].PointerToRawData;

		if (!wpm(address, section, sections[x].SizeOfRawData)) return -16;

		VirtualProtectEx(process, address, sections[x].SizeOfRawData, sections[x].Characteristics / 0x1000000, &old);
	}

	return 1;
} 


int HijackThread()
{
	const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (snapshot == INVALID_HANDLE_VALUE) return -17;

	THREADENTRY32 te32;
	te32.dwSize = sizeof(THREADENTRY32);
	const DWORD PID = GetProcessId(process);
	HANDLE thread = nullptr;

	//Locating a thread within the target process
	if (Thread32First(snapshot, &te32))
	{
		do
		{
			if (te32.th32OwnerProcessID == PID)
			{
				thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, false, te32.th32ThreadID);
				if (thread) break; 
			}

		} while (Thread32Next(snapshot, &te32));
	}
	CloseHandle(snapshot);

	if (!thread) return -18;

	if (Wow64SuspendThread(thread) == static_cast<DWORD>(-1))
	{
		CloseHandle(thread);
		return -19;
	}

	int status = 1;
	constexpr int reserved = NULL;
	constexpr int reason = DLL_PROCESS_ATTACH;

	//Getting thread context (GPR's only)
	WOW64_CONTEXT context { NULL };
	context.ContextFlags = WOW64_CONTEXT_CONTROL;
	if (!Wow64GetThreadContext(thread, &context)) { status = -20; goto exit; }

	// Pushing DllMain parameters & return address onto thread stack
	context.Esp -= 4; // LPVOID lpvReserved
	if (!wpm(context.Esp, &reserved, sizeof(LPVOID))) { status = -21; goto exit; }

	context.Esp -= 4; // DWORD fdwReason
	if (!wpm(context.Esp, &reason, sizeof(DWORD))) { status = -22; goto exit; }

	context.Esp -= 4; // HINSTANCE hinstDLL
	if (!wpm(context.Esp, &modules[0].ImageBase, sizeof(HINSTANCE))) { status = -23; goto exit; }

	context.Esp -= 4; // Return address
	if (!wpm(context.Esp, &context.Eip, sizeof(DWORD))) { status = -24; goto exit; }

	context.Eip = modules[0].ImageBase + modules[0].image.NT_HEADERS->OptionalHeader.AddressOfEntryPoint;
	status = Wow64SetThreadContext(thread, &context);
	if (!status) { status = -25; goto exit; }

exit:
	ResumeThread(thread);
	CloseHandle(thread);
	return status;
}


int CreateNewThread()
{
	BYTE shellcode[] =
	{
		0x8B, 0x04, 0x24,                               // mov eax, [esp]
		0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,       // mov [esp], 0          (0:    lpvReserved)
		0xC7, 0x44, 0x24, 0xFC, 0x01, 0x00, 0x00, 0x00, // mov [esp-4], 1        (1:    DLL_PROCESS_ATTACH | fdwReason)
		0xC7, 0x44, 0x24, 0xF8, 0x00, 0x00, 0x00, 0x00, // mov [esp-8], 0        (0:    PLACEHOLDER FOR hinstDLL)
		0x83, 0xEC, 0x0C,                               // sub esp, 0xC
		0x89, 0x04, 0x24,                               // mov [esp], eax        (eax:  return address)
		0xE9, 0x00, 0x00, 0x00, 0x00                    // jmp 0                 (0:    PLACEHOLDER FOR ENTRY POINT)
	};

	void* const ShellAddress = VirtualAllocEx(process, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!ShellAddress) return -26;

	const MODULE& TargetModule = modules[0];
	const DWORD EntryPoint = TargetModule.image.NT_HEADERS->OptionalHeader.AddressOfEntryPoint + TargetModule.ImageBase;

	*reinterpret_cast<DWORD*>(shellcode + 33) = EntryPoint - (reinterpret_cast<DWORD>(ShellAddress) + 37); // ENTRY POINT
	*reinterpret_cast<DWORD*>(shellcode + 22) = TargetModule.ImageBase; // hinstDLL

	if (!wpm(ShellAddress, shellcode, sizeof(shellcode))) return -27;

	if (!CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(ShellAddress), nullptr, 0, nullptr)) return -28;

	return 1;
}
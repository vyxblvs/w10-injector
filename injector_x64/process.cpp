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


void* GetTlsEp(void* EntryPoint)
{
	BYTE shellcode[] =
	{
		0x48, 0x31, 0xC0,                   // xor rax, rax
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rbx, 0
		0x48, 0x8B, 0x0C, 0x8C,             // mov rcx, [rbx+rax*4]
		0x48, 0x85, 0xC9,                   // test rcx, rcx
		0x74, 0x0A,                         // je 0x0A
		0x6A, 0x00,                         // push 0
		0x6A, 0x01,                         // push 1
		0xFF, 0x74, 0x24, 0x0C,             // push [rsp+0x0C]
		0xFF, 0xD1,                         // call rcx
		0x48, 0xFF, 0xC0,                   // inc rax
		0xEB, 0xE8,                         // jmp 0xE8
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, 0
		0xFF, 0xE0,                         // jmp rax
	};

	const MODULE& TargetModule = modules[0];
	const auto TlsDirectory = ConvertRva<const IMAGE_TLS_DIRECTORY64*>(TargetModule.image.LocalBase, DATA_DIR((&TargetModule.image), IMAGE_DIRECTORY_ENTRY_TLS).VirtualAddress, &TargetModule.image);

	// The TLS directory is resolved in ResolveImports, and then mapped into memory. TlsDirectory->AddressOfCallBacks is valid.
	*reinterpret_cast<DWORD64*>(shellcode + 5) = TlsDirectory->AddressOfCallBacks;
	*reinterpret_cast<void**>(shellcode + 39) = EntryPoint;

	void* AllocatedMem = __VirtualAllocEx(sizeof(shellcode), PAGE_EXECUTE_READWRITE);
	if (!AllocatedMem) return nullptr;

	if (!wpm(AllocatedMem, shellcode, sizeof(shellcode))) return nullptr;

	return AllocatedMem;
}


int HijackThread(const int cfg)
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
	_stack_params stack_params;

	//Getting thread context (GPR's only)
	WOW64_CONTEXT context{ NULL };
	context.ContextFlags = WOW64_CONTEXT_CONTROL;
	if (!Wow64GetThreadContext(thread, &context)) { status = -20; goto exit; }

	context.Esp -= 16;
	stack_params.hinstDLL = modules[0].ImageBase;
	stack_params.ReturnAddress = context.Eip;

	if (!wpm(context.Esp, &stack_params, sizeof(_stack_params))) return -21;

	context.Eip = GET_ENTRY_POINT(modules[0].image, modules[0].ImageBase);

	if (cfg & RUN_TLS_CALLBACKS)
	{
		context.Eip = reinterpret_cast<DWORD64>(GetTlsEp(reinterpret_cast<void*>(context.Eip)));
		if (!context.Eip) return -69;
	}

	status = Wow64SetThreadContext(thread, &context);
	if (!status) { status = -25; goto exit; }

exit:
	ResumeThread(thread);
	CloseHandle(thread);
	return status;
}


int CreateNewThread(const int cfg)
{
	BYTE shellcode[] =
	{
		0x48, 0x31, 0xC0,                   // xor rax, rax
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rbx, 0
		0x48, 0x8B, 0x0C, 0x8C,             // mov rcx, [rbx+rax*4]
		0x48, 0x85, 0xC9,                   // test rcx, rcx
		0x74, 0x0A,                         // je 0x0A
		0x6A, 0x00,                         // push 0
		0x6A, 0x01,                         // push 1
		0xFF, 0x74, 0x24, 0x0C,             // push [rsp+0x0C]
		0xFF, 0xD1,                         // call rcx
		0x48, 0xFF, 0xC0,                   // inc rax
		0xEB, 0xE8,                         // jmp 0xE8
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, // mov rax, 0
		0xFF, 0xE0,                         // jmp rax
	};

	void* ShellAddress = __VirtualAllocEx(sizeof(shellcode), PAGE_EXECUTE_READWRITE);
	if (!ShellAddress) return -26;

	const MODULE& TargetModule = modules[0];
	const DWORD EntryPoint = GET_ENTRY_POINT(TargetModule.image, TargetModule.ImageBase);

	*reinterpret_cast<DWORD*>(shellcode + 33) = EntryPoint - (reinterpret_cast<DWORD>(ShellAddress) + 37); // ENTRY POINT
	*reinterpret_cast<DWORD*>(shellcode + 22) = TargetModule.ImageBase; // hinstDLL

	if (!wpm(ShellAddress, shellcode, sizeof(shellcode))) return -27;

	if (cfg & RUN_TLS_CALLBACKS)
	{
		ShellAddress = GetTlsEp(ShellAddress);
		if (!ShellAddress) return -28;
	}

	if (!CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(ShellAddress), nullptr, 0, nullptr)) return -29;

	return 1;
}
#include "pch.h"
#include "parsing.h"


int GetDll(const char* const path, IMAGE_DATA* const buffer)
{
	if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) return -2;

	std::ifstream file(path, std::ios::binary | std::ios::ate);
	if (file.fail()) return -3;

	const UINT size = static_cast<UINT>(file.tellg());
	char* const image_ptr = new char[size];

	file.seekg(0, std::ios::beg);
	file.read(image_ptr, size);
	file.close();

	if (!buffer->path)
	{
		buffer->path = new char[MAX_PATH];
		strcpy_s(buffer->path, MAX_PATH, path);
	}
	
	buffer->LocalBase = image_ptr;
	buffer->NT_HEADERS = reinterpret_cast<IMAGE_NT_HEADERS64*>(image_ptr + *reinterpret_cast<DWORD64*>(image_ptr + 0x3C));
	buffer->sections = IMAGE_FIRST_SECTION(buffer->NT_HEADERS);

	if (buffer->NT_HEADERS->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return -4;

	return 1;
}


template <typename ptr> int FindModule(const char* const name, ptr buffer, const bool ReturnIndex = false)
{
	std::string path;
	std::vector<MODULE>* VectorPtr = &modules;

	for (char x = 0; x < 2; ++x, VectorPtr = &LoadedModules)
	{
		for (UINT y = 0; y < VectorPtr->size(); ++y)
		{
			path = VectorPtr->at(y).image.path;
			if (path.find('\\') != std::string::npos) path.erase(0, path.find_last_of('\\') + 1);

			if (_stricmp(path.c_str(), name) == 0)
			{
				if (ReturnIndex)
				{
					*reinterpret_cast<void**>(buffer) = VectorPtr;
					return y;
				}
				else
				{
					*reinterpret_cast<void**>(buffer) = &VectorPtr->at(y);
					return x;
				}
			}
		}
	}

	return -60;
}


int FindModuleDir(const char* const target, std::string dir, char* buffer)
{
	dir += '\\';
	WIN32_FIND_DATAA data;
	const HANDLE search = FindFirstFileExA((dir + '*').c_str(), FindExInfoBasic, &data, FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
	if (search == INVALID_HANDLE_VALUE) return -12;

	do
	{
		if (data.dwFileAttributes >= 256) continue;

		char path[MAX_PATH];
		strcpy_s(path, sizeof(path), (dir + data.cFileName).c_str());

		if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY && strcmp(data.cFileName, ".") && strcmp(data.cFileName, ".."))
		{
			if (FindModuleDir(target, path, buffer) > 0)
			{
				FindClose(search);
				return 1;
			}
		}

		else if (_stricmp(target, data.cFileName) == 0)
		{
			FindClose(search);
			strcpy_s(buffer, MAX_PATH, path);
			return 1;
		}

	} while (FindNextFileA(search, &data) && GetLastError() != ERROR_NO_MORE_FILES);

	SetLastError(0);
	FindClose(search);
	return -13;
}


int FindModuleDirWrapper(const char* const target, char* buffer)
{
	//An array of directories: The target process's main executable path, SysWOW64, and the windows directory (../windows/)
	static std::string dirs[3];
	if (dirs[0].empty())
	{
		char buffer[MAX_PATH];

		DWORD size = MAX_PATH;
		if (!QueryFullProcessImageNameA(process, 0, buffer, &size)) return -10;
		dirs[0] = buffer;
		dirs[0].erase(dirs[0].find_last_of('\\'), dirs[0].length());

		if (!GetWindowsDirectoryA(buffer, MAX_PATH)) return -11;
		dirs[1] = dirs[2] = buffer;
		dirs[1] += "\\SysWOW64";
	}

	for (int y = 0; y < 3; ++y)
	{
		const int status = FindModuleDir(target, dirs[y], buffer);
		if (status == 1) break;
		else if (y == 2) return status;
	}

	return 1;
}


int GetDependencies(const int i)
{
	//No pointers to modules[i] are created because the increase in size caused by FindModuleDir triggers relocation of the vector, invalidating any pointers to it.
	const auto ImportDirTable = ConvertRva<const IMAGE_IMPORT_DESCRIPTOR*>(modules[i].image.LocalBase, DATA_DIR((&modules[i].image), IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress, &modules[i].image);

	for (DWORD x = 0; ImportDirTable[x].Characteristics; ++x)
	{
		const auto ModuleName = ConvertRva<const char*>(modules[i].image.LocalBase, ImportDirTable[x].Name, &modules[i].image);

		MODULE* ModulePtr = nullptr;
		if (FindModule(ModuleName, &ModulePtr) == 0) continue;

		char ModulePath[MAX_PATH];
		int status = FindModuleDirWrapper(ModuleName, ModulePath);
		if (!status) return status;

		if (ModulePtr)
		{
			delete[] ModulePtr->image.path;
			ModulePtr->image.path = nullptr;
			status = GetDll(ModulePath, &ModulePtr->image);
		}
		else
		{
			modules.push_back({});
			status = GetDll(ModulePath, &modules.back().image);
		}

		if (!status) return status;
	}

	return 1;
}


void ApplyReloction(const MODULE* TargetModule)
{
	const auto image   = &TargetModule->image;
	const auto DataDir = DATA_DIR(image, IMAGE_DIRECTORY_ENTRY_BASERELOC);

	auto RelocBlock = ConvertRva<IMAGE_BASE_RELOCATION*>(image->LocalBase, DataDir.VirtualAddress, image);
	const BYTE* const FinalEntry = reinterpret_cast<BYTE*>(RelocBlock) + DataDir.Size;
	
	const DWORD64 PreferredBase = image->NT_HEADERS->OptionalHeader.ImageBase;
	const DWORD64 TargetBase    = TargetModule->ImageBase;

	while (reinterpret_cast<BYTE*>(RelocBlock) < FinalEntry)
	{
		const auto entry = reinterpret_cast<const WORD*>(RelocBlock) + 4;

		for (UINT y = 0; entry[y] && y < (RelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); ++y)
		{
			DWORD64* const RelocAddress = ConvertRva<DWORD64*>(image->LocalBase, (entry[y] % 0x1000) + RelocBlock->VirtualAddress, image);
			*RelocAddress = (*RelocAddress - PreferredBase) + TargetBase;
		}

		RelocBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(RelocBlock) + RelocBlock->SizeOfBlock);
	}
}


MODULE* GetForwarderModule(MODULE* ModulePtr, const char* const ImportName, const char** buffer)
{
	const auto image         = &ModulePtr->image;
	const auto MappedAddress = image->LocalBase;
	const auto ExportDirData = DATA_DIR(image, IMAGE_DIRECTORY_ENTRY_EXPORT);
	const auto ExportDir     = ConvertRva<IMAGE_EXPORT_DIRECTORY*>(MappedAddress, ExportDirData.VirtualAddress, image);
	const auto NamePtrTable  = ConvertRva<DWORD64*>(MappedAddress, ExportDir->AddressOfNames, image);
	const auto OrdinalTable  = ConvertRva<WORD*>(MappedAddress, ExportDir->AddressOfNameOrdinals, image);
	const auto ExportTable   = ConvertRva<DWORD64*>(MappedAddress, ExportDir->AddressOfFunctions, image);

	for (UINT x = 0; x < ExportDir->NumberOfFunctions; ++x)
	{
		const auto ExportName = ConvertRva<const char*>(MappedAddress, NamePtrTable[x], image);

		if (_stricmp(ImportName, ExportName) == 0)
		{
			const char* ExportString = ConvertRva<const char*>(MappedAddress, ExportTable[OrdinalTable[x]], image);
			std::string ForwarderStr = ExportString;

			ForwarderStr.erase(ForwarderStr.find_first_of('.'), ForwarderStr.length());
			ForwarderStr += ".dll";

			MODULE* ForwardedModule = nullptr;
			if (FindModule(ForwarderStr.c_str(), &ForwardedModule) == -1)
			{
				char ModulePath[MAX_PATH];
				FindModuleDirWrapper(ForwarderStr.c_str(), ModulePath);

				modules.push_back({});
				GetDll(ModulePath, &modules.back().image);

				ForwardedModule = &modules.back();
			}

			*buffer = ExportString + (ForwarderStr.size() - 3); //The name of a function in the module its forwarded from can be different
			return ForwardedModule;
		}
	}

	return nullptr;
}


int ResolveImports(const IMAGE_DATA* const image)
{
	const char* const MappedAddress = image->LocalBase;
	const auto ImportDir = ConvertRva<const IMAGE_IMPORT_DESCRIPTOR*>(MappedAddress, DATA_DIR(image, IMAGE_DIRECTORY_ENTRY_IMPORT).VirtualAddress, image);
	
	for (UINT x = 0; ImportDir[x].Name != NULL; ++x)
	{
		const auto ModuleName = ConvertRva<const char*>(MappedAddress, ImportDir[x].Name, image);

		std::vector<MODULE>* VectorVer = nullptr;
		const int i = FindModule(ModuleName, &VectorVer, true);
		MODULE* ModulePtr = i == -1 ? nullptr : &(*VectorVer)[i];

		if (ModulePtr && DATA_DIR((&ModulePtr->image), IMAGE_DIRECTORY_ENTRY_IMPORT).Size && !ModulePtr->handle)
		{
			if (!ModulePtr->image.NT_HEADERS)
			{
				FindModuleDirWrapper(ModuleName, ModulePtr->image.path);
			}
			ModulePtr->handle = LoadLibraryExA(ModulePtr->image.path, nullptr, DONT_RESOLVE_DLL_REFERENCES);
		}

		const auto ImportTable = ConvertRva<IMAGE_THUNK_DATA32*>(MappedAddress, ImportDir[x].FirstThunk, image);
		const auto LookupTable = ConvertRva<const IMAGE_THUNK_DATA32*>(MappedAddress, ImportDir[x].Characteristics, image);
		
		for (UINT y = 0; LookupTable[y].u1.Function; ++y)
		{
			ModulePtr = &(*VectorVer)[i];
			const char* ImportName = ConvertRva<IMAGE_IMPORT_BY_NAME*>(image->LocalBase, LookupTable[y].u1.AddressOfData, image)->Name;

		retry:

			if (ModulePtr->handle) //indicates that it isnt an api set
			{
				const DWORD64 address = reinterpret_cast<DWORD64>(GetProcAddress(ModulePtr->handle, ImportName));
				if (address) ImportTable[y].u1.AddressOfData = ModulePtr->ImageBase + (address - reinterpret_cast<DWORD64>(ModulePtr->handle));
				else return -14;
			}
			else
			{
				ModulePtr = GetForwarderModule(ModulePtr, ImportName, &ImportName);

				if(!ModulePtr->handle && (!ModulePtr->image.NT_HEADERS || DATA_DIR((&ModulePtr->image), IMAGE_DIRECTORY_ENTRY_IMPORT).Size)) 
					ModulePtr->handle = LoadLibraryExA(ModulePtr->image.path, nullptr, DONT_RESOLVE_DLL_REFERENCES);

				goto retry;
			}
		}
	}

	return 1;
}
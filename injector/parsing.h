#pragma once
#include "pch.h"

//Structs

struct IMAGE_DATA
{
	char* path = nullptr;
	const char* LocalBase = nullptr;
	const IMAGE_NT_HEADERS64* NT_HEADERS = nullptr;
	const IMAGE_SECTION_HEADER* sections = nullptr;
};

struct MODULE
{
	HMODULE handle = nullptr;
	DWORD64 ImageBase = NULL;
	IMAGE_DATA image;
};


//Forward Declarations

extern HANDLE process;
extern std::vector<MODULE> modules, LoadedModules;

int GetDll(const char* path, IMAGE_DATA* const buffer);

int GetDependencies(const int index);

void ApplyReloction(const MODULE* TargetModule);

int ResolveImports(const IMAGE_DATA* const target);


//Macros

#define DATA_DIR(image, directory) image->NT_HEADERS->OptionalHeader.DataDirectory[directory]

#define IS_API_SET(image) DATA_DIR((&image), IMAGE_DIRECTORY_ENTRY_IMPORT).Size == 0

#define SHOULD_RELOCATE(ModulePtr) ModulePtr.ImageBase != ModulePtr.image.NT_HEADERS->OptionalHeader.ImageBase && DATA_DIR((&ModulePtr.image), IMAGE_DIRECTORY_ENTRY_BASERELOC).Size

#define HIJACK_THREAD        0x01

#define RUN_TLS_CALLBACKS    0x02

#define METHOD_LOADLIBRARY   0x04

#define METHOD_MANUAL_MAP    0x08

#define METHOD_HIJACK_THREAD 0x10


template <typename ret> auto ConvertRva(const void* const base, const DWORD64 rva, const IMAGE_DATA* const image)->ret
{
	const IMAGE_SECTION_HEADER* SectionHeader = image->sections;

	for (UINT x = 0; x < image->NT_HEADERS->FileHeader.NumberOfSections; ++x)
	{
		if (rva >= SectionHeader[x].VirtualAddress && rva <= (SectionHeader[x].VirtualAddress + SectionHeader[x].Misc.VirtualSize))
		{
			return reinterpret_cast<ret>(reinterpret_cast<DWORD>(base) + SectionHeader[x].PointerToRawData + (rva - SectionHeader[x].VirtualAddress));
		}
	}

	return reinterpret_cast<ret>(-50);
}
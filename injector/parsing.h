#pragma once
#include "pch.h"

//Structs

struct IMAGE_DATA
{
	char* path = nullptr;
	const char* LocalBase = nullptr;
	const IMAGE_NT_HEADERS32* NT_HEADERS = nullptr;
	const IMAGE_SECTION_HEADER* sections = nullptr;
};

struct MODULE
{
	HMODULE handle = nullptr;
	DWORD ImageBase = NULL;
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
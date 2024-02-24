#include "pch.h"
#include "process.h"
#include "parsing.h"

HANDLE process;
std::vector<MODULE> modules, LoadedModules;

__declspec(dllexport) int InjectDll(const HANDLE pProcess, const char* FilePath, int config)
{
    int status = 0;
    process = pProcess;

    //Load user specified DLL
    modules.push_back({});
    status = GetDll(FilePath, &modules.back().image);
    if (status <= 0) return status;

    status = GetLoadedModules();
    if (status == 1) // Populating LoadedModules with every module already present in the target process
    {
        //Allocate memory & resolve dependencies
        for (size_t x = 0; x < modules.size(); ++x)
        {
            if (IS_API_SET(modules[x].image)) continue;

            modules[x].ImageBase = reinterpret_cast<DWORD64>(__VirtualAllocEx(modules[x].image.NT_HEADERS->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE));
            if (!modules[x].ImageBase) 
            {
                status = -8; 
                break;
            }
            
            status = GetDependencies(x);
            if (status <= 0) break;
        }
            
        if (status == 1)
        {
            //Applying relocation & import resolution
            for (int x = 0; x < modules.size(); ++x)
            {
                if (IS_API_SET(modules[x].image)) continue;

                if (SHOULD_RELOCATE(modules[x])) ApplyReloction(&modules[x]);

                status = ResolveImports(&modules[x].image);
                if (status <= 0) break;
            }
            for (int x = 0; x < LoadedModules.size(); ++x)
            {
                delete[] LoadedModules[x].image.path;
                if (LoadedModules[x].image.NT_HEADERS) delete[] LoadedModules[x].image.LocalBase;
            }
            LoadedModules.clear();
                
            if (status == 1)
            {
                //Mapping modules into memory
                for (int x = 0; status && x < modules.size(); ++x)
                {
                    if (IS_API_SET(modules[x].image)) continue;
                    status = MapDll(&modules[x]);
                    if (status <= 0) break;
                }
                for (int x = 1; x < modules.size(); ++x)
                {
                    delete[] modules[x].image.path;
                    delete[] modules[x].image.LocalBase;
                }
                if (modules.size() > 1) modules.erase(modules.begin() + 1, modules.end());
                    
                //Running DllMain via thread hijacking
                if (status == 1)
                {
                    if (config & HIJACK_THREAD) status = HijackThread(config);
                    else status = CreateNewThread(config);
                }
            }
        }
    }
    
    if (status == 1)
    {
        MessageBoxW(nullptr, L"Successfully injected DLL!", L"Success!", MB_OK);
    }
    else
    {
        const std::wstring msg = L"Failed to inject DLL. Error code: " + std::to_wstring(status) + L'\n';
        MessageBoxW(nullptr, msg.c_str(), L"ERROR", MB_OK);
    }

    CloseHandle(process);
    return status;
}
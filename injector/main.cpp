#include "pch.h"
#include "process.h"
#include "parsing.h"

HANDLE process;
std::vector<MODULE> modules, LoadedModules;

int main(int argc, char* argv[])
{
    int status = 0;
    char config = 0;
    char ProcessName[MAX_PATH], FileName[MAX_PATH];

    std::string buffer(MAX_PATH, NULL);
    GetModuleFileNameA(nullptr, buffer.data(), MAX_PATH);

    std::fstream file(buffer.substr(0, buffer.find_last_of('\\') + 1) + "cfg.txt");
    if (file.fail()) return -1;

    for (int x = 1; x < argc; ++x)
    {
        if (argv[x][0] == '-')
        {
            if (_stricmp(argv[x], "-save") == 0)
            {
                file << ProcessName << '\n';
                file << FileName << '\n';
            }
            else if (_stricmp(argv[x], "-hijack") == 0) config |= HIJACK_THREAD;
            else if (_stricmp(argv[x], "-tls") == 0) config |= RUN_TLS_CALLBACKS;
        }
        else
        {
            if (!status)
            {
                strcpy_s(ProcessName, MAX_PATH, argv[x]);
                status = 1;
            }
            else strcpy_s(FileName, MAX_PATH, argv[x]);
        }
    }

    if (!status)
    {
        file.getline(ProcessName, MAX_PATH);
        file.getline(FileName, MAX_PATH);
        status = 1;
    }
    file.close();

    //Load user specified DLL
    modules.push_back({});
    status = GetDll(FileName, &modules.back().image);
    if (status <= 0) return status;

    status = GetProcessHandle(ProcessName);
    if (status == 1)
    {
        if (GetLoadedModules() == 1) // Populating LoadedModules with every module already present in the target process
        {
            //Allocate memory & resolve dependencies
            for (UINT x = 0; x < modules.size(); ++x)
            {
                if (IS_API_SET(modules[x].image)) continue;

                modules[x].ImageBase = reinterpret_cast<DWORD>(__VirtualAllocEx(modules[x].image.NT_HEADERS->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE));
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
    }
    
    if (status == 1) std::cout << "Successfully mapped dll!\n";
    else std::cout << "ERR: " << status << '\n';

    CloseHandle(process);
    return status;
}
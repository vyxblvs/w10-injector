#include "pch.h"
#include "process.h"
#include "parsing.h"

HANDLE process;
std::vector<MODULE> modules, LoadedModules;

int main(int argc, char* argv[])
{
    int status = 1;
    char ProcessName[MAX_PATH], FileName[MAX_PATH];

    if (argc >= 3)
    {
        strcpy_s(ProcessName, MAX_PATH, argv[1]);
        strcpy_s(FileName, MAX_PATH, argv[2]);
    }

    //Loading or saving target data
    if (argc == 1 || argc == 4)
    {
        //If the executable path isnt prefixed to cfg.txt, the command directory will be used by fstream unless cd'd to injector dir
        std::string buffer(MAX_PATH, NULL);
        GetModuleFileNameA(nullptr, buffer.data(), MAX_PATH);

        std::fstream file(buffer.substr(0, buffer.find_last_of('\\') + 1) + "cfg.txt");
        if (file.fail()) return -1;

        if (argc == 1)
        {
            file.getline(ProcessName, MAX_PATH);
            file.getline(FileName, MAX_PATH);
        }
        else if (_stricmp(argv[3], "-save") == 0)
        {
            file << ProcessName << '\n';
            file << FileName << '\n';
        }

        file.close();
    }

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

                modules[x].ImageBase = reinterpret_cast<DWORD>(VirtualAllocEx(process, nullptr, modules[x].image.NT_HEADERS->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
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
                        status = HijackThread();
                        if (status == 1) std::cout << "Successfully mapped dll!\n";
                    }
                }
            }
        }
    }
    
    CloseHandle(process);
    return status;
}
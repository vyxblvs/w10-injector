#include "pch.h"
#include "gui_helpers.h"
#include "process_gui.h"
#include "rendering.h"

std::vector<std::string> ProcessList;
std::vector<DWORD> PidList;


void DisplayProcessList(int& CurrentProcess, char pid[6], const std::string& filter, const _config& cfg, std::string& ProcessPreview)
{
	static bool OpenLastFrame = false;

	if (ImGui::BeginCombo("##PROCESS LIST", ProcessPreview.c_str()))
	{		
		if (!OpenLastFrame)
		{
			OpenLastFrame = true;
			GetProcessList(filter, cfg);
		}

		for (size_t x = 0; x < ProcessList.size(); ++x)
		{
			const bool selected = (CurrentProcess == x);

			ImGui::PushID(x);

			if (selected)
			{
				constexpr ImVec4 green      = { 0.058824f, 0.309804f, 0.105882f, 1.0f };
				constexpr ImVec4 LightGreen = { 0.068824f, 0.409804f, 0.205882f, 1.0f };

				ImGui::PushStyleColor(ImGuiCol_Header,        green);
				ImGui::PushStyleColor(ImGuiCol_HeaderHovered, LightGreen);
				ImGui::PushStyleColor(ImGuiCol_HeaderActive,  LightGreen);
			}

			ImGuiSelectableFlags flags = ImGuiSelectableFlags_None;
			if (ImGui::GetIO().KeyCtrl) flags = ImGuiSelectableFlags_DontClosePopups;

			if (ImGui::Selectable(ProcessList[x].c_str(), selected, flags))
			{
				if (CurrentProcess != x)
				{
					CurrentProcess = x;
					memcpy(pid, std::to_string(PidList[CurrentProcess]).c_str(), sizeof(pid));
					ProcessPreview = ProcessList[CurrentProcess];
				}
				else
				{
					CurrentProcess = -1;
					ProcessPreview = "No Process Selected";
					memset(pid, 0, sizeof(pid));
				}
			}

			ImGui::PopID();

			if (selected)
			{
				ImGui::PopStyleColor(3);
				ImGui::SetItemDefaultFocus();
			}
		}

		ImGui::EndCombo();
	}
	else if (OpenLastFrame) OpenLastFrame = false;
}


void GetConfigList(std::vector<std::string>& buffer, const std::string& CfgFolder)
{
	buffer.clear();
	
	WIN32_FIND_DATAA data;
	const HANDLE search = FindFirstFileExA((CfgFolder + '*').c_str(), FindExInfoBasic, &data, FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
	if (search == INVALID_HANDLE_VALUE) return;
	
	do
	{
		if (strcmp(data.cFileName, ".") == 0 || strcmp(data.cFileName, "..") == 0) continue;
		else buffer.emplace_back(data.cFileName);
	} 
	while (FindNextFileA(search, &data) && GetLastError() != ERROR_NO_MORE_FILES);

	FindClose(search);
	SetLastError(0);
}


void ReadConfig(std::vector<std::string>& ModuleList, char pid[6], const std::string path, _config& cfg, int& CurrentProcess, const std::string& filter, std::string& ProcessPreview)
{
	char buffer[MAX_PATH];
	std::fstream file(path);

	for (int x = 0; file.getline(buffer, MAX_PATH); ++x)
	{
		switch (x)
		{

		// Target Process
		case 0:
		{
			GetProcessList(filter, cfg);

			bool found = false;
			for (size_t i = 0; i < ProcessList.size(); ++i)
			{
				if (_stricmp(ProcessList[i].c_str(), buffer) == 0)
				{
					CurrentProcess = i;
					ProcessPreview = ProcessList[i];
					memcpy(pid, std::to_string(PidList[i]).c_str(), sizeof(pid));
					found = true;
				}
			}

			if (!found)
			{
				MessageBoxA(nullptr, buffer, "SAVED PROCESS NOT RUNNING", 0);
				file.close();
			}

			break;
		}

		// DLL Directory
		case 1:
		{
			ModuleList.clear();
			ModuleList.emplace_back(buffer);

			break;
		}

		// Injection Method
		case 2:
		{
			if (_stricmp(buffer, "-ManualMap") == 0)
				cfg.InjectionMethod = METHOD_MANUAL_MAP;

			else cfg.InjectionMethod = METHOD_LOADLIBRARY;

			break;
		}

		// Execution Method
		case 3:
		{
			if (_stricmp(buffer, "-CreateRemoteThread") == 0)
				cfg.ExecutionMethod = METHOD_CREATE_THREAD;

			else cfg.ExecutionMethod = METHOD_HIJACK_THREAD;

			break;
		}

		// TLS CallBacks
		case 4:
		{
			if (_stricmp(buffer, "-RunTLS") == 0)
				cfg.RunTlsCallbacks = true;

			else cfg.RunTlsCallbacks = false;

			break;
		}

		}
	}

	file.close();
}


void ShowConfigOptions(std::vector<std::string>& ModuleList, char pid[6], _config& cfg, int& CurrentProcess, const std::string& filter, std::string& ProcessPreview)
{
	static bool OpenLastFrame = false;
	static int CurrentCfg = -1;

	constexpr const char* DefaultPreview = "No Config Selected";
	static std::vector<std::string> CfgFiles;
	static std::string preview = DefaultPreview;

	static std::string CfgFolder;
	if (CfgFolder.empty())
	{
		char InjectorPath[MAX_PATH];
		GetModuleFileNameA(nullptr, InjectorPath, sizeof(InjectorPath));

		CfgFolder = InjectorPath;
		CfgFolder.erase(CfgFolder.find_last_of('\\'));
		CfgFolder += "\\configs\\";
	}

	if (ImGui::BeginCombo("##CONFIG LIST", preview.c_str()))
	{
		if (!OpenLastFrame)
		{
			OpenLastFrame = true;
			GetConfigList(CfgFiles, CfgFolder);
		}

		for (size_t x = 0; x < CfgFiles.size(); ++x)
		{
			const bool IsSelected = (x == CurrentCfg);

			ImGui::PushID(x);

			if (ImGui::Selectable(CfgFiles[x].c_str(), &CurrentCfg))
			{
				if (IsSelected && strcmp(preview.c_str(), DefaultPreview) != 0)
				{
					ModuleList.clear();
					memset(pid, 0, sizeof(pid));

					ProcessPreview = "No Process Selected";
					preview = DefaultPreview;

					cfg = _config{};
				}

				else
				{
					CurrentCfg = x;
					preview = CfgFiles[x];
					ReadConfig(ModuleList, pid, CfgFolder + CfgFiles[x], cfg, CurrentProcess, filter, ProcessPreview);
				}
			}

			ImGui::PopID();
		}

		ImGui::EndCombo();
	}
	if (OpenLastFrame && !ImGui::IsItemActive()) OpenLastFrame = false;
}


void ShowSettings(std::vector<std::string>& ModuleList, char pid[6], _config& cfg, int& CurrentProcess, const std::string& filter, std::string& ProcessPreview)
{
	ImGui::PushStyleColor(ImGuiCol_ChildBg, ImGui::GetStyle().Colors[ImGuiCol_WindowBg]);

	constexpr const char* InjectionMethods[] = { "LoadLibraryA", "Manual Mapping" };
	constexpr const char* ExecutionMethods[] = { "CreateRemoteThreadEx", "Thread Hijacking" };

	const ImVec2 size = { ImGui::GetWindowWidth() * 0.40f, static_cast<float>(ImGui::GetWindowHeight() * 0.85f) - ImGui::GetCursorPosY() };

	if (ImGui::BeginChild("SETTINGS", size, ImGuiChildFlags_Border))
	{
		static const float TextSize = ImGui::CalcTextSize("?").x;

		ImGui::PushItemWidth(GET_MAX_WIDTH - TextSize - (ImGui::GetStyle().FramePadding.x * 2));

		ImGui::SetCursorPosX(ImGui::GetCursorPosX());

		ShowConfigOptions(ModuleList, pid, cfg, CurrentProcess, filter, ProcessPreview);

		ImGui::Combo("##INJECTION METHOD", &cfg.InjectionMethod, InjectionMethods, IM_ARRAYSIZE(InjectionMethods));

		ImGui::Combo("##EXECUTION METHOD", &cfg.ExecutionMethod, ExecutionMethods, IM_ARRAYSIZE(ExecutionMethods));

		ToolTip("WARNING: Please only select thread hijacking if you're sure that thread desynchronization is not a risk!");


		CheckboxEx("Run TLS callbacks",       &cfg.RunTlsCallbacks);

		if (CheckboxEx("Filter by handle rights", &cfg.CheckHandles))
		{
			GetProcessList(filter, cfg);

			bool found = false;

			for (size_t x = 0; x < ProcessList.size(); ++x)
			{
				if (strcmp(ProcessPreview.c_str(), ProcessList[x].c_str()) == 0)
				{
					found = true;
					CurrentProcess = x;
					break;
				}
			}

			if (!found)
			{
				memset(pid, 0, sizeof(pid));
				ProcessPreview = "No Process Selected";
				CurrentProcess = -1;
			}
		}

		ToolTip("When enabled, the process list displayed will not show processes which can't be opened with required access rights");


		CheckboxEx("Case sensitive filtering", &cfg.CaseSensitiveFilter);

		CheckboxEx("Save Config",              &cfg.SaveConfig);

		ImGui::PopItemWidth();
		ImGui::EndChild();
	}

	ImGui::PopStyleVar();
	ImGui::PopStyleColor();
}


void ShowDllOptions(OPENFILENAMEA* const ofn, std::vector<std::string>& ModuleList)
{
	ImVec2 size = { GET_MAX_WIDTH, static_cast<float>(ImGui::GetWindowHeight() * 0.7225f) - ImGui::GetCursorPosY() };
	ImVec2 CursorPos = ImGui::GetCursorPos();

	static int SelectedDll = 0;
	
	if (ImGui::BeginChild("Dll Options", size))
	{
		for (int x = 0; x < ModuleList.size(); ++x)
		{
			if (SelectedDll == x)
			{
				constexpr ImVec4 LightGrey = { 0.1562745, 0.1562745, 0.1562745, 1 };
				ImGui::PushStyleColor(ImGuiCol_Header, LightGrey);
			}

			if (ImGui::Selectable(ModuleList[x].c_str(), &SelectedDll)) SelectedDll = x;

			if (SelectedDll == x) ImGui::PopStyleColor();
		}

		ImGui::EndChild();
	}

	const ImGuiStyle& style = ImGui::GetStyle();
	
	CursorPos.y += (size.y + (style.FramePadding.y / 2));

	ImGui::SetCursorPos(CursorPos);

	//casting the y to an int prevents it from rounding up, which (depending on the window size) may result in misalignment of a single pixel
	size.x /= 2;
	size.y = static_cast<int>(((size.y * 1.17647058824f) - size.y) + style.FramePadding.y + (style.ChildBorderSize * 2));
	
	if (ImGui::Button("Add DLL", size) && GetOpenFileNameA(ofn))
	{
		bool found = false;

		for (int x = 0; x < ModuleList.size(); ++x)
		{
			if (_stricmp(ModuleList[x].c_str(), ofn->lpstrFile) == 0)
			{
				found = true;
				break;
			}
		}

		if (!found) ModuleList.emplace_back(ofn->lpstrFile);
	}

	CursorPos.x += size.x;

	ImGui::SetCursorPos(CursorPos);

	if (ImGui::Button("Remove DLL", size) && ModuleList.size() > 0)
	{
		ModuleList.erase(ModuleList.begin() + SelectedDll);
	}
}


static INT WINAPI wWinMain(_In_ HINSTANCE instance, _In_opt_ HINSTANCE PrevInstance, _In_ PWSTR CmdLine, _In_ INT CmdShow)
{
	UNREFERENCED_PARAMETER(instance);
	UNREFERENCED_PARAMETER(PrevInstance);
	UNREFERENCED_PARAMETER(CmdLine);
	UNREFERENCED_PARAMETER(CmdShow);
	
	if (!glfwInit()) return 1;

	GLFWwindow* window = InitializeMenu();

	int CurrentProcess = -1;
	char pid[6] = "\0";
	char path[MAX_PATH] = "\0";

	char FileName[MAX_PATH];
	OPENFILENAMEA ofn;

	InitFileDialog(ofn, FileName, window);

	char FilterBuffer[MAX_PATH] = "\0";
	std::string filter;
	std::vector<std::string> ModuleList;
	std::string ProcessPreview = "No Process Selected";
	_config cfg;

	bool FilterInputGiven = false;
	bool PidInputGiven = false;

	while (!glfwWindowShouldClose(window))
	{
		SetupFrame();

		if (InputTextEx("PID", pid, sizeof(pid), 55.0f, 1)) PidInputGiven = true;
		else if (PidInputGiven && !ImGui::IsItemActive())
		{
			PidInputGiven = false;
			GetProcessList(filter, cfg);
			CurrentProcess = HandlePidInput(std::stoi(pid));
			ProcessPreview = ProcessList[CurrentProcess];
		}

		ImGui::SameLine();

		DisplayProcessList(CurrentProcess, pid, filter, cfg, ProcessPreview);

		ImGui::SameLine();

		if (InputTextEx("Filter", FilterBuffer, MAX_PATH, GET_MAX_WIDTH, 2)) FilterInputGiven = true;
		else if (FilterInputGiven && !ImGui::IsItemActive())
		{
			FilterInputGiven = false;
			filter = FilterBuffer;
		}

		ShowSettings(ModuleList, pid, cfg, CurrentProcess, filter, ProcessPreview);

		ImGui::SameLine();

		ShowDllOptions(&ofn, ModuleList);
		
		ImGui::Button("Inject", { GET_MAX_WIDTH, (ImGui::GetWindowHeight() - ImGui::GetCursorPosY()) - 8 });

		EndFrame(window);
	}
	
	ImGui_ImplOpenGL3_Shutdown();
	ImGui_ImplGlfw_Shutdown();
	ImGui::DestroyContext();

	glfwDestroyWindow(window);
	glfwTerminate();

	return 0;
}
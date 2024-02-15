#include "pch.h"
#include "rendering.h"


void EndFrame(GLFWwindow* window)
{
	ImGui::End();
	ImGui::Render();

	int display_w, display_h;

	glfwGetFramebufferSize(window, &display_w, &display_h);
	glViewport(0, 0, display_w, display_h);
	glClearColor(0, 0, 0, 0);
	glClear(GL_COLOR_BUFFER_BIT);
	ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
	glfwSwapBuffers(window);
}


void SetupFrame()
{
	glfwPollEvents();
	ImGui_ImplOpenGL3_NewFrame();
	ImGui_ImplGlfw_NewFrame();

	ImGui::NewFrame();
	ImGui::SetNextWindowSize({ 700, 500 }, ImGuiCond_FirstUseEver);
	ImGui::Begin("Injector", nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings);
}


GLFWwindow* InitializeMenu()
{
	glfwWindowHint(GLFW_TRANSPARENT_FRAMEBUFFER, true);

	GLFWwindow* window = glfwCreateWindow(1000, 700, "injector", nullptr, nullptr);
	glfwMakeContextCurrent(window);

	IMGUI_CHECKVERSION();
	ImGui::CreateContext();

	ImGui_ImplGlfw_InitForOpenGL(window, true);
	ImGui_ImplOpenGL3_Init("#version 150");

	ImGuiStyle& style = ImGui::GetStyle();

	constexpr ImVec4 clear          = { 0, 0, 0, 0 };
	constexpr ImVec4 black          = { 0, 0, 0, 1 };
	constexpr ImVec4 grey           = { 0.0901960, 0.0901960, 0.0901960, 1 };
	constexpr ImVec4 DarkGrey       = { 0.0601960, 0.0601960, 0.0601960, 1 };
	constexpr ImVec4 LightGrey      = { 0.1562745, 0.1562745, 0.1562745, 1 };
	constexpr ImVec4 DarkGrey_Child = { 0.0501960, 0.0501960, 0.0501960, 1 };

	style.TabRounding     = 0;
	style.FrameBorderSize = 1;
	style.FramePadding    = { 7.0f, 7.0f };
	style.Colors[ImGuiCol_ResizeGrip]        = clear;
	style.Colors[ImGuiCol_ResizeGripActive]  = clear;
	style.Colors[ImGuiCol_ResizeGripHovered] = clear;
	style.Colors[ImGuiCol_TitleBgActive]     = black;
	style.Colors[ImGuiCol_TitleBg]           = black;
	style.Colors[ImGuiCol_WindowBg]          = grey;
	style.Colors[ImGuiCol_Button]            = DarkGrey;
	style.Colors[ImGuiCol_ButtonActive]      = LightGrey;
	style.Colors[ImGuiCol_ButtonHovered]     = LightGrey;
	style.Colors[ImGuiCol_PopupBg]           = DarkGrey;
	style.Colors[ImGuiCol_Header]            = DarkGrey;
	style.Colors[ImGuiCol_HeaderActive]      = LightGrey;
	style.Colors[ImGuiCol_HeaderHovered]     = LightGrey;
	style.Colors[ImGuiCol_FrameBg]           = DarkGrey;
	style.Colors[ImGuiCol_FrameBgHovered]    = LightGrey;
	style.Colors[ImGuiCol_FrameBgActive]     = LightGrey;
	style.Colors[ImGuiCol_ChildBg]           = DarkGrey_Child;
	style.Colors[ImGuiCol_CheckMark]         = black;

	ImGuiIO& io = ImGui::GetIO();
	io.ConfigWindowsResizeFromEdges = false;

	std::string dir(MAX_PATH, 0);
	GetModuleFileNameA(nullptr, dir.data(), MAX_PATH);
	
	dir.erase(dir.find_last_of("\\") + 1);
	dir += "arial.ttf"; // i'll put this in the zip of a release build if i make one, until then it doesn't really matter

	io.Fonts->AddFontFromFileTTF(dir.c_str(), 16);
	io.FontDefault = io.Fonts->Fonts[0];

	return window;
}
#include "pch.h"
#include "gui_helpers.h"
#include "process_gui.h"


void ToolTip(const char* const text)
{
	ImGui::SameLine();

	constexpr ImVec4 LightPurple = { 0.8156862f, 0.5217647f, 0.9686274f, 0.75f };

	ImGui::TextColored(LightPurple, "?");

	if (ImGui::IsItemHovered())
	{
		ImGui::SetTooltip(text);
	}
}


void BackgroundText(const char* const text, const int ItemCount)
{
	ImGui::SameLine();

	const ImGuiStyle& style = ImGui::GetStyle();
	const float CursorPos = ImGui::GetCursorPosX();

	float OldCursorPos = CursorPos - ImGui::GetItemRectSize().x;
	float mid = (((OldCursorPos + CursorPos) / 2) - ImGui::CalcTextSize(text).x / 2) - style.FrameBorderSize * ItemCount;
	mid -= style.FramePadding.x * (ItemCount / ((ItemCount > 1) + 1));

	ImGui::SetCursorPosX(mid);
	ImGui::TextColored({ 1.0f, 1.0f, 1.0f, 0.5f }, text);

	ImGui::SameLine();
	ImGui::SetCursorPosX(CursorPos - style.ItemInnerSpacing.x * 2);
	ImGui::NewLine();
}


bool InputTextEx(const std::string name, char* const buf, const int sz, const float width, const int ItemCount)
{
	ImGui::PushItemWidth(width);

	const bool status = ImGui::InputText(("##" + name).c_str(), buf, sz);

	ImGui::PopItemWidth();

	if (!buf[0]) BackgroundText(name.c_str(), ItemCount);

	return status;
}


bool CheckboxEx(const char* const label, bool* const var)
{
	constexpr ImVec4 dark_purple  = { 0.2156862f, 0.0117647f, 0.3686274f, 0.75f };
	constexpr ImVec4 light_purple = { 0.3156862f, 0.0217647f, 0.4686274f, 0.75f };
	constexpr ImVec4 LightGrey    = { 0.1562745f, 0.1562745f, 0.1562745f, 1.0f };

	ImGui::PushStyleVar(ImGuiStyleVar_FramePadding,  { 1.3f, 1.3f });
	ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding,   1.5f);
	ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 1.0f);

	const bool v_status = *var;

	if (v_status)
	{
		ImGui::PushStyleColor(ImGuiCol_FrameBg,        dark_purple);
		ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, light_purple);
		ImGui::PushStyleColor(ImGuiCol_FrameBgActive,  light_purple);
	}
	else ImGui::PushStyleColor(ImGuiCol_Border, LightGrey);

	const bool status = ImGui::Checkbox(label, var);

	ImGui::PopStyleColor(v_status ? 3 : 1);
	ImGui::PopStyleVar(3);

	return status;
}


void InitFileDialog(OPENFILENAMEA& ofn, char* FileName, GLFWwindow* window)
{
	memset(&ofn, 0, sizeof(OPENFILENAMEA));
	ofn.lStructSize  = sizeof(OPENFILENAMEA);
	ofn.hwndOwner    = glfwGetWin32Window(window);
	ofn.lpstrFile    = FileName;
	ofn.lpstrFile[0] = '\0';
	ofn.nMaxFile     = MAX_PATH;
	ofn.lpstrFilter  = "Dynamic Link Libraries (.dll)\0*.DLL";
	ofn.nFilterIndex = 1;
	ofn.Flags        = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
}
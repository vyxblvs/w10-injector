#pragma once
#include "pch.h"

void EndFrame(GLFWwindow* window);

void SetupFrame();

GLFWwindow* InitializeMenu();

// retrieves the width between the end of the window and the cursor pos
#define GET_MAX_WIDTH (ImGui::GetWindowWidth() - ImGui::GetCursorPosX()) - 8
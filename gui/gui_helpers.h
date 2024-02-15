#pragma once
#include "pch.h"
#include "process_gui.h"

void ToolTip(const char* const text);

void BackgroundText(const char* const text, const int ItemCount);

bool InputTextEx(const std::string name, char* const buf, const int sz, const float width, const int ItemCount);

bool CheckboxEx(const char* const label, bool* const var);

void InitFileDialog(OPENFILENAMEA& ofn, char* FileName, GLFWwindow* window);
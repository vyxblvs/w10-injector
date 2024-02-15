#pragma once

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <commdlg.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <vector>
#include <string>
#include <fstream>

#define GLFW_EXPOSE_NATIVE_WIN32

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "glfw3.h"
#include "glfw3native.h"
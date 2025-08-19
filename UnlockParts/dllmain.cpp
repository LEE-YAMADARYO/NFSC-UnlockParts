// Copyright(C) 2025 YAMADA RYO
// 此 ASI 插件用于 Need for Speed Most Carbon，它可以让所有外观套件在存档创建之初全部解锁
// 该代码根据 MIT 许可证发布
// 著作权所有
#include "pch.h"
#include <Windows.h>
#include <cstdio>
#include <set>

#include "MinHook\include\MinHook.h"
#include "HookingPatterns\Hooking.Patterns.h"

HMODULE g_module = NULL;
bool g_initialized = false;

// 解锁所有外观部件
typedef bool(__fastcall* tIsCarPartUnlocked)(void* this_ptr, void* edx, void* pDBCarPart);
tIsCarPartUnlocked originalIsCarPartUnlocked = nullptr;
bool __fastcall hkIsCarPartUnlocked(void* this_ptr, void* edx, void* pDBCarPart) {
    return true;
}

// 解锁所有彩绘/涂装
typedef bool(__fastcall* tIsVinylUnlocked)(void* this_ptr, void* edx, int arg0, int arg4);
tIsVinylUnlocked originalIsVinylUnlocked = nullptr;
bool __fastcall hkIsVinylUnlocked(void* this_ptr, void* edx, int arg0, int arg4) {
    return true;
}

// 确保 Xbox 360 独占的彩绘等特殊视觉部件可见
typedef bool(__cdecl* tISelectablePart_CheckOnlineParts)(void* carPart);
tISelectablePart_CheckOnlineParts originalISelectablePart_CheckOnlineParts = nullptr;
bool __cdecl hkISelectablePart_CheckOnlineParts(void* carPart) {
    if (carPart == NULL)
        return false;
    return true;
}

// 禁用游戏内置的全解锁功能 (0x0049EE77)
void DisableUnlockAllThingsFullUnlockPatch() {
    DWORD oldProtect;
    if (VirtualProtect((LPVOID)0x0049EE77, 2, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        *(BYTE*)0x0049EE77 = 0xEB; // 替换为 JMP 指令，跳过全局解锁路径
        VirtualProtect((LPVOID)0x0049EE77, 2, oldProtect, &oldProtect);
    }
}

// 主 Hook 初始化函数
void InitializeHooks() {
    if (g_initialized)
        return;
    g_initialized = true;

    // Hook UnlockSystem::IsCarPartUnlocked (0x004B0B70)
    if (MH_CreateHook((LPVOID)0x004B0B70, &hkIsCarPartUnlocked, (LPVOID*)&originalIsCarPartUnlocked) != MH_OK) {
        return;
    }

    // Hook UnlockSystem::IsVinylUnlocked (0x004B0E70)
    if (MH_CreateHook((LPVOID)0x004B0E70, &hkIsVinylUnlocked, (LPVOID*)&originalIsVinylUnlocked) != MH_OK) {
        return;
    }

    // Hook ISelectablePart_CheckOnlineParts (使用内存特征码查找)
    auto pattern_CheckOnlineParts = hook::pattern("56 8B 74 24 08 85 F6 75 04 32 C0 5E C3 57 68 ? ? ? ? E8");
    if (!pattern_CheckOnlineParts.empty()) {
        if (MH_CreateHook(pattern_CheckOnlineParts.get_first(), &hkISelectablePart_CheckOnlineParts, (LPVOID*)&originalISelectablePart_CheckOnlineParts) != MH_OK) {
            return;
        }
    }

    // 禁用游戏全局的全解锁功能。
    DisableUnlockAllThingsFullUnlockPatch();

    // 启用所有已成功创建的 Hook
    MH_EnableHook(MH_ALL_HOOKS);
}

// 延迟 Hook 触发点
void* (WINAPI* Direct3DCreate9_orig)(UINT) = NULL;
void* Direct3DCreate9_target = NULL;

void* WINAPI Direct3DCreate9_hook(UINT SDKVersion) {
    void* result = Direct3DCreate9_orig(SDKVersion);
    InitializeHooks();
    return result;
}

// ASI 加载器入口点
extern "C" __declspec(dllexport) void InitializeASI() {
    if (MH_Initialize() != MH_OK) {
        return;
    }
    if (MH_CreateHookApiEx(L"d3d9", "Direct3DCreate9", &Direct3DCreate9_hook, (void**)&Direct3DCreate9_orig, &Direct3DCreate9_target) != MH_OK) {
        MH_Uninitialize();
        return;
    }
    if (MH_EnableHook(Direct3DCreate9_target) != MH_OK) {
        MH_Uninitialize();
        return;
    }
}

// DLL 入口点
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        g_module = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
        break;
    case DLL_PROCESS_DETACH:
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    default:
        break;
    }
    return TRUE;
}
#include <windows.h>
#include <d3d9.h>
#include <stdio.h>
#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx9.h"
#include "mapper.h"
#include "driver_comm.h"
#include "service.h"
#include "anticheat.h"
#include "driver_data.h" // هنعمله بعدين

// المتغيرات العالمية (زي ما هو في جيدرا)
HWND g_hWnd = NULL;
LPDIRECT3DDEVICE9 g_pd3dDevice = NULL;
LPDIRECT3D9 g_pD3D = NULL;
bool g_bFivemSpoof = false;

// دالة النافذة (بديل FUN_140030ac0)
extern LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
        return true;

    switch (msg) {
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    case WM_SIZE:
        if (g_pd3dDevice && msg == WM_SIZE && wParam != SIZE_MINIMIZED) {
            // نحدّث حجم النافذة
        }
        return 0;
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

// دالة إنشاء النافذة و DirectX (بديل FUN_140030090)
bool CreateImGuiWindow() {
    WNDCLASSEXW wc = { sizeof(WNDCLASSEXW) };
    wc.lpfnWndProc = WndProc;
    wc.hInstance = GetModuleHandleW(0);
    wc.lpszClassName = L"WASP";
    RegisterClassExW(&wc);

    g_hWnd = CreateWindowExW(0, L"WASP", L"WASP Spoofer", WS_POPUP | WS_VISIBLE, 100, 100, 820, 600, 0, 0, wc.hInstance, 0);
    if (!g_hWnd) return false;

    g_pD3D = Direct3DCreate9(D3D_SDK_VERSION);
    D3DPRESENT_PARAMETERS d3dpp = {};
    d3dpp.Windowed = TRUE;
    d3dpp.SwapEffect = D3DSWAPEFFECT_DISCARD;
    d3dpp.hDeviceWindow = g_hWnd;
    d3dpp.BackBufferFormat = D3DFMT_UNKNOWN;
    d3dpp.EnableAutoDepthStencil = TRUE;
    d3dpp.AutoDepthStencilFormat = D3DFMT_D16;

    if (FAILED(g_pD3D->CreateDevice(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, g_hWnd,
                                    D3DCREATE_HARDWARE_VERTEXPROCESSING, &d3dpp, &g_pd3dDevice))) {
        return false;
    }

    ImGui::CreateContext();
    ImGui_ImplWin32_Init(g_hWnd);
    ImGui_ImplDX9_Init(g_pd3dDevice);

    // ضبط الـ Style (زي ما هو في جيدرا)
    ImGui::GetIO().IniFilename = NULL;
    ImGui::GetStyle().WindowRounding = 0.0f;
    ImGui::GetStyle().Colors[ImGuiCol_WindowBg] = ImVec4(0.12f, 0.12f, 0.14f, 1.0f);
    
    return true;
}

// دالة رسم الـ GUI (بديل FUN_14002cd50)
void RenderUI() {
    ImGui_ImplDX9_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    // ====== المنطق بتاع الشاشة الرئيسية (زي جيدرا) ======
    ImGui::Begin("WASP Spoofer", nullptr, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize);
    ImGui::SetWindowSize(ImVec2(620, 400));

    ImGui::TextColored(ImVec4(0.9f, 0.2f, 0.2f, 1.0f), "Anti-Cheat Status:");
    if (IsAntiCheatRunning()) {
        ImGui::TextColored(ImVec4(0.0f, 1.0f, 0.0f, 1.0f), "[+] System is PROTECTED");
    } else {
        ImGui::TextColored(ImVec4(1.0f, 1.0f, 1.0f, 1.0f), "[-] No Anti-Cheat Detected");
    }

    ImGui::Separator();
    ImGui::Spacing();

    // زر الـ SPOOF (زي loginbar في جيدرا)
    if (ImGui::Button("Spoofer", ImVec2(150, 30))) {
        // 1. نفذ Manual Map للـ Driver
        PVOID kernelBase = ManualMapDriver((PVOID)driver_data, driver_data_len);
        if (kernelBase) {
            // 2. افتح الجهاز وابعت IOCTL
            if (OpenDriverDevice()) {
                // هنا بنبعت أمر الكتابة في النواة (زي ما هو في FUN_140027f60)
                DWORD magic = 0x33;
                DWORD dummy = 0;
                SendIOCTL(0x80862007, &magic, sizeof(magic), &dummy, sizeof(dummy));
                MessageBoxA(g_hWnd, "Driver Mapped Successfully!", "Success", MB_OK);
            }
        } else {
            MessageBoxA(g_hWnd, "Failed to map driver!", "Error", MB_OK);
        }
    }

    ImGui::SameLine();
    if (ImGui::Button("Extras", ImVec2(150, 30))) {
        // حاجات إضافية (Cleaner أو غيره)
        MessageBoxA(g_hWnd, "Extra features coming soon!", "Info", MB_OK);
    }

    ImGui::Spacing();
    ImGui::Checkbox("Fivem Spoof (Cleaner)", &g_bFivemSpoof);

    ImGui::Spacing();
    if (ImGui::Button("CHECK SPOOF", ImVec2(150, 30))) {
        // هنعمل فحص الـ Spoofing (زي ما هو في جيدرا)
        if (IsAntiCheatRunning()) {
            ImGui::OpenPopup("Anti-Cheat Detected!");
        } else {
            ImGui::OpenPopup("Spoof Active");
        }
    }

    // نوافذ الـ Popup
    if (ImGui::BeginPopupModal("Anti-Cheat Detected!", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Anti-Cheat is running!\nSpoofer might be detected.");
        if (ImGui::Button("OK", ImVec2(120, 0))) { ImGui::CloseCurrentPopup(); }
        ImGui::EndPopup();
    }
    if (ImGui::BeginPopupModal("Spoof Active", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Spoofer is active and protecting you.");
        if (ImGui::Button("OK", ImVec2(120, 0))) { ImGui::CloseCurrentPopup(); }
        ImGui::EndPopup();
    }

    ImGui::End();

    // ====== نهاية الرسم ======
    ImGui::EndFrame();
    ImGui::Render();

    g_pd3dDevice->Clear(0, NULL, D3DCLEAR_TARGET | D3DCLEAR_ZBUFFER, D3DCOLOR_RGBA(30, 30, 40, 255), 1.0f, 0);
    ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
    g_pd3dDevice->Present(NULL, NULL, NULL, NULL);
}

// ====== الـ Entry Point (WinMain) ======
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    if (!CreateImGuiWindow()) {
        MessageBoxA(0, "Failed to create ImGui window!", "Error", MB_ICONERROR);
        return 1;
    }

    // الحلقة الرئيسية (زي ما هو في جيدرا)
    MSG msg = { 0 };
    while (msg.message != WM_QUIT) {
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
            continue;
        }
        RenderUI();
    }

    // التنظيف
    ImGui_ImplDX9_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    if (g_pd3dDevice) g_pd3dDevice->Release();
    if (g_pD3D) g_pD3D->Release();
    if (g_hWnd) DestroyWindow(g_hWnd);

    return 0;
}
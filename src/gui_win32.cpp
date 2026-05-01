// Win32 + Direct3D 11 driver for the log viewer.
//
// Mirrors src/gui_macos.mm: create a window, set up an ImGui context with
// the platform/renderer backends, and pump frames until the window
// closes. Every frame we resize the ImGui window to fill the client area
// and call Viewer::draw().

#include <winsock2.h>
#include <windows.h>
#include <d3d11.h>
#include <tchar.h>

#include <string>

#include "imgui.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

#include "viewer.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(
    HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace {

ID3D11Device*           g_device      = nullptr;
ID3D11DeviceContext*    g_ctx         = nullptr;
IDXGISwapChain*         g_swap        = nullptr;
ID3D11RenderTargetView* g_rtv         = nullptr;
UINT                    g_resize_w    = 0;
UINT                    g_resize_h    = 0;

bool create_d3d(HWND hwnd) {
  DXGI_SWAP_CHAIN_DESC sd{};
  sd.BufferCount       = 2;
  sd.BufferDesc.Width  = 0;
  sd.BufferDesc.Height = 0;
  sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
  sd.BufferDesc.RefreshRate.Numerator   = 60;
  sd.BufferDesc.RefreshRate.Denominator = 1;
  sd.Flags        = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
  sd.BufferUsage  = DXGI_USAGE_RENDER_TARGET_OUTPUT;
  sd.OutputWindow = hwnd;
  sd.SampleDesc.Count   = 1;
  sd.SampleDesc.Quality = 0;
  sd.Windowed     = TRUE;
  sd.SwapEffect   = DXGI_SWAP_EFFECT_DISCARD;

  D3D_FEATURE_LEVEL feature_level;
  const D3D_FEATURE_LEVEL levels[] = {
    D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0
  };
  HRESULT hr = D3D11CreateDeviceAndSwapChain(
      nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
      levels, _countof(levels),
      D3D11_SDK_VERSION, &sd, &g_swap,
      &g_device, &feature_level, &g_ctx);
  if (hr == DXGI_ERROR_UNSUPPORTED) {
    hr = D3D11CreateDeviceAndSwapChain(
        nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0,
        levels, _countof(levels),
        D3D11_SDK_VERSION, &sd, &g_swap,
        &g_device, &feature_level, &g_ctx);
  }
  if (FAILED(hr)) return false;

  ID3D11Texture2D* back = nullptr;
  g_swap->GetBuffer(0, IID_PPV_ARGS(&back));
  if (!back) return false;
  g_device->CreateRenderTargetView(back, nullptr, &g_rtv);
  back->Release();
  return true;
}

void destroy_rtv() {
  if (g_rtv) { g_rtv->Release(); g_rtv = nullptr; }
}

void destroy_d3d() {
  destroy_rtv();
  if (g_swap)   { g_swap->Release();   g_swap   = nullptr; }
  if (g_ctx)    { g_ctx->Release();    g_ctx    = nullptr; }
  if (g_device) { g_device->Release(); g_device = nullptr; }
}

LRESULT WINAPI WndProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l) {
  if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, w, l)) return true;
  switch (msg) {
    case WM_SIZE:
      if (w != SIZE_MINIMIZED) {
        g_resize_w = (UINT)LOWORD(l);
        g_resize_h = (UINT)HIWORD(l);
      }
      return 0;
    case WM_SYSCOMMAND:
      // Disable the alt-menu activation that would steal focus from
      // ImGui keyboard nav.
      if ((w & 0xfff0) == SC_KEYMENU) return 0;
      break;
    case WM_DESTROY:
      ::PostQuitMessage(0);
      return 0;
  }
  return ::DefWindowProcW(hwnd, msg, w, l);
}

}  // namespace

int run_gui(const char* initial_path) {
  WNDCLASSEXW wc{};
  wc.cbSize        = sizeof(wc);
  wc.style         = CS_CLASSDC;
  wc.lpfnWndProc   = WndProc;
  wc.hInstance     = ::GetModuleHandleW(nullptr);
  wc.hCursor       = ::LoadCursor(nullptr, IDC_ARROW);
  wc.lpszClassName = L"LogViewerWindow";
  ::RegisterClassExW(&wc);

  HWND hwnd = ::CreateWindowW(
      wc.lpszClassName, L"urbit event log viewer",
      WS_OVERLAPPEDWINDOW, 100, 100, 1280, 800,
      nullptr, nullptr, wc.hInstance, nullptr);

  if (!create_d3d(hwnd)) {
    destroy_d3d();
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
    ::MessageBoxW(nullptr, L"Failed to create D3D11 device", L"log-viewer",
                  MB_ICONERROR);
    return 1;
  }

  ::ShowWindow(hwnd, SW_SHOWDEFAULT);
  ::UpdateWindow(hwnd);

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO& io = ImGui::GetIO();
  // Intentionally NOT enabling NavEnableKeyboard: we want the arrow keys
  // to step through events (handled in Viewer::draw), not jump focus
  // between widgets. Textbox cursor movement still works either way.
  io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
  ImGui::StyleColorsDark();
  ImGui_ImplWin32_Init(hwnd);
  ImGui_ImplDX11_Init(g_device, g_ctx);

  Viewer viewer;
  if (initial_path && *initial_path) viewer.open(initial_path);

  bool running = true;
  while (running) {
    MSG msg;
    while (::PeekMessageW(&msg, nullptr, 0, 0, PM_REMOVE)) {
      ::TranslateMessage(&msg);
      ::DispatchMessageW(&msg);
      if (msg.message == WM_QUIT) running = false;
    }
    if (!running) break;

    if (g_resize_w != 0 && g_resize_h != 0) {
      destroy_rtv();
      g_swap->ResizeBuffers(0, g_resize_w, g_resize_h,
                            DXGI_FORMAT_UNKNOWN, 0);
      g_resize_w = g_resize_h = 0;
      ID3D11Texture2D* back = nullptr;
      g_swap->GetBuffer(0, IID_PPV_ARGS(&back));
      if (back) {
        g_device->CreateRenderTargetView(back, nullptr, &g_rtv);
        back->Release();
      }
    }

    ImGui_ImplDX11_NewFrame();
    ImGui_ImplWin32_NewFrame();
    ImGui::NewFrame();

    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    viewer.draw();

    ImGui::Render();
    const float clear[4] = { 0.10f, 0.11f, 0.13f, 1.0f };
    g_ctx->OMSetRenderTargets(1, &g_rtv, nullptr);
    g_ctx->ClearRenderTargetView(g_rtv, clear);
    ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    g_swap->Present(1, 0);
  }

  ImGui_ImplDX11_Shutdown();
  ImGui_ImplWin32_Shutdown();
  ImGui::DestroyContext();
  destroy_d3d();
  ::DestroyWindow(hwnd);
  ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
  return 0;
}

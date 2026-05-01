// GLFW + OpenGL3 driver for Linux. Mirrors gui_macos.mm and gui_win32.cpp:
// create a window, set up an ImGui context with the GLFW + OpenGL3
// backends, and pump frames until the window closes.
//
// GLFW dynamically loads X11 / Wayland / libGL at runtime, so we don't
// link them statically — the build needs the X11 (and optionally Wayland)
// dev headers, the runtime needs the corresponding `.so`s available.

#include <GLFW/glfw3.h>

#include <stdio.h>

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include "viewer.h"

namespace {

void glfw_error(int code, const char* desc) {
  fprintf(stderr, "GLFW error %d: %s\n", code, desc);
}

}  // namespace

int run_gui(const char* initial_path) {
  glfwSetErrorCallback(glfw_error);
  if (!glfwInit()) return 1;

  // Request a modern-enough GL context. 3.2 core gives us the GLSL 150
  // that imgui_impl_opengl3 expects by default and matches what the
  // ImGui docking branch ships with.
  glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
  glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
  glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
  glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GLFW_TRUE);

  GLFWwindow* window = glfwCreateWindow(1280, 800, "urbit event log viewer",
                                        nullptr, nullptr);
  if (!window) {
    glfwTerminate();
    return 1;
  }
  glfwMakeContextCurrent(window);
  glfwSwapInterval(1);                  // vsync

  IMGUI_CHECKVERSION();
  ImGui::CreateContext();
  ImGuiIO& io = ImGui::GetIO();
  // See gui_macos.mm / gui_win32.cpp: arrow keys are reserved for stepping
  // events, not for ImGui widget-focus navigation.
  io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
  ImGui::StyleColorsDark();

  ImGui_ImplGlfw_InitForOpenGL(window, true);
  ImGui_ImplOpenGL3_Init("#version 150");

  Viewer viewer;
  if (initial_path && *initial_path) viewer.open(initial_path);

  while (!glfwWindowShouldClose(window)) {
    glfwPollEvents();

    ImGui_ImplOpenGL3_NewFrame();
    ImGui_ImplGlfw_NewFrame();
    ImGui::NewFrame();

    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    viewer.draw();

    ImGui::Render();
    int fb_w = 0, fb_h = 0;
    glfwGetFramebufferSize(window, &fb_w, &fb_h);
    glViewport(0, 0, fb_w, fb_h);
    glClearColor(0.10f, 0.11f, 0.13f, 1.0f);
    glClear(GL_COLOR_BUFFER_BIT);
    ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    glfwSwapBuffers(window);
  }

  ImGui_ImplOpenGL3_Shutdown();
  ImGui_ImplGlfw_Shutdown();
  ImGui::DestroyContext();
  glfwDestroyWindow(window);
  glfwTerminate();
  return 0;
}

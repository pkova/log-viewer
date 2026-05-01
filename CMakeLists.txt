cmake_minimum_required(VERSION 3.16)
# OBJCXX is only meaningful on Apple targets; gate the language list so the
# Visual Studio + Ninja Windows generators don't trip over it.
if(APPLE)
  project(log-viewer LANGUAGES C CXX OBJCXX)
else()
  project(log-viewer LANGUAGES C CXX)
endif()

set(CMAKE_C_STANDARD   11)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED   ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(APPLE)
  set(CMAKE_OBJCXX_STANDARD 17)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# ---------------------------------------------------------------------------
# mbedTLS — POSIX HTTPS only.
#
# Windows uses WinHTTP via http_win32.cpp; mbedTLS isn't needed there. Skip
# the FetchContent download entirely on Windows so a Visual Studio build
# doesn't pull a 30 MB tarball it never links.
# ---------------------------------------------------------------------------
if(NOT WIN32)
  include(FetchContent)
  set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
  set(ENABLE_TESTING  OFF CACHE BOOL "" FORCE)
  # mbedTLS 3.6 enables -Werror by default; clang ≥ 19 trips it on a few
  # new diagnostics that we don't want to chase upstream.
  set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(mbedtls
    URL      https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.2/mbedtls-3.6.2.tar.bz2
    URL_HASH SHA256=8b54fb9bcf4d5a7078028e0520acddefb7900b3e66fec7f7175bb5b7d85ccdca
    DOWNLOAD_EXTRACT_TIMESTAMP FALSE)
  FetchContent_MakeAvailable(mbedtls)
endif()

# ---------------------------------------------------------------------------
# GLFW (Linux GUI driver). Cocoa/Metal on macOS and Win32/DX11 on Windows
# already cover the windowing/rendering layer there; on Linux we use GLFW
# + OpenGL3, which is the standard ImGui combination.
#
# At build time you need the X11 (and optionally Wayland) -dev packages.
# Debian/Ubuntu: sudo apt install libgl1-mesa-dev libx11-dev libxrandr-dev \
#                                  libxinerama-dev libxcursor-dev libxi-dev \
#                                  libwayland-dev libxkbcommon-dev
# Fedora/RHEL: sudo dnf install mesa-libGL-devel libX11-devel libXrandr-devel \
#                                libXinerama-devel libXcursor-devel libXi-devel \
#                                wayland-devel libxkbcommon-devel
# ---------------------------------------------------------------------------
if(UNIX AND NOT APPLE)
  set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
  set(GLFW_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
  set(GLFW_BUILD_DOCS     OFF CACHE BOOL "" FORCE)
  set(GLFW_INSTALL        OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(glfw
    URL      https://github.com/glfw/glfw/archive/refs/tags/3.4.tar.gz
    URL_HASH SHA256=c038d34200234d071fae9345bc455e4a8f2f544ab60150765d7704e08f3dac01
    DOWNLOAD_EXTRACT_TIMESTAMP FALSE)
  FetchContent_MakeAvailable(glfw)

  find_package(OpenGL REQUIRED)
endif()

# ---------------------------------------------------------------------------
# Vendored LMDB (built as a tiny static library)
# ---------------------------------------------------------------------------
add_library(lmdb STATIC
  third_party/lmdb/mdb.c
  third_party/lmdb/midl.c
)
target_include_directories(lmdb PUBLIC third_party/lmdb)
if(NOT WIN32)
  target_compile_definitions(lmdb PRIVATE _GNU_SOURCE)
  target_compile_options(lmdb PRIVATE
    -Wno-unused-but-set-variable
    -Wno-unused-parameter
    -Wno-implicit-function-declaration
    -Wno-shorten-64-to-32
  )
else()
  # MSVC: silence the heap of secure-CRT warnings the LMDB sources emit.
  target_compile_definitions(lmdb PRIVATE _CRT_SECURE_NO_WARNINGS)
  target_link_libraries(lmdb PUBLIC ntdll)
endif()

# ---------------------------------------------------------------------------
# Vendored monocypher (X25519 + SHA-512 + Ed25519-to-X25519)
# ---------------------------------------------------------------------------
add_library(monocypher STATIC
  third_party/monocypher/monocypher.c
  third_party/monocypher/monocypher-ed25519.c
)
target_include_directories(monocypher PUBLIC third_party/monocypher)

# ---------------------------------------------------------------------------
# Vendored BLAKE3 reference C — portable build only (no SIMD dispatch)
# ---------------------------------------------------------------------------
add_library(blake3 STATIC
  third_party/blake3/blake3.c
  third_party/blake3/blake3_dispatch.c
  third_party/blake3/blake3_portable.c
)
target_include_directories(blake3 PUBLIC third_party/blake3)
target_compile_definitions(blake3 PRIVATE BLAKE3_NO_SSE2 BLAKE3_NO_SSE41
                                          BLAKE3_NO_AVX2 BLAKE3_NO_AVX512
                                          BLAKE3_USE_NEON=0)

# ---------------------------------------------------------------------------
# Vendored Dear ImGui (core + per-platform backends)
# ---------------------------------------------------------------------------
set(IMGUI_CORE_SOURCES
  third_party/imgui/imgui.cpp
  third_party/imgui/imgui_draw.cpp
  third_party/imgui/imgui_widgets.cpp
  third_party/imgui/imgui_tables.cpp
)
if(APPLE)
  add_library(imgui STATIC
    ${IMGUI_CORE_SOURCES}
    third_party/imgui/imgui_impl_metal.mm
    third_party/imgui/imgui_impl_osx.mm
  )
  set_source_files_properties(
    third_party/imgui/imgui_impl_metal.mm
    third_party/imgui/imgui_impl_osx.mm
    PROPERTIES COMPILE_FLAGS "-fobjc-arc")
  target_link_libraries(imgui PUBLIC
    "-framework Foundation"
    "-framework Cocoa"
    "-framework Metal"
    "-framework MetalKit"
    "-framework QuartzCore"
    "-framework GameController")
elseif(WIN32)
  add_library(imgui STATIC
    ${IMGUI_CORE_SOURCES}
    third_party/imgui/imgui_impl_win32.cpp
    third_party/imgui/imgui_impl_dx11.cpp
  )
  target_link_libraries(imgui PUBLIC d3d11 dxgi d3dcompiler dwmapi)
else()
  add_library(imgui STATIC
    ${IMGUI_CORE_SOURCES}
    third_party/imgui/imgui_impl_glfw.cpp
    third_party/imgui/imgui_impl_opengl3.cpp
  )
  target_link_libraries(imgui PUBLIC glfw OpenGL::GL)
endif()
target_include_directories(imgui PUBLIC third_party/imgui)
if(NOT MSVC)
  target_compile_options(imgui PRIVATE -Wno-deprecated-declarations)
endif()

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
set(LV_SOURCES
  src/main.cpp
  src/cli.cpp
  src/viewer.cpp
  src/cue.cpp
  src/patp.cpp
  src/crypto.cpp
  src/api.cpp
)
if(APPLE)
  list(APPEND LV_SOURCES src/gui_macos.mm src/http_posix.cpp)
elseif(WIN32)
  list(APPEND LV_SOURCES src/gui_win32.cpp src/http_win32.cpp)
else()
  list(APPEND LV_SOURCES src/gui_linux.cpp src/http_posix.cpp)
endif()

add_executable(log-viewer ${LV_SOURCES})
target_include_directories(log-viewer PRIVATE src)
target_link_libraries(log-viewer PRIVATE imgui lmdb monocypher blake3)

if(WIN32)
  # WinHTTP for HTTPS, BCrypt is reserved for any future native crypto
  # we want to delegate to the OS, ws2_32 covers winsock2 symbols pulled
  # in transitively through <windows.h>.
  target_link_libraries(log-viewer PRIVATE winhttp bcrypt ws2_32)
  target_compile_definitions(log-viewer PRIVATE
    NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS UNICODE _UNICODE)
  if(MSVC)
    # Use windowed subsystem for release builds; console for debug so
    # printf() from --probe is visible. The /SUBSYSTEM setting is only
    # part of the answer — main() still entry-points here either way
    # because CMake's WIN32_EXECUTABLE is off.
    target_compile_options(log-viewer PRIVATE /utf-8)
  endif()
else()
  target_include_directories(log-viewer PRIVATE ${mbedtls_SOURCE_DIR}/include)
  target_link_libraries(log-viewer PRIVATE mbedtls mbedx509 mbedcrypto)
endif()

if(APPLE)
  set_source_files_properties(src/gui_macos.mm PROPERTIES COMPILE_FLAGS "-fobjc-arc")
endif()

if(NOT MSVC)
  target_compile_options(log-viewer PRIVATE -Wall -Wextra -Wno-unused-parameter)
endif()

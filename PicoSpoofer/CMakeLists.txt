cmake_minimum_required(VERSION 3.10)
project(WASP_Spoofer)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 1. ملفات المصدر
set(SOURCES
    src/main.cpp
    src/mapper.cpp
    src/driver_comm.cpp
    src/service.cpp
    src/anticheat.cpp
    imgui/imgui.cpp
    imgui/imgui_draw.cpp
    imgui/imgui_widgets.cpp
    imgui/imgui_tables.cpp
    imgui/imgui_impl_dx9.cpp
    imgui/imgui_impl_win32.cpp
)

# 2. أماكن الـ Headers
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/imgui
    ${CMAKE_CURRENT_SOURCE_DIR}/driver
)

# 3. البرنامج (نوعه WIN32 عشان يختفي الكونسول)
add_executable(WASP_Spoofer WIN32 ${SOURCES})

# 4. المكتبات المطلوبة
target_link_libraries(WASP_Spoofer
    d3d9
    d3dx9
    ntdll
    advapi32
    user32
    gdi32
    shell32
)
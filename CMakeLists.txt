cmake_minimum_required(VERSION 3.20)
project(AureliaVPN LANGUAGES C)

if(NOT WIN32)
    message(FATAL_ERROR "Aurelia VPN requires Windows.")
endif()

enable_language(RC)
file(TO_CMAKE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/src/aurelia.ico" AURELIA_ICON_PATH)
configure_file(src/aurelia.rc.in "${CMAKE_CURRENT_BINARY_DIR}/aurelia.rc" @ONLY)

add_executable(aurelia WIN32 src/main.c)
target_sources(aurelia PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/aurelia.rc")
add_executable(aurelia-net WIN32 src/net_helper.c)
target_compile_features(aurelia PRIVATE c_std_11)
target_compile_features(aurelia-net PRIVATE c_std_11)
target_compile_definitions(aurelia PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN)
target_compile_definitions(aurelia-net PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00 COBJMACROS)
target_link_libraries(aurelia PRIVATE comctl32 comdlg32 shell32 ws2_32 bcrypt)
target_link_libraries(aurelia-net PRIVATE shell32 ole32 oleaut32 uuid advapi32 iphlpapi ws2_32)
set(HEV_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/hev-socks5-tunnel")
set(TOR_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/Tor")
add_custom_command(TARGET aurelia-net POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${HEV_DIR}/bin/hev-socks5-tunnel.dll" "$<TARGET_FILE_DIR:aurelia-net>/hev-socks5-tunnel.dll"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${HEV_DIR}/third-part/wintun/bin/amd64/wintun.dll" "$<TARGET_FILE_DIR:aurelia-net>/wintun.dll")
if(EXISTS "${TOR_DIR}")
    add_custom_command(TARGET aurelia POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_directory "${TOR_DIR}" "$<TARGET_FILE_DIR:aurelia>/Tor")
endif()
add_dependencies(aurelia aurelia-net)

if(MSVC)
    target_compile_options(aurelia PRIVATE /W4 /utf-8)
else()
    target_compile_options(aurelia PRIVATE -Wall -Wextra -Wpedantic)
endif()

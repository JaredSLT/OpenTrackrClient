cmake_minimum_required(VERSION 3.10)  # Updated to suppress deprecation warning
project(OpenTrackr C)

set(CMAKE_C_STANDARD 11)

add_executable(OpenTrackr main.c)  # Add yyjson.c (adjust path if needed)
target_link_libraries(OpenTrackr PRIVATE $<$<PLATFORM_ID:Windows>:ws2_32> $<$<NOT:$<PLATFORM_ID:Windows>>:pthread>)
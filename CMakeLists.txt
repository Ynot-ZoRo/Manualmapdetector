cmake_minimum_required(VERSION 3.10)
project(Manualmapdetector)

set(CMAKE_CXX_STANDARD 17)

# Add your source files - adjust this to match your project
file(GLOB SOURCES "*.cpp" "*.c")
file(GLOB HEADERS "*.h" "*.hpp")

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# For static linking (more portable)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

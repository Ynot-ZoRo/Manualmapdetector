cmake_minimum_required(VERSION 3.10)
project(ManualMapDetector VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Windows specific settings
if(WIN32)
    add_executable(ManualMapDetector src/manualmapdetector.cpp)
    
    target_compile_definitions(ManualMapDetector PRIVATE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _CRT_SECURE_NO_WARNINGS
    )
    
    target_link_libraries(ManualMapDetector
        psapi
        iphlpapi
        wintrust
        crypt32
        ws2_32
    )
    
    # Set compiler flags for MSVC
    if(MSVC)
        target_compile_options(ManualMapDetector PRIVATE
            /O2
            /EHsc
            /utf-8
        )
        target_link_options(ManualMapDetector PRIVATE
            /SUBSYSTEM:CONSOLE
            /DYNAMICBASE
            /NXCOMPAT
        )
    endif()
endif()

# Set output directory
set_target_properties(ManualMapDetector PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

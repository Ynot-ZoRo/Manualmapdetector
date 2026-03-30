@echo off
echo Building ManualMapDetector...

if not exist "build" mkdir build
cd build

echo Generating build files...
cmake .. -G "Visual Studio 17 2022" -A x64

echo Building project...
cmake --build . --config Release

echo Build complete!
cd ..
echo Executable is at: build\bin\Release\ManualMapDetector.exe
pause

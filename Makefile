CXX = cl.exe
CXXFLAGS = /nologo /O2 /EHsc /DUNICODE /DNOMINMAX /DWIN32_LEAN_AND_MEAN /std:c++17
LDFLAGS = /link /subsystem:console /incremental:no /dynamicbase /nxcompat
LIBS = psapi.lib iphlpapi.lib wintrust.lib crypt32.lib ws2_32.lib

TARGET = ManualMapDetector.exe
SRC = src/manualmapdetector.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(SRC) $(LDFLAGS) $(LIBS) /out:$(TARGET)

clean:
	-del $(TARGET) *.obj *.pdb

.PHONY: all clean

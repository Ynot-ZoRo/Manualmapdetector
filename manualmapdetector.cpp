ections (IPv4)\n");
    return 0;
}
// PIDsDetectorPro.cpp by Ynot-ZoRo
//
// Escanea todos los procesos accesibles y les asigna una puntuación basada en múltiples
// indicadores de inyección y evasión. Incluye detección de inline hooks en APIs
// críticas, parches en ETW/AMSI, anti-debugging, memoria ejecutable privada, PE
// manual-map, módulos sin firma y off-path, así como conexiones de red externas.

// Configuración de compilación (VS en x64):
//   cl /nologo /O2 /EHsc PIDsDetectorPro.cpp /DUNICODE /DNOMINMAX /DWIN32_LEAN_AND_MEAN \
//      /link /subsystem:console /incremental:no /dynamicbase /nxcompat psapi.lib \
//      iphlpapi.lib wintrust.lib crypt32.lib Ws2_32.lib

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <iphlpapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <cstdint>
#include <cstdio>
#include <cstdarg>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <memory>
#include <intrin.h>
#include <cstring>

#pragma intrinsic(_byteswap_ulong)
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

// Dynamic declaration of NtQueryInformationThread
typedef NTSTATUS(NTAPI* PFN_NtQueryInformationThread)(
    HANDLE, THREADINFOCLASS, PVOID, ULONG, PULONG);
static PFN_NtQueryInformationThread g_NtQueryInformationThread = nullptr;

// Console output helper
static void Printf(const char* fmt, ...) {
    char buf[4096];
    va_list ap;
    va_start(ap, fmt);
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);
    DWORD written;
    WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), buf, (DWORD)strlen(buf), &written, nullptr);
}

// Enable SeDebugPrivilege to inspect protected processes
static void EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    if (!LookupPrivilegeValueW(nullptr, L"SeDebugPrivilege", &tp.Privileges[0].Luid)) {
        CloseHandle(hToken);
        return;
    }
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hToken);
}

// Check if executable path is under system directories
static bool InSystemPath(const std::wstring& path) {
    std::wstring lp = path;
    std::transform(lp.begin(), lp.end(), lp.begin(), ::towlower);
    return lp.find(L"\\windows\\") != std::wstring::npos ||
        lp.find(L"\\program files") != std::wstring::npos;
}

// Use WinTrust to verify if a file is digitally signed
static bool IsSigned(const std::wstring& path) {
    WINTRUST_FILE_INFO file = {};
    file.cbStruct = sizeof(file);
    file.pcwszFilePath = path.c_str();
    GUID guid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data = {};
    data.cbStruct = sizeof(data);
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file;
    data.dwStateAction = 0;
    data.dwProvFlags = WTD_SAFER_FLAG;
    LONG status = WinVerifyTrust(nullptr, &guid, &data);
    return status == ERROR_SUCCESS;
}

// Helpers to identify local IPs
static bool IsLocalIPv4(DWORD ip) {
    DWORD h = _byteswap_ulong(ip); // ntohl equivalent
    if ((h & 0xFF000000) == 0x7F000000) return true;       // 127.0.0.0/8
    if ((h & 0xFF000000) == 0x0A000000) return true;       // 10.0.0.0/8
    if ((h & 0xFFF00000) == 0xAC100000) return true;       // 172.16.0.0/12
    if ((h & 0xFFFF0000) == 0xC0A80000) return true;       // 192.168.0.0/16
    return false;
}

// Detect PE signatures in arbitrary memory
static bool ContainsPE(const uint8_t* buf, size_t sz) {
    for (size_t i = 0; i + sizeof(IMAGE_DOS_HEADER) + 4 < sz; ++i) {
        auto dos = (const IMAGE_DOS_HEADER*)(buf + i);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            DWORD off = dos->e_lfanew;
            if (off > 0 && off < sz - 4 && *(DWORD*)(buf + i + off) == IMAGE_NT_SIGNATURE)
                return true;
        }
    }
    return false;
}

// Module info structure
struct ModuleInfo {
    HMODULE base;
    SIZE_T size;
    std::wstring name;
    std::wstring path;
};

// Enumerate modules of a process (all types)
static std::vector<ModuleInfo> EnumModules(HANDLE hp) {
    std::vector<ModuleInfo> v;
    HMODULE list[1024];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(hp, list, sizeof(list), &needed, LIST_MODULES_ALL))
        return v;
    size_t count = needed / sizeof(HMODULE);
    wchar_t nameBuf[MAX_PATH], pathBuf[MAX_PATH];
    MODULEINFO mi{};
    for (size_t i = 0; i < count; ++i) {
        if (!GetModuleInformation(hp, list[i], &mi, sizeof(mi)))
            continue;
        GetModuleBaseNameW(hp, list[i], nameBuf, MAX_PATH);
        GetModuleFileNameExW(hp, list[i], pathBuf, MAX_PATH);
        v.push_back({ list[i], mi.SizeOfImage, nameBuf, pathBuf });
    }
    return v;
}

static bool AddressInModules(const std::vector<ModuleInfo>& mods, uintptr_t addr) {
    for (auto& m : mods) {
        uintptr_t start = (uintptr_t)m.base;
        uintptr_t end = start + m.size;
        if (addr >= start && addr < end)
            return true;
    }
    return false;
}

// Baseline function prologue structure
struct FuncBaseline {
    size_t offset;
    uint8_t bytes[16];
    std::string name;
};

// Baseline vectors
static std::vector<FuncBaseline> g_NtFuncs, g_K32Funcs, g_AmsiFuncs, g_DbgFuncs;
static size_t g_EtwOffset = 0;
static uint8_t g_EtwBaseline[16] = {};

// Initialise baselines for API prologues
static void InitBaselines() {
    // Local modules
    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    if (!hNt) hNt = LoadLibraryW(L"ntdll.dll");
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (!hK32) hK32 = LoadLibraryW(L"kernel32.dll");
    
    // ntdll functions of interest (syscalls)
    const char* ntList[] = {
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtCreateThreadEx",
        "NtQueueApcThread", "NtWriteVirtualMemory", "NtOpenProcess",
        "NtOpenThread", "NtSuspendThread", "NtResumeThread",
        "NtReadVirtualMemory", "NtMapViewOfSection", "NtUnmapViewOfSection",
        "NtSetInformationThread", "NtQueryInformationThread"
    };
    for (auto name : ntList) {
        FARPROC fp = GetProcAddress(hNt, name);
        if (!fp) continue;
        FuncBaseline f;
        f.offset = (size_t)((uint8_t*)fp - (uint8_t*)hNt);
        f.name = name;
        // FIX: Cast FARPROC to void* for memcpy
        memcpy(f.bytes, (void*)fp, sizeof(f.bytes));
        g_NtFuncs.push_back(f);
    }
    
    // Baseline for EtwEventWrite
    FARPROC etw = GetProcAddress(hNt, "EtwEventWrite");
    if (etw) {
        g_EtwOffset = (size_t)((uint8_t*)etw - (uint8_t*)hNt);
        // FIX: Cast FARPROC to void* for memcpy
        memcpy(g_EtwBaseline, (void*)etw, sizeof(g_EtwBaseline));
    }
    
    // kernel32 functions (injection primitives)
    const char* k32List[] = {
        "CreateRemoteThread", "WriteProcessMemory", "ReadProcessMemory",
        "VirtualAllocEx", "VirtualProtectEx", "QueueUserAPC",
        "CreateToolhelp32Snapshot", "Module32FirstW", "Module32NextW"
    };
    for (auto name : k32List) {
        FARPROC fp = GetProcAddress(hK32, name);
        if (!fp) continue;
        FuncBaseline f;
        f.offset = (size_t)((uint8_t*)fp - (uint8_t*)hK32);
        f.name = name;
        // FIX: Cast FARPROC to void* for memcpy
        memcpy(f.bytes, (void*)fp, sizeof(f.bytes));
        g_K32Funcs.push_back(f);
    }
    
    // AMSI functions
    HMODULE hAmsi = LoadLibraryW(L"amsi.dll");
    if (hAmsi) {
        const char* amsiList[] = {
            "AmsiScanBuffer", "AmsiScanString", "AmsiInitialize", "AmsiOpenSession"
        };
        for (auto name : amsiList) {
            FARPROC fp = GetProcAddress(hAmsi, name);
            if (!fp) continue;
            FuncBaseline f;
            f.offset = (size_t)((uint8_t*)fp - (uint8_t*)hAmsi);
            f.name = name;
            // FIX: Cast FARPROC to void* for memcpy
            memcpy(f.bytes, (void*)fp, sizeof(f.bytes));
            g_AmsiFuncs.push_back(f);
        }
    }
    
    // Debug-related functions
    const char* dbgList[] = {
        "DbgUiRemoteBreakin", "DbgBreakPoint", "KiUserExceptionDispatcher"
    };
    for (auto name : dbgList) {
        FARPROC fp = GetProcAddress(hNt, name); // all in ntdll
        if (!fp) continue;
        FuncBaseline f;
        f.offset = (size_t)((uint8_t*)fp - (uint8_t*)hNt);
        f.name = name;
        // FIX: Cast FARPROC to void* for memcpy
        memcpy(f.bytes, (void*)fp, sizeof(f.bytes));
        g_DbgFuncs.push_back(f);
    }
}

// Heuristics data structure per process
struct Heuristics {
    int privX = 0;       // MEM_PRIVATE executable pages
    int rwx = 0;         // RWX pages
    int peHdr = 0;       // PE headers in memory (manual map)
    int threadsOut = 0;  // Threads starting outside modules
    int hooks = 0;       // Inline hook detections (ntdll/kernel32)
    bool etwPatch = false;  // EtwEventWrite patched
    int amsiPatch = 0;    // AMSI functions patched
    int dbgPatch = 0;     // Debug functions patched
    bool unsignedExe = false;
    bool offPath = false;
    int modsUnsigned = 0;
    int netConns = 0;
    int modulesNoPath = 0; // modules with empty/unknown path (memory only)
};

// Determine if a process is a likely JIT host to reduce noise
static bool IsLikelyJIT(const std::wstring& name) {
    std::wstring low = name;
    std::transform(low.begin(), low.end(), low.begin(), ::towlower);
    static const wchar_t* wl[] = {
        L"devenv.exe", L"servicehub", L"msbuild.exe", L"node.exe",
        L"chrome.exe", L"msedge.exe", L"firefox.exe", L"brave.exe",
        L"dotnet.exe", L"w3wp.exe", L"spotify.exe", L"teams.exe",
        L"discord.exe"
    };
    for (auto w : wl) {
        if (low.find(w) != std::wstring::npos)
            return true;
    }
    return false;
}

// Analyze a single process
static Heuristics AnalyzeProcess(DWORD pid, const std::wstring& exePath, HANDLE hp) {
    Heuristics h{};
    // Signed/exe and path
    h.unsignedExe = !IsSigned(exePath);
    h.offPath = !InSystemPath(exePath);
    // Enumerate modules
    auto mods = EnumModules(hp);
    // Count unsigned modules and modules with no path
    for (auto& m : mods) {
        if (!IsSigned(m.path))
            h.modsUnsigned++;
        if (m.path.empty() || wcslen(m.path.c_str()) == 0)
            h.modulesNoPath++;
    }
    // Threads outside modules
    HANDLE tsnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (tsnap != INVALID_HANDLE_VALUE && g_NtQueryInformationThread) {
        THREADENTRY32 te{ sizeof(te) };
        if (Thread32First(tsnap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid)
                    continue;
                HANDLE th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
                if (th) {
                    PVOID start = nullptr;
                    ULONG ret = 0;
                    if (g_NtQueryInformationThread(th, (THREADINFOCLASS)9,
                        &start, sizeof(start), &ret) == 0 && start) {
                        uintptr_t sa = (uintptr_t)start;
                        if (!AddressInModules(mods, sa))
                            h.threadsOut++;
                    }
                    CloseHandle(th);
                }
            } while (Thread32Next(tsnap, &te));
        }
        CloseHandle(tsnap);
    }
    // Memory scan: count private exec/RWX pages and PE headers
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    uintptr_t a = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t max = (uintptr_t)si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi{};
    while (a < max) {
        if (VirtualQueryEx(hp, (LPCVOID)a, &mbi, sizeof(mbi)) != sizeof(mbi))
            break;
        bool exec = mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
        bool rw = mbi.Protect & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);
        bool priv = (mbi.Type == MEM_PRIVATE);
        if (exec) {
            if (priv) h.privX++;
            if (rw) h.rwx++;
            // Up to 8KB for PE detection
            SIZE_T cap = (SIZE_T)std::min((SIZE_T)mbi.RegionSize, (SIZE_T)0x2000);
            std::vector<uint8_t> buf(cap);
            SIZE_T rd = 0;
            if (ReadProcessMemory(hp, mbi.BaseAddress, buf.data(), cap, &rd) && rd > 256) {
                if (ContainsPE(buf.data(), rd))
                    h.peHdr++;
            }
        }
        a = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    // Network connections (only IPv4 TCP for speed)
    DWORD sz = 0;
    GetExtendedTcpTable(nullptr, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    std::unique_ptr<uint8_t[]> tmp(new uint8_t[sz]);
    PMIB_TCPTABLE_OWNER_PID tbl = (PMIB_TCPTABLE_OWNER_PID)tmp.get();
    if (GetExtendedTcpTable(tbl, &sz, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == 0) {
        for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
            if (tbl->table[i].dwOwningPid != pid)
                continue;
            DWORD remote = tbl->table[i].dwRemoteAddr;
            if (remote != 0 && !IsLocalIPv4(remote))
                h.netConns++;
        }
    }
    // Inline hook detection
    const ModuleInfo* ntmod = nullptr, * k32mod = nullptr, * amsimod = nullptr;
    for (auto& m : mods) {
        std::wstring low = m.name;
        std::transform(low.begin(), low.end(), low.begin(), ::towlower);
        if (low == L"ntdll.dll") ntmod = &m;
        else if (low == L"kernel32.dll") k32mod = &m;
        else if (low == L"amsi.dll") amsimod = &m;
    }
    // Compare against baseline
    auto checkHooks = [&](const ModuleInfo* mod, const std::vector<FuncBaseline>& funcs, int& counter) {
        if (!mod) return;
        for (auto& f : funcs) {
            uintptr_t remote = (uintptr_t)mod->base + f.offset;
            uint8_t bytes[16]{};
            SIZE_T rd = 0;
            if (ReadProcessMemory(hp, (LPCVOID)remote, bytes, sizeof(bytes), &rd) && rd >= 8) {
                bool diff = memcmp(bytes, f.bytes, 8) != 0;
                bool jmp = (bytes[0] == 0xE9 || bytes[0] == 0xE8 || bytes[0] == 0xC3 ||
                    (bytes[0] == 0xFF && ((bytes[1] >> 3) == 4)));
                if (diff && jmp)
                    counter++;
            }
        }
    };
    // ntdll/k32 hooks
    checkHooks(ntmod, g_NtFuncs, h.hooks);
    checkHooks(k32mod, g_K32Funcs, h.hooks);
    // ETW patch
    if (ntmod && g_EtwOffset) {
        uintptr_t remote = (uintptr_t)ntmod->base + g_EtwOffset;
        uint8_t bytes[16]{};
        SIZE_T rd = 0;
        if (ReadProcessMemory(hp, (LPCVOID)remote, bytes, sizeof(bytes), &rd) && rd >= 8) {
            bool diff = memcmp(bytes, g_EtwBaseline, 8) != 0;
            bool patched = (bytes[0] == 0xC3 || bytes[0] == 0x90 || bytes[0] == 0xE9 || bytes[0] == 0xE8);
            if (diff && patched)
                h.etwPatch = true;
        }
    }
    // AMSI patches
    if (amsimod) {
        checkHooks(amsimod, g_AmsiFuncs, h.amsiPatch);
    }
    // Debug patches (in ntdll)
    if (ntmod) {
        checkHooks(ntmod, g_DbgFuncs, h.dbgPatch);
    }
    return h;
}

// Calculate weighted score
static int ComputeScore(const Heuristics& h, bool isJit, bool strict) {
    int s = 0;
    // Critical indicators
    s += h.threadsOut * 5;
    s += h.peHdr * 4;
    s += h.hooks * 4;
    if (h.etwPatch) s += 4;
    s += h.amsiPatch * 3;
    s += h.dbgPatch * 3;
    // Memory heuristics (capped)
    s += std::min(h.privX, 4);
    s += std::min(h.rwx, 3);
    // Module and path heuristics
    if (h.unsignedExe) s += 3;
    if (h.offPath) s += 2;
    s += h.modsUnsigned;
    s += h.modulesNoPath * 2;
    // Network
    s += h.netConns;
    // JIT suppression
    if (isJit && h.peHdr == 0 && h.threadsOut == 0 && h.hooks == 0 &&
        !h.etwPatch && h.amsiPatch == 0 && h.dbgPatch == 0) {
        s = 0;
    }
    // Strict: require at least one strong indicator
    if (strict && h.peHdr == 0 && h.threadsOut == 0 && h.hooks == 0 &&
        !h.etwPatch && h.amsiPatch == 0 && h.dbgPatch == 0 &&
        !h.unsignedExe && !h.offPath && h.modsUnsigned == 0) {
        s = 0;
    }
    return s;
}

int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    // Resolve NtQueryInformationThread
    HMODULE hNt = GetModuleHandleW(L"ntdll.dll");
    if (!hNt) hNt = LoadLibraryW(L"ntdll.dll");
    if (hNt) {
        g_NtQueryInformationThread = (PFN_NtQueryInformationThread)GetProcAddress(hNt,
            "NtQueryInformationThread");
    }
    EnableDebugPrivilege();
    InitBaselines();
    bool strict = false;
    for (int i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--strict") == 0)
            strict = true;
    }
    Printf("Hunting suspicious processes (PIDsDetectorPro)\n");
    // Snapshot processes
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        Printf("Failed to snapshot processes\n");
        return 1;
    }
    std::vector<DWORD> pids;
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID > 4)
                pids.push_back(pe.th32ProcessID);
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    // Collect results
    struct Row { DWORD pid; std::wstring name; Heuristics h; int score; };
    std::vector<Row> rows;
    rows.reserve(pids.size());
    for (auto pid : pids) {
        HANDLE hp = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_OPERATION, FALSE, pid);
        if (!hp) continue;
        wchar_t exePath[MAX_PATH]{};
        if (!GetModuleFileNameExW(hp, nullptr, exePath, MAX_PATH)) {
            CloseHandle(hp);
            continue;
        }
        wchar_t baseName[MAX_PATH]{};
        GetModuleBaseNameW(hp, nullptr, baseName, MAX_PATH);
        std::wstring name(baseName);
        Heuristics heur = AnalyzeProcess(pid, exePath, hp);
        bool jit = IsLikelyJIT(name);
        int score = ComputeScore(heur, jit, strict);
        if (score > 0) {
            rows.push_back({ pid, name, heur, score });
        }
        CloseHandle(hp);
    }
    std::sort(rows.begin(), rows.end(), [](const Row& a, const Row& b) {
        return a.score > b.score;
    });
    // Print top results
    Printf("\nPID     Score  Nombre                     privX rwx peHdr hilosOut Hooks Etw Amsi Dbg Unsig OffP ModsU NoPath Conn\n");
    for (size_t i = 0; i < rows.size() && i < 20; ++i) {
        const Row& r = rows[i];
        Printf("%-7lu %-6d %-25S %5d %3d %5d %8d %5d %3d %4d %3d %5d %4d %5d %6d %4d\n",
            r.pid, r.score, r.name.c_str(),
            r.h.privX, r.h.rwx, r.h.peHdr, r.h.threadsOut,
            r.h.hooks, r.h.etwPatch ? 1 : 0, r.h.amsiPatch, r.h.dbgPatch,
            r.h.unsignedExe ? 1 : 0, r.h.offPath ? 1 : 0,
            r.h.modsUnsigned, r.h.modulesNoPath, r.h.netConns);
    }
    if (rows.empty())
        Printf("No suspicious processes detected\n");
    // Legend
    Printf("\nLegend:\n");
    Printf("  privX   = private executable pages\n");
    Printf("  rwx     = RWX pages\n");
    Printf("  peHdr   = PE header regions (manual map)\n");
    Printf("  hilosOut= threads starting outside modules\n");
    Printf("  Hooks   = inline hook deviations (ntdll/kernel32)\n");
    Printf("  Etw     = 1 if EtwEventWrite patched\n");
    Printf("  Amsi    = # of patched AMSI functions\n");
    Printf("  Dbg     = # of patched debug functions (anti-debug)\n");
    Printf("  Unsig   = 1 if main executable unsigned\n");
    Printf("  OffP    = 1 if main executable outside Windows/Program Files\n");
    Printf("  ModsU   = unsigned loaded modules\n");
    Printf("  NoPath  = modules with no path (memory-only)\n");
    Printf("  Conn    = external network connections (IPv4)\n");
    return 0;
}

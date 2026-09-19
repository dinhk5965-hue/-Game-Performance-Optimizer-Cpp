#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <winternl.h>

#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cwchar>
#include <memory>
#include <map>
#include <set>
#include <thread>
#include <mutex>
#include <atomic>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <locale>
#include <cstdio>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")

#ifndef PROCESS_QUERY_LIMITED_INFORMATION
#define PROCESS_QUERY_LIMITED_INFORMATION 0x1000
#endif

#ifndef PROCESS_QUERY_INFORMATION
#define PROCESS_QUERY_INFORMATION 0x0400
#endif

#ifndef PROCESS_VM_READ
#define PROCESS_VM_READ 0x0010
#endif

#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION 0x0200
#endif

#ifndef ProcessPowerThrottling
#define ProcessPowerThrottling 4
#endif

#ifndef ProcessMemoryPriority
#define ProcessMemoryPriority 0
#endif

#ifndef PROCESS_POWER_THROTTLING_EXECUTION_SPEED
#define PROCESS_POWER_THROTTLING_EXECUTION_SPEED 0x1
#endif

#ifndef PROCESS_POWER_THROTTLING_CURRENT_VERSION
#define PROCESS_POWER_THROTTLING_CURRENT_VERSION 1
#endif

#ifndef MEMORY_PRIORITY_LOW
#define MEMORY_PRIORITY_LOW 2
#endif

#ifndef EVENT_SYSTEM_FOREGROUND
#define EVENT_SYSTEM_FOREGROUND 0x0003
#endif

#ifndef WINEVENT_OUTOFCONTEXT
#define WINEVENT_OUTOFCONTEXT 0x0000
#endif

#ifndef WINEVENT_SKIPOWNPROCESS
#define WINEVENT_SKIPOWNPROCESS 0x0002
#endif

#ifndef AF_UNSPEC
#define AF_UNSPEC 0
#endif

#ifndef IF_TYPE_SOFTWARE_LOOPBACK
#define IF_TYPE_SOFTWARE_LOOPBACK 24
#endif

#ifndef TCP_TABLE_OWNER_PID_ALL
#define TCP_TABLE_OWNER_PID_ALL 5
#endif

#ifndef UDP_TABLE_OWNER_PID
#define UDP_TABLE_OWNER_PID 1
#endif

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI* NtQueryTimerResolutionFn)(PULONG, PULONG, PULONG);

struct POWER_STATE_COMPAT {
    DWORD Version;
    DWORD ControlMask;
    DWORD StateMask;
};

struct MEMORY_PRIORITY_COMPAT {
    ULONG MemoryPriority;
};

struct ProcessHandleDeleter {
    void operator()(HANDLE h) const {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
};

using UniqueHandle = std::unique_ptr<void, ProcessHandleDeleter>;

struct SnapshotDeleter {
    void operator()(HANDLE h) const {
        if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
};

using UniqueSnapshot = std::unique_ptr<void, SnapshotDeleter>;

struct WinEventHookDeleter {
    void operator()(HWINEVENTHOOK h) const {
        if (h) UnhookWinEvent(h);
    }
};

using UniqueWinEventHook = std::unique_ptr<HWINEVENTHOOK__, WinEventHookDeleter>;

struct GameInfo {
    DWORD pid = 0;
    std::wstring exe;
    std::wstring name;
};

struct ProcessSample {
    DWORD pid = 0;
    std::wstring exe;
    std::wstring role;
    double cpuPercent = 0.0;
    SIZE_T workingSet = 0;
    SIZE_T privateBytes = 0;
    ULONGLONG ioRead = 0;
    ULONGLONG ioWrite = 0;
    DWORD threadCount = 0;
    DWORD priorityClass = 0;
    BOOL priorityBoostDisabled = FALSE;
    ULONG memoryPriority = 0;
    bool memoryPriorityValid = false;
    POWER_STATE_COMPAT power = {};
    bool powerValid = false;
};

static const wchar_t* kGameFiles[] = {
    L"tslgame.exe",
    L"league of legends.exe",
    L"cs2.exe",
    L"valorant-win64-shipping.exe",
    L"naraka.exe",
    L"dota2.exe",
    L"overwatch.exe",
    L"r5apex.exe",
    L"rainbowsix.exe",
    L"rainbowsix_vulkan.exe",
    L"fifa.exe",
    L"fc24.exe",
    L"fc25.exe",
    L"rocketleague.exe",
    L"crossfire.exe",
    L"sf6.exe",
    L"tekken8-win64-shipping.exe",
    L"starcraft2.exe",
    L"smite.exe",
    L"brawlhalla.exe"
};

static const wchar_t* kProtectedProcesses[] = {
    L"system",
    L"system idle process",
    L"registry",
    L"smss.exe",
    L"csrss.exe",
    L"wininit.exe",
    L"services.exe",
    L"lsass.exe",
    L"winlogon.exe",
    L"dwm.exe",
    L"explorer.exe",
    L"sihost.exe",
    L"fontdrvhost.exe",
    L"conhost.exe",
    L"audiodg.exe",
    L"msmpeng.exe",
    L"securityhealthservice.exe",
    L"searchindexer.exe",
    L"runtimebroker.exe",
    L"taskhostw.exe",
    L"spoolsv.exe",
    L"memory compression",
    L"ntoskrnl.exe"
};

static const wchar_t* kAntiCheatProcesses[] = {
    L"vgc.exe",
    L"vgtray.exe",
    L"vgk.exe",
    L"faceitclient.exe",
    L"faceitac.exe",
    L"easyanticheat.exe",
    L"easyanticheat_eos.exe",
    L"eac_launcher.exe",
    L"beservice.exe",
    L"battleye.exe"
};

static const wchar_t* kBackgroundTargets[] = {
    L"chrome.exe",
    L"msedge.exe",
    L"firefox.exe",
    L"discord.exe",
    L"steam.exe",
    L"steamwebhelper.exe",
    L"epicgameslauncher.exe",
    L"riotclientservices.exe",
    L"riotclientux.exe",
    L"battle.net.exe",
    L"ea app.exe",
    L"eadesktop.exe",
    L"spotify.exe",
    L"telegram.exe",
    L"whatsapp.exe",
    L"onedrive.exe"
};

using SetProcessInformationFn = BOOL (WINAPI*)(HANDLE, DWORD, LPVOID, DWORD);
using GetProcessInformationFn = BOOL (WINAPI*)(HANDLE, DWORD, LPVOID, DWORD);

static SetProcessInformationFn gSetProcessInformation = nullptr;
static GetProcessInformationFn gGetProcessInformation = nullptr;

static HWND gEventWindow = nullptr;
static HANDLE gWakeEvent = nullptr;
static std::atomic<bool> gStop(false);
static std::atomic<DWORD> gForegroundPid(0);

static GameInfo gCurrentGame;
static DWORD gCurrentPid = 0;

static std::wofstream gLog;
static std::mutex gLogMutex;
static UINT_PTR gLogTimer = 0;
static std::wstring gLogPath;

static std::map<DWORD, ULONGLONG> gLastProcessCpu;
static std::map<DWORD, ULONGLONG> gLastProcessIoRead;
static std::map<DWORD, ULONGLONG> gLastProcessIoWrite;
static ULONGLONG gLastSystemTotal = 0;
static ULONGLONG gLastSystemIdle = 0;
static ULONGLONG gLastSampleTick = 0;

static std::wstring Lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), towlower);
    return s;
}

static bool EqualsIgnoreCase(const std::wstring& a, const wchar_t* b) {
    return Lower(a) == Lower(b);
}

static bool IsInList(const std::wstring& value, const wchar_t* const* list, size_t count) {
    std::wstring v = Lower(value);
    for (size_t i = 0; i < count; ++i) {
        if (v == Lower(list[i])) return true;
    }
    return false;
}

static bool IsGameFile(const std::wstring& exe) {
    return IsInList(exe, kGameFiles, sizeof(kGameFiles) / sizeof(kGameFiles[0]));
}

static bool IsProtectedProcess(const std::wstring& exe) {
    return IsInList(exe, kProtectedProcesses, sizeof(kProtectedProcesses) / sizeof(kProtectedProcesses[0]));
}

static bool IsAntiCheatProcess(const std::wstring& exe) {
    return IsInList(exe, kAntiCheatProcesses, sizeof(kAntiCheatProcesses) / sizeof(kAntiCheatProcesses[0]));
}

static bool IsBackgroundTarget(const std::wstring& exe) {
    return IsInList(exe, kBackgroundTargets, sizeof(kBackgroundTargets) / sizeof(kBackgroundTargets[0]));
}

static std::wstring ErrorText(DWORD error) {
    if (!error) return L"ERROR_SUCCESS";

    wchar_t* buffer = nullptr;
    DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                  FORMAT_MESSAGE_FROM_SYSTEM |
                  FORMAT_MESSAGE_IGNORE_INSERTS;

    DWORD len = FormatMessageW(
        flags, NULL, error, 0,
        reinterpret_cast<LPWSTR>(&buffer), 0, NULL
    );

    std::wstring result = L"ERROR_" + std::to_wstring(error);

    if (len && buffer) {
        result += L" (";
        result.append(buffer, len);
        result += L")";
        LocalFree(buffer);
    }

    return result;
}

static std::wstring NowText() {
    SYSTEMTIME st = {};
    GetLocalTime(&st);

    wchar_t b[64] = {};

    swprintf_s(
        b,
        L"%04u-%02u-%02u %02u:%02u:%02u.%03u",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond,
        st.wMilliseconds
    );

    return b;
}

static void LogLine(const std::wstring& text) {
    std::lock_guard<std::mutex> lock(gLogMutex);

    if (!gLog.is_open()) return;

    gLog << L"[" << NowText() << L"] " << text << L"\n";
    gLog.flush();
}

static std::wstring ExeDirectory() {
    wchar_t path[MAX_PATH * 4] = {};

    DWORD n = GetModuleFileNameW(
        NULL,
        path,
        static_cast<DWORD>(sizeof(path) / sizeof(path[0]))
    );

    if (!n || n >= sizeof(path) / sizeof(path[0])) {
        return L".";
    }

    wchar_t* slash = wcsrchr(path, L'\\');

    if (!slash) return L".";

    *slash = L'\0';

    return path;
}

static void OpenLog() {
    gLogPath = ExeDirectory() + L"\\game_optimizer_collector.txt";

    gLog.open(gLogPath.c_str(), std::ios::out | std::ios::app);

    if (!gLog.is_open()) return;

    gLog.imbue(std::locale(""));

    LogLine(L"============================================================");
    LogLine(L"GAME OPTIMIZER - INFORMATION COLLECTOR SESSION START");
    LogLine(L"MODE=COLLECTOR_ONLY");
    LogLine(L"IMPORTANT=NO_OPTIMIZATION_OR_SYSTEM_MODIFICATION_IS_PERFORMED");
    LogLine(L"LogFile=" + gLogPath);
}

static ULONGLONG FileTimeValue(const FILETIME& ft) {
    ULARGE_INTEGER u = {};
    u.LowPart = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

static std::wstring ProcessName(DWORD pid) {
    UniqueHandle h(
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            pid
        )
    );

    if (!h) return L"";

    wchar_t buffer[MAX_PATH * 4] = {};
    DWORD size = static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0]));

    if (QueryFullProcessImageNameW(
            (HANDLE)h.get(),
            0,
            buffer,
            &size)) {

        const wchar_t* slash = wcsrchr(buffer, L'\\');

        return Lower(slash ? slash + 1 : buffer);
    }

    return L"";
}

static std::wstring ProcessPath(DWORD pid) {
    UniqueHandle h(
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            pid
        )
    );

    if (!h) return L"";

    wchar_t buffer[MAX_PATH * 4] = {};
    DWORD size = static_cast<DWORD>(sizeof(buffer) / sizeof(buffer[0]));

    if (QueryFullProcessImageNameW(
            (HANDLE)h.get(),
            0,
            buffer,
            &size)) {

        return buffer;
    }

    return L"";
}

static bool GetMemoryPriority(
    HANDLE process,
    ULONG& priority
) {
    if (!gGetProcessInformation) return false;

    MEMORY_PRIORITY_COMPAT info = {};

    if (!gGetProcessInformation(
            process,
            ProcessMemoryPriority,
            &info,
            sizeof(info))) {

        return false;
    }

    priority = info.MemoryPriority;
    return true;
}

static bool GetPowerState(
    HANDLE process,
    POWER_STATE_COMPAT& state
) {
    if (!gGetProcessInformation) return false;

    ZeroMemory(&state, sizeof(state));

    return gGetProcessInformation(
        process,
        ProcessPowerThrottling,
        &state,
        sizeof(state)
    ) != FALSE;
}

static bool ReadProcessSample(
    DWORD pid,
    ProcessSample& sample
) {
    sample = ProcessSample();
    sample.pid = pid;
    sample.exe = ProcessName(pid);

    if (sample.exe.empty()) return false;

    HANDLE h = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
        FALSE,
        pid
    );

    if (!h) {
        h = OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            pid
        );
    }

    if (!h) return false;

    FILETIME createTime = {};
    FILETIME exitTime = {};
    FILETIME kernelTime = {};
    FILETIME userTime = {};

    bool timesOk = GetProcessTimes(
        h,
        &createTime,
        &exitTime,
        &kernelTime,
        &userTime
    ) != FALSE;

    if (timesOk) {
        ULONGLONG procCpu =
            FileTimeValue(kernelTime) +
            FileTimeValue(userTime);

        ULONGLONG now = GetTickCount64();

        if (gLastProcessCpu.count(pid) &&
            gLastSampleTick &&
            now > gLastSampleTick) {

            ULONGLONG old = gLastProcessCpu[pid];

            ULONGLONG delta =
                procCpu >= old ? procCpu - old : 0;

            ULONGLONG wall =
                (now - gLastSampleTick) * 10000ULL;

            if (wall) {
                sample.cpuPercent =
                    100.0 *
                    static_cast<double>(delta) /
                    static_cast<double>(wall);
            }
        }

        gLastProcessCpu[pid] = procCpu;
    }

    PROCESS_MEMORY_COUNTERS pmc = {};
    pmc.cb = sizeof(pmc);

    if (GetProcessMemoryInfo(
            h,
            &pmc,
            sizeof(pmc))) {

        sample.workingSet = pmc.WorkingSetSize;
        sample.privateBytes = pmc.PrivateUsage;
    }

    IO_COUNTERS io = {};

    if (GetProcessIoCounters(h, &io)) {
        sample.ioRead = io.ReadTransferCount;
        sample.ioWrite = io.WriteTransferCount;
    }

    sample.priorityClass = GetPriorityClass(h);

    GetProcessPriorityBoost(
        h,
        &sample.priorityBoostDisabled
    );

    sample.memoryPriorityValid =
        GetMemoryPriority(
            h,
            sample.memoryPriority
        );

    sample.powerValid =
        GetPowerState(
            h,
            sample.power
        );

    CloseHandle(h);

    UniqueSnapshot snapshot(
        CreateToolhelp32Snapshot(
            TH32CS_SNAPTHREAD,
            0
        )
    );

    if (snapshot.get() &&
        snapshot.get() != INVALID_HANDLE_VALUE) {

        THREADENTRY32 te = {};
        te.dwSize = sizeof(te);

        if (Thread32First(
                (HANDLE)snapshot.get(),
                &te)) {

            do {
                if (te.th32OwnerProcessID == pid) {
                    ++sample.threadCount;
                }
            } while (Thread32Next(
                (HANDLE)snapshot.get(),
                &te
            ));
        }
    }

    return timesOk;
}

static void LogProcessSample(
    DWORD pid,
    const std::wstring& role
) {
    ProcessSample sample;

    if (!ReadProcessSample(pid, sample)) {
        LogLine(
            L"PROCESS_READ_FAIL pid=" +
            std::to_wstring(pid) +
            L" role=" +
            role +
            L" error=" +
            ErrorText(GetLastError())
        );
        return;
    }

    sample.role = role;

    ULONGLONG oldRead =
        gLastProcessIoRead[pid];

    ULONGLONG oldWrite =
        gLastProcessIoWrite[pid];

    std::wstringstream ss;

    ss << L"PROCESS"
       << L" role=" << role
       << L" pid=" << pid
       << L" exe=" << sample.exe
       << L" path=" << ProcessPath(pid)
       << L" cpu_pct=" << std::fixed
       << std::setprecision(2)
       << sample.cpuPercent
       << L" working_set_mb="
       << (static_cast<double>(sample.workingSet) / 1048576.0)
       << L" private_mb="
       << (static_cast<double>(sample.privateBytes) / 1048576.0)
       << L" io_read_mb_total="
       << (static_cast<double>(sample.ioRead) / 1048576.0)
       << L" io_write_mb_total="
       << (static_cast<double>(sample.ioWrite) / 1048576.0)
       << L" io_read_mb_delta="
       << (static_cast<double>(
              sample.ioRead >= oldRead
              ? sample.ioRead - oldRead
              : 0
          ) / 1048576.0)
       << L" io_write_mb_delta="
       << (static_cast<double>(
              sample.ioWrite >= oldWrite
              ? sample.ioWrite - oldWrite
              : 0
          ) / 1048576.0)
       << L" threads="
       << sample.threadCount
       << L" priority_class="
       << sample.priorityClass
       << L" priority_boost_disabled="
       << (sample.priorityBoostDisabled ? L"YES" : L"NO");

    if (sample.memoryPriorityValid) {
        ss << L" memory_priority="
           << sample.memoryPriority;
    } else {
        ss << L" memory_priority=UNAVAILABLE";
    }

    if (sample.powerValid) {
        ss << L" power_control_mask="
           << sample.power.ControlMask
           << L" power_state_mask="
           << sample.power.StateMask;
    } else {
        ss << L" power_state=UNAVAILABLE";
    }

    LogLine(ss.str());

    gLastProcessIoRead[pid] = sample.ioRead;
    gLastProcessIoWrite[pid] = sample.ioWrite;
}

static bool ReadSystemCpu(
    double& cpuPercent,
    MEMORYSTATUSEX& memory
) {
    cpuPercent = 0.0;

    ZeroMemory(
        &memory,
        sizeof(memory)
    );

    memory.dwLength = sizeof(memory);

    GlobalMemoryStatusEx(&memory);

    FILETIME idle = {};
    FILETIME kernel = {};
    FILETIME user = {};

    if (!GetSystemTimes(
            &idle,
            &kernel,
            &user)) {

        return false;
    }

    ULONGLONG idleV = FileTimeValue(idle);
    ULONGLONG totalV =
        FileTimeValue(kernel) +
        FileTimeValue(user);

    if (gLastSystemTotal &&
        gLastSystemTotal <= totalV) {

        ULONGLONG totalDelta =
            totalV - gLastSystemTotal;

        ULONGLONG idleDelta =
            idleV >= gLastSystemIdle
            ? idleV - gLastSystemIdle
            : 0;

        if (totalDelta) {
            cpuPercent =
                100.0 *
                (1.0 -
                 static_cast<double>(idleDelta) /
                 static_cast<double>(totalDelta));
        }
    }

    gLastSystemTotal = totalV;
    gLastSystemIdle = idleV;

    return true;
}

static void CollectSystemMemoryAndCPU() {
    double cpu = 0.0;
    MEMORYSTATUSEX mem = {};

    bool ok =
        ReadSystemCpu(cpu, mem);

    std::wstringstream ss;

    ss << L"SYSTEM"
       << L" resource_read=" << (ok ? L"YES" : L"NO")
       << L" cpu_pct=" << std::fixed
       << std::setprecision(2)
       << cpu
       << L" memory_load_pct="
       << mem.dwMemoryLoad
       << L" physical_total_mb="
       << (mem.ullTotalPhys / 1048576ULL)
       << L" physical_available_mb="
       << (mem.ullAvailPhys / 1048576ULL)
       << L" physical_used_mb="
       << ((mem.ullTotalPhys - mem.ullAvailPhys) / 1048576ULL)
       << L" pagefile_total_mb="
       << (mem.ullTotalPageFile / 1048576ULL)
       << L" pagefile_available_mb="
       << (mem.ullAvailPageFile / 1048576ULL);

    LogLine(ss.str());
}

static void LogSystemTopology() {
    SYSTEM_INFO si = {};
    GetSystemInfo(&si);

    DWORD len = 0;

    GetLogicalProcessorInformationEx(
        RelationProcessorCore,
        NULL,
        &len
    );

    std::vector<BYTE> buffer;

    if (len) {
        buffer.resize(len);

        if (GetLogicalProcessorInformationEx(
                RelationProcessorCore,
                reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
                    buffer.data()
                ),
                &len)) {

            BYTE* p = buffer.data();
            BYTE* end = p + len;

            DWORD cores = 0;
            DWORD logical = 0;

            while (p < end) {
                PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX info =
                    reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(p);

                if (info->Relationship == RelationProcessorCore) {
                    ++cores;

                    for (WORD g = 0;
                         g < info->Processor.GroupCount;
                         ++g) {

                        KAFFINITY mask =
                            info->Processor.GroupMask[g].Mask;

                        while (mask) {
                            ++logical;
                            mask &= mask - 1;
                        }
                    }
                }

                p += info->Size;
            }

            std::wstringstream ss;

            ss << L"CPU_TOPOLOGY"
               << L" reported_logical_processors="
               << si.dwNumberOfProcessors
               << L" physical_core_records="
               << cores
               << L" logical_processors_from_core_records="
               << logical
               << L" architecture="
               << si.wProcessorArchitecture
               << L" page_size="
               << si.dwPageSize
               << L" allocation_granularity="
               << si.dwAllocationGranularity;

            LogLine(ss.str());
        }
    }

    DWORD cacheLen = 0;

    GetLogicalProcessorInformationEx(
        RelationCache,
        NULL,
        &cacheLen
    );

    if (cacheLen) {
        buffer.clear();
        buffer.resize(cacheLen);

        if (GetLogicalProcessorInformationEx(
                RelationCache,
                reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(
                    buffer.data()
                ),
                &cacheLen)) {

            BYTE* p = buffer.data();
            BYTE* end = p + cacheLen;

            while (p < end) {
                PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX info =
                    reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(p);

                if (info->Relationship == RelationCache) {
                    std::wstringstream ss;

                    ss << L"CPU_CACHE"
                       << L" level="
                       << static_cast<unsigned>(
                              info->Cache.Level
                          )
                       << L" size_kb="
                       << (info->Cache.CacheSize / 1024)
                       << L" line_bytes="
                       << info->Cache.LineSize
                       << L" associativity="
                       << static_cast<unsigned>(
                              info->Cache.Associativity
                          );

                    LogLine(ss.str());
                }

                p += info->Size;
            }
        }
    }
}

static void LogOSVersion() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    typedef NTSTATUS (WINAPI* RtlGetVersionFn)(
        PRTL_OSVERSIONINFOW
    );

    RtlGetVersionFn fn = nullptr;

    if (ntdll) {
        fn = reinterpret_cast<RtlGetVersionFn>(
            GetProcAddress(ntdll, "RtlGetVersion")
        );
    }

    if (!fn) {
        LogLine(L"OS_VERSION status=UNAVAILABLE");
        return;
    }

    RTL_OSVERSIONINFOW vi = {};
    vi.dwOSVersionInfoSize = sizeof(vi);

    if (fn(&vi) == 0) {
        std::wstringstream ss;

        ss << L"OS_VERSION"
           << L" major="
           << vi.dwMajorVersion
           << L" minor="
           << vi.dwMinorVersion
           << L" build="
           << vi.dwBuildNumber
           << L" platform="
           << vi.dwPlatformId;

        LogLine(ss.str());
    }
}

static void LogPowerSchemeReadOnly() {
    FILE* pipe = _wpopen(
        L"powercfg /getactivescheme 2>&1",
        L"r"
    );

    if (!pipe) {
        LogLine(L"POWER_SCHEME_READ status=UNAVAILABLE");
        return;
    }

    wchar_t buffer[512] = {};

    while (fgetws(
        buffer,
        static_cast<int>(sizeof(buffer) / sizeof(buffer[0])),
        pipe)) {

        std::wstring line = buffer;

        while (!line.empty() &&
               (line.back() == L'\r' ||
                line.back() == L'\n')) {
            line.pop_back();
        }

        if (!line.empty()) {
            LogLine(L"POWER_SCHEME_READ " + line);
        }
    }

    _pclose(pipe);
}

static void LogProcessorPowerSettingsReadOnly() {
    const wchar_t* commands[] = {
        L"powercfg /query SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMIN",
        L"powercfg /query SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX",
        L"powercfg /query SCHEME_CURRENT SUB_PROCESSOR CPMINCORES",
        L"powercfg /query SCHEME_CURRENT SUB_PROCESSOR PERFEPP",
        L"powercfg /query SCHEME_CURRENT SUB_PROCESSOR 5d76a2ca-e8c0-402f-a133-2158492d58ad"
    };

    for (size_t i = 0;
         i < sizeof(commands) / sizeof(commands[0]);
         ++i) {

        FILE* pipe = _wpopen(
            commands[i],
            L"r"
        );

        if (!pipe) {
            LogLine(
                L"POWER_SETTING_READ command_failed"
            );
            continue;
        }

        wchar_t buffer[512] = {};

        while (fgetws(
            buffer,
            static_cast<int>(
                sizeof(buffer) / sizeof(buffer[0])
            ),
            pipe)) {

            std::wstring line = buffer;

            while (!line.empty() &&
                   (line.back() == L'\r' ||
                    line.back() == L'\n')) {
                line.pop_back();
            }

            if (!line.empty()) {
                LogLine(
                    L"POWER_SETTING_READ " +
                    std::wstring(commands[i]) +
                    L" | " +
                    line
                );
            }
        }

        _pclose(pipe);
    }
}

static void LogTimerResolution() {
    HMODULE ntdll =
        GetModuleHandleW(L"ntdll.dll");

    if (!ntdll) {
        LogLine(L"TIMER_RESOLUTION status=UNAVAILABLE");
        return;
    }

    NtQueryTimerResolutionFn fn =
        reinterpret_cast<NtQueryTimerResolutionFn>(
            GetProcAddress(
                ntdll,
                "NtQueryTimerResolution"
            )
        );

    if (!fn) {
        LogLine(L"TIMER_RESOLUTION status=UNAVAILABLE");
        return;
    }

    ULONG minimum = 0;
    ULONG maximum = 0;
    ULONG current = 0;

    NTSTATUS status =
        fn(
            &minimum,
            &maximum,
            &current
        );

    if (status == 0) {
        std::wstringstream ss;

        ss << L"TIMER_RESOLUTION"
           << L" minimum_100ns="
           << minimum
           << L" maximum_100ns="
           << maximum
           << L" current_100ns="
           << current;

        LogLine(ss.str());
    } else {
        LogLine(
            L"TIMER_RESOLUTION query_failed status=" +
            std::to_wstring(
                static_cast<long>(status)
            )
        );
    }
}

static void LogDiskInformation() {
    DWORD drives = GetLogicalDrives();

    if (!drives) {
        LogLine(L"STORAGE status=UNAVAILABLE");
        return;
    }

    for (int i = 0; i < 26; ++i) {
        if (!(drives & (1u << i))) continue;

        wchar_t root[] = {
            static_cast<wchar_t>(L'A' + i),
            L':',
            L'\\',
            L'\0'
        };

        UINT type =
            GetDriveTypeW(root);

        ULARGE_INTEGER freeBytes = {};
        ULARGE_INTEGER totalBytes = {};
        ULARGE_INTEGER totalFree = {};

        bool spaceOk =
            GetDiskFreeSpaceExW(
                root,
                &freeBytes,
                &totalBytes,
                &totalFree
            ) != FALSE;

        std::wstringstream ss;

        ss << L"STORAGE"
           << L" drive="
           << root
           << L" type="
           << type;

        if (spaceOk) {
            ss << L" total_gb="
               << std::fixed
               << std::setprecision(2)
               << (
                   static_cast<double>(
                       totalBytes.QuadPart
                   ) / 1073741824.0
               )
               << L" free_gb="
               << (
                   static_cast<double>(
                       totalFree.QuadPart
                   ) / 1073741824.0
               );
        } else {
            ss << L" space=UNAVAILABLE";
        }

        LogLine(ss.str());
    }
}

static void LogNetworkAdapters() {
    ULONG size = 0;

    DWORD result =
        GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX,
            NULL,
            NULL,
            &size
        );

    if (result != ERROR_BUFFER_OVERFLOW) {
        LogLine(
            L"NETWORK_ADAPTERS status=UNAVAILABLE error=" +
            ErrorText(result)
        );
        return;
    }

    std::vector<BYTE> buffer(size);

    IP_ADAPTER_ADDRESSES* addresses =
        reinterpret_cast<IP_ADAPTER_ADDRESSES*>(
            buffer.data()
        );

    result =
        GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_INCLUDE_PREFIX,
            NULL,
            addresses,
            &size
        );

    if (result != NO_ERROR) {
        LogLine(
            L"NETWORK_ADAPTERS read_failed error=" +
            ErrorText(result)
        );
        return;
    }

    for (IP_ADAPTER_ADDRESSES* a = addresses;
         a;
         a = a->Next) {

        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
            continue;
        }

        std::wstringstream ss;

        ss << L"NETWORK_ADAPTER"
           << L" name="
           << (a->FriendlyName
               ? a->FriendlyName
               : L"UNKNOWN")
           << L" description="
           << (a->Description
               ? a->Description
               : L"UNKNOWN")
           << L" if_index="
           << a->IfIndex
           << L" mtu="
           << a->Mtu
           << L" oper_status="
           << static_cast<unsigned>(
                  a->OperStatus
              )
           << L" receive_link_speed="
           << a->ReceiveLinkSpeed
           << L" transmit_link_speed="
           << a->TransmitLinkSpeed;

        LogLine(ss.str());
    }
}

static void LogProcessList() {
    UniqueSnapshot snapshot(
        CreateToolhelp32Snapshot(
            TH32CS_SNAPPROCESS,
            0
        )
    );

    if (!snapshot.get() ||
        snapshot.get() == INVALID_HANDLE_VALUE) {

        LogLine(
            L"PROCESS_LIST snapshot_failed error=" +
            ErrorText(GetLastError())
        );
        return;
    }

    PROCESSENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    if (!Process32FirstW(
            (HANDLE)snapshot.get(),
            &entry)) {

        LogLine(
            L"PROCESS_LIST first_failed error=" +
            ErrorText(GetLastError())
        );
        return;
    }

    do {
        DWORD pid = entry.th32ProcessID;

        if (!pid) continue;

        std::wstring exe =
            Lower(entry.szExeFile);

        bool game =
            IsGameFile(exe);

        bool background =
            IsBackgroundTarget(exe);

        bool antiCheat =
            IsAntiCheatProcess(exe);

        bool protectedProcess =
            IsProtectedProcess(exe);

        if (!game &&
            !background &&
            !antiCheat &&
            !protectedProcess) {
            continue;
        }

        std::wstring role =
            game
            ? L"GAME"
            : background
              ? L"BACKGROUND"
              : antiCheat
                ? L"ANTICHEAT"
                : L"PROTECTED";

        LogProcessSample(
            pid,
            role
        );

    } while (Process32NextW(
        (HANDLE)snapshot.get(),
        &entry
    ));
}

static void LogModulesForGame(DWORD pid) {
    if (!pid) return;

    UniqueHandle process(
        OpenProcess(
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_READ,
            FALSE,
            pid
        )
    );

    if (!process) {
        LogLine(
            L"GAME_MODULES status=UNAVAILABLE pid=" +
            std::to_wstring(pid)
        );
        return;
    }

    HMODULE modules[1024] = {};
    DWORD needed = 0;

    if (!EnumProcessModules(
            (HANDLE)process.get(),
            modules,
            sizeof(modules),
            &needed)) {

        LogLine(
            L"GAME_MODULES enum_failed pid=" +
            std::to_wstring(pid)
        );
        return;
    }

    DWORD count =
        needed / sizeof(HMODULE);

    for (DWORD i = 0;
         i < count && i < 1024;
         ++i) {

        wchar_t name[MAX_PATH * 4] = {};

        if (GetModuleFileNameExW(
                (HANDLE)process.get(),
                modules[i],
                name,
                static_cast<DWORD>(
                    sizeof(name) / sizeof(name[0])
                ))) {

            std::wstringstream ss;

            ss << L"GAME_MODULE"
               << L" pid=" << pid
               << L" module=" << name;

            LogLine(ss.str());
        }
    }
}

static GameInfo FindGameByPid(DWORD pid) {
    GameInfo result;

    if (!pid) return result;

    result.pid = pid;
    result.exe = ProcessName(pid);

    if (result.exe.empty() ||
        !IsGameFile(result.exe)) {

        result.pid = 0;
        result.exe.clear();
        return result;
    }

    result.name = result.exe;

    if (EqualsIgnoreCase(
            result.exe,
            L"tslgame.exe")) {

        result.name = L"PUBG";

    } else if (EqualsIgnoreCase(
                   result.exe,
                   L"league of legends.exe")) {

        result.name = L"League of Legends";

    } else if (EqualsIgnoreCase(
                   result.exe,
                   L"cs2.exe")) {

        result.name = L"Counter-Strike 2";

    } else if (EqualsIgnoreCase(
                   result.exe,
                   L"valorant-win64-shipping.exe")) {

        result.name = L"VALORANT";
    }

    return result;
}

static void LoadReadOnlyProcessApis() {
    HMODULE kernel =
        GetModuleHandleW(L"kernel32.dll");

    if (!kernel) return;

    gSetProcessInformation =
        reinterpret_cast<SetProcessInformationFn>(
            GetProcAddress(
                kernel,
                "SetProcessInformation"
            )
        );

    gGetProcessInformation =
        reinterpret_cast<GetProcessInformationFn>(
            GetProcAddress(
                kernel,
                "GetProcessInformation"
            )
        );

    /*
        IMPORTANT:
        gSetProcessInformation is intentionally NEVER called.
        It is retained only so the collector can report API
        availability for future implementation work.
    */
}

static void LogProcessApiAvailability() {
    LogLine(
        L"API_AVAILABILITY SetProcessInformation=" +
        std::wstring(
            gSetProcessInformation
            ? L"AVAILABLE"
            : L"MISSING"
        )
    );

    LogLine(
        L"API_AVAILABILITY GetProcessInformation=" +
        std::wstring(
            gGetProcessInformation
            ? L"AVAILABLE"
            : L"MISSING"
        )
    );
}

static void LogGameGraphicsHints(DWORD pid) {
    if (!pid) return;

    std::wstring path =
        ProcessPath(pid);

    if (path.empty()) {
        LogLine(
            L"GAME_GRAPHICS_HINTS path=UNAVAILABLE"
        );
        return;
    }

    std::wstring lowerPath =
        Lower(path);

    std::wstring api = L"UNKNOWN";

    /*
        This is deliberately only a hint from loaded modules/path.
        It does NOT alter the process.
    */

    UniqueHandle process(
        OpenProcess(
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_READ,
            FALSE,
            pid
        )
    );

    if (process) {
        HMODULE modules[1024] = {};
        DWORD needed = 0;

        if (EnumProcessModules(
                (HANDLE)process.get(),
                modules,
                sizeof(modules),
                &needed)) {

            DWORD count =
                needed / sizeof(HMODULE);

            bool dx12 = false;
            bool dx11 = false;
            bool vulkan = false;

            for (DWORD i = 0;
                 i < count && i < 1024;
                 ++i) {

                wchar_t moduleName[MAX_PATH] = {};

                if (!GetModuleBaseNameW(
                        (HANDLE)process.get(),
                        modules[i],
                        moduleName,
                        MAX_PATH)) {
                    continue;
                }

                std::wstring m =
                    Lower(moduleName);

                if (m == L"d3d12.dll" ||
                    m == L"d3d12core.dll") {
                    dx12 = true;
                }

                if (m == L"d3d11.dll") {
                    dx11 = true;
                }

                if (m == L"vulkan-1.dll") {
                    vulkan = true;
                }
            }

            if (dx12) api = L"DX12";
            else if (vulkan) api = L"VULKAN";
            else if (dx11) api = L"DX11";
        }
    }

    LogLine(
        L"GAME_GRAPHICS_HINTS pid=" +
        std::to_wstring(pid) +
        L" api=" +
        api +
        L" path=" +
        path
    );
}

static void LogForegroundWindowInfo(DWORD pid) {
    HWND hwnd = GetForegroundWindow();

    if (!hwnd) {
        LogLine(L"FOREGROUND_WINDOW status=NONE");
        return;
    }

    DWORD windowPid = 0;

    GetWindowThreadProcessId(
        hwnd,
        &windowPid
    );

    wchar_t title[512] = {};

    GetWindowTextW(
        hwnd,
        title,
        static_cast<int>(
            sizeof(title) / sizeof(title[0])
        )
    );

    RECT rect = {};
    GetWindowRect(
        hwnd,
        &rect
    );

    std::wstringstream ss;

    ss << L"FOREGROUND_WINDOW"
       << L" pid=" << pid
       << L" actual_window_pid="
       << windowPid
       << L" title=" << title
       << L" x=" << rect.left
       << L" y=" << rect.top
       << L" width="
       << (rect.right - rect.left)
       << L" height="
       << (rect.bottom - rect.top);

    LogLine(ss.str());
}

static void LogGameState() {
    DWORD pid =
        gForegroundPid.load();

    GameInfo game =
        FindGameByPid(pid);

    if (game.pid) {
        gCurrentGame = game;
        gCurrentPid = game.pid;

        LogLine(
            L"GAME_STATE detected=YES" +
            std::wstring(L" pid=") +
            std::to_wstring(game.pid) +
            L" exe=" +
            game.exe +
            L" name=" +
            game.name
        );

        LogForegroundWindowInfo(
            game.pid
        );

        LogGameGraphicsHints(
            game.pid
        );

        LogModulesForGame(
            game.pid
        );

    } else {
        if (gCurrentPid) {
            UniqueHandle current(
                OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION,
                    FALSE,
                    gCurrentPid
                )
            );

            if (!current) {
                LogLine(
                    L"GAME_STATE previous_game_exited pid=" +
                    std::to_wstring(gCurrentPid)
                );

                gCurrentGame = GameInfo();
                gCurrentPid = 0;
            }
        }

        if (!gCurrentPid) {
            LogLine(L"GAME_STATE detected=NO");
        }
    }
}

static void LogSpikeCandidates(
    double systemCpu,
    const MEMORYSTATUSEX& mem
) {
    if (!gCurrentPid) return;

    ProcessSample sample;

    if (!ReadProcessSample(
            gCurrentPid,
            sample)) {
        return;
    }

    bool cpuPressure =
        sample.cpuPercent >= 150.0;

    bool memoryPressure =
        mem.dwMemoryLoad >= 90;

    bool ioPressure =
        false;

    ULONGLONG oldRead =
        gLastProcessIoRead[gCurrentPid];

    ULONGLONG oldWrite =
        gLastProcessIoWrite[gCurrentPid];

    ULONGLONG readDelta =
        sample.ioRead >= oldRead
        ? sample.ioRead - oldRead
        : 0;

    ULONGLONG writeDelta =
        sample.ioWrite >= oldWrite
        ? sample.ioWrite - oldWrite
        : 0;

    if (readDelta > 256ULL * 1024ULL * 1024ULL ||
        writeDelta > 256ULL * 1024ULL * 1024ULL) {
        ioPressure = true;
    }

    if (cpuPressure ||
        memoryPressure ||
        ioPressure ||
        systemCpu >= 85.0) {

        std::wstring reason;

        if (cpuPressure)
            reason += L"GAME_CPU ";

        if (memoryPressure)
            reason += L"MEMORY_PRESSURE ";

        if (ioPressure)
            reason += L"GAME_IO ";

        if (systemCpu >= 85.0)
            reason += L"SYSTEM_CPU ";

        LogLine(
            L"DIAGNOSTIC_SPIKE_CANDIDATE" +
            std::wstring(L" game_pid=") +
            std::to_wstring(gCurrentPid) +
            L" game_cpu=" +
            std::to_wstring(sample.cpuPercent) +
            L" system_cpu=" +
            std::to_wstring(systemCpu) +
            L" memory_load=" +
            std::to_wstring(mem.dwMemoryLoad) +
            L" reason=" +
            reason
        );
    }
}

static void CollectRuntimeSample() {
    CollectSystemMemoryAndCPU();

    double systemCpu = 0.0;
    MEMORYSTATUSEX mem = {};

    ReadSystemCpu(
        systemCpu,
        mem
    );

    LogGameState();
    LogProcessList();
    LogSpikeCandidates(
        systemCpu,
        mem
    );

    LogTimerResolution();
    LogPowerSchemeReadOnly();
    LogProcessorPowerSettingsReadOnly();
    LogNetworkAdapters();
    LogDiskInformation();

    gLastSampleTick =
        GetTickCount64();
}

static void CollectStaticInformation() {
    LogOSVersion();
    LogSystemTopology();
    LogProcessApiAvailability();
    LogTimerResolution();
    LogPowerSchemeReadOnly();
    LogProcessorPowerSettingsReadOnly();
    LogNetworkAdapters();
    LogDiskInformation();

    MEMORYSTATUSEX mem = {};
    mem.dwLength = sizeof(mem);

    if (GlobalMemoryStatusEx(&mem)) {
        std::wstringstream ss;

        ss << L"MEMORY_BASELINE"
           << L" total_physical_mb="
           << (mem.ullTotalPhys / 1048576ULL)
           << L" available_physical_mb="
           << (mem.ullAvailPhys / 1048576ULL)
           << L" total_pagefile_mb="
           << (mem.ullTotalPageFile / 1048576ULL)
           << L" available_pagefile_mb="
           << (mem.ullAvailPageFile / 1048576ULL);

        LogLine(ss.str());
    }
}

static void PrintStatus(
    const std::wstring& file,
    const wchar_t* applied
) {
    static std::mutex statusMutex;
    static bool initialized = false;
    static std::wstring lastFile;
    static std::wstring lastApplied;

    std::wstring currentFile =
        file.empty()
        ? L"NONE"
        : file;

    std::wstring currentApplied =
        applied
        ? applied
        : L"NO";

    std::lock_guard<std::mutex> lock(
        statusMutex
    );

    if (initialized &&
        currentFile == lastFile &&
        currentApplied == lastApplied) {
        return;
    }

    HANDLE console =
        CreateFileW(
            L"CONOUT$",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

    if (console == INVALID_HANDLE_VALUE)
        return;

    CONSOLE_SCREEN_BUFFER_INFO csbi = {};

    if (!GetConsoleScreenBufferInfo(
            console,
            &csbi)) {

        CloseHandle(console);
        return;
    }

    CONSOLE_CURSOR_INFO cursorInfo = {
        1,
        FALSE
    };

    SetConsoleCursorInfo(
        console,
        &cursorInfo
    );

    const SHORT width =
        csbi.dwSize.X > 0
        ? csbi.dwSize.X
        : 80;

    SHORT top =
        csbi.srWindow.Top;

    if (top < 0) top = 0;

    if (top + 3 >= csbi.dwSize.Y) {
        top =
            static_cast<SHORT>(
                csbi.dwSize.Y > 4
                ? csbi.dwSize.Y - 4
                : 0
            );
    }

    std::wstring lines[4];

    lines[0] =
        L"Optimizer: RUNNING";

    lines[1] =
        L"Detected file: " +
        currentFile;

    lines[2] =
        L"Applied: " +
        currentApplied;

    lines[3] =
        L"Mode: INFORMATION COLLECTOR ONLY";

    for (SHORT row = 0;
         row < 4;
         ++row) {

        std::wstring line =
            lines[row];

        if (static_cast<SHORT>(
                line.size()
            ) > width) {

            line.resize(
                static_cast<size_t>(
                    width
                )
            );
        }

        line.resize(
            static_cast<size_t>(width),
            L' '
        );

        COORD pos = {
            0,
            static_cast<SHORT>(
                top + row
            )
        };

        if (!SetConsoleCursorPosition(
                console,
                pos)) {
            continue;
        }

        DWORD written = 0;

        WriteConsoleW(
            console,
            line.c_str(),
            static_cast<DWORD>(
                line.size()
            ),
            &written,
            NULL
        );
    }

    SetConsoleCursorPosition(
        console,
        COORD{
            0,
            static_cast<SHORT>(
                top + 4 < csbi.dwSize.Y
                ? top + 4
                : top + 3
            )
        }
    );

    CloseHandle(console);

    lastFile = currentFile;
    lastApplied = currentApplied;
    initialized = true;
}

static VOID CALLBACK GameExitCallback(
    PVOID context,
    BOOLEAN
) {
    DWORD pid =
        static_cast<DWORD>(
            reinterpret_cast<ULONG_PTR>(
                context
            )
        );

    if (gStop.load())
        return;

    if (pid == gCurrentPid &&
        gEventWindow) {

        PostMessageW(
            gEventWindow,
            WM_APP + 2,
            static_cast<WPARAM>(pid),
            0
        );
    }
}

static HANDLE gWatchedProcess = NULL;
static HANDLE gGameWaitRegistration = NULL;

static void UnregisterGameExitWatch() {
    if (gGameWaitRegistration) {
        UnregisterWaitEx(
            gGameWaitRegistration,
            INVALID_HANDLE_VALUE
        );

        gGameWaitRegistration = NULL;
    }

    if (gWatchedProcess) {
        CloseHandle(
            gWatchedProcess
        );

        gWatchedProcess = NULL;
    }
}

static bool RegisterGameExitWatch(
    DWORD pid
) {
    UnregisterGameExitWatch();

    HANDLE process =
        OpenProcess(
            SYNCHRONIZE,
            FALSE,
            pid
        );

    if (!process)
        return false;

    HANDLE registration = NULL;

    if (!RegisterWaitForSingleObject(
            &registration,
            process,
            GameExitCallback,
            reinterpret_cast<PVOID>(
                static_cast<ULONG_PTR>(pid)
            ),
            INFINITE,
            WT_EXECUTEONLYONCE)) {

        CloseHandle(process);
        return false;
    }

    gWatchedProcess = process;
    gGameWaitRegistration =
        registration;

    return true;
}

static void ProcessForegroundChange(
    DWORD pid
) {
    GameInfo game =
        FindGameByPid(pid);

    if (!game.pid) {
        if (!gCurrentPid) {
            PrintStatus(
                L"",
                L"NOT APPLIED - COLLECTOR ONLY"
            );
        }

        return;
    }

    gCurrentGame = game;
    gCurrentPid = game.pid;

    RegisterGameExitWatch(
        game.pid
    );

    /*
        CRITICAL:
        No process priority change.
        No memory priority change.
        No power-throttling change.
        No affinity change.
        No CPU-set change.
        No registry change.
        No service change.
        No network change.
        No power-plan change.
        No system modification.
    */

    PrintStatus(
        game.exe,
        L"NOT APPLIED - COLLECTOR ONLY"
    );

    LogLine(
        L"GAME_DETECTED_FOR_COLLECTION pid=" +
        std::to_wstring(game.pid) +
        L" exe=" +
        game.exe
    );
}

static LRESULT CALLBACK EventWindowProc(
    HWND hwnd,
    UINT msg,
    WPARAM wParam,
    LPARAM lParam
) {
    (void)hwnd;
    (void)lParam;

    if (msg == WM_TIMER) {
        if (wParam == 1) {
            CollectRuntimeSample();
        }

        return 0;
    }

    if (msg == WM_APP + 1) {
        DWORD pid =
            gForegroundPid.load();

        LogLine(
            L"FOREGROUND_EVENT pid=" +
            std::to_wstring(pid)
        );

        ProcessForegroundChange(
            pid
        );

        return 0;
    }

    if (msg == WM_APP + 2) {
        DWORD exitedPid =
            static_cast<DWORD>(
                wParam
            );

        LogLine(
            L"GAME_EXIT_EVENT pid=" +
            std::to_wstring(exitedPid)
        );

        if (exitedPid == gCurrentPid) {
            gCurrentGame =
                GameInfo();

            gCurrentPid = 0;

            UnregisterGameExitWatch();

            DWORD pid =
                gForegroundPid.load();

            GameInfo stillForeground =
                FindGameByPid(pid);

            if (stillForeground.pid) {
                ProcessForegroundChange(
                    pid
                );
            } else {
                PrintStatus(
                    L"",
                    L"NOT APPLIED - COLLECTOR ONLY"
                );
            }
        }

        return 0;
    }

    if (msg == WM_CLOSE ||
        msg == WM_DESTROY) {

        gStop.store(true);

        if (gWakeEvent)
            SetEvent(gWakeEvent);

        PostQuitMessage(0);

        return 0;
    }

    return DefWindowProcW(
        hwnd,
        msg,
        wParam,
        lParam
    );
}

static void CALLBACK WinEventProc(
    HWINEVENTHOOK,
    DWORD event,
    HWND hwnd,
    LONG,
    LONG,
    DWORD,
    DWORD
) {
    if (event != EVENT_SYSTEM_FOREGROUND ||
        !hwnd ||
        !gEventWindow) {
        return;
    }

    DWORD pid = 0;

    GetWindowThreadProcessId(
        hwnd,
        &pid
    );

    gForegroundPid.store(pid);

    PostMessageW(
        gEventWindow,
        WM_APP + 1,
        0,
        0
    );
}

static bool InstallEventHook(
    UniqueWinEventHook& hook
) {
    hook.reset(
        SetWinEventHook(
            EVENT_SYSTEM_FOREGROUND,
            EVENT_SYSTEM_FOREGROUND,
            NULL,
            WinEventProc,
            0,
            0,
            WINEVENT_OUTOFCONTEXT |
            WINEVENT_SKIPOWNPROCESS
        )
    );

    return hook.get() != nullptr;
}

static bool CreateEventWindow() {
    const wchar_t* className =
        L"GameOptimizerCollectorEventWindow";

    WNDCLASSW wc = {};

    wc.lpfnWndProc =
        EventWindowProc;

    wc.hInstance =
        GetModuleHandleW(NULL);

    wc.lpszClassName =
        className;

    if (!RegisterClassW(&wc) &&
        GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {

        return false;
    }

    gEventWindow =
        CreateWindowExW(
            0,
            className,
            L"GameOptimizerCollectorEventWindow",
            0,
            0,
            0,
            0,
            0,
            HWND_MESSAGE,
            NULL,
            GetModuleHandleW(NULL),
            NULL
        );

    return gEventWindow != nullptr;
}

static BOOL WINAPI ConsoleHandler(
    DWORD signal
) {
    if (signal == CTRL_CLOSE_EVENT ||
        signal == CTRL_LOGOFF_EVENT ||
        signal == CTRL_SHUTDOWN_EVENT) {

        gStop.store(true);

        if (gEventWindow) {
            PostMessageW(
                gEventWindow,
                WM_CLOSE,
                0,
                0
            );
        }

        return TRUE;
    }

    return FALSE;
}

static bool InitializeConsole() {
    if (GetConsoleWindow() == NULL) {
        if (!AttachConsole(
                ATTACH_PARENT_PROCESS)) {

            DWORD err =
                GetLastError();

            if (err != ERROR_ACCESS_DENIED) {
                if (!AllocConsole())
                    return false;
            }
        }
    }

    FILE* fp = nullptr;

    freopen_s(
        &fp,
        "CONOUT$",
        "w",
        stdout
    );

    freopen_s(
        &fp,
        "CONOUT$",
        "w",
        stderr
    );

    freopen_s(
        &fp,
        "CONIN$",
        "r",
        stdin
    );

    std::ios::sync_with_stdio(
        false
    );

    SetConsoleCtrlHandler(
        ConsoleHandler,
        TRUE
    );

    return GetConsoleWindow() != NULL;
}

static int RunCollector() {
    if (!InitializeConsole())
        return 1;

    PrintStatus(
        L"",
        L"NOT APPLIED - COLLECTOR ONLY"
    );

    LoadReadOnlyProcessApis();
    OpenLog();

    LogLine(
        L"Collector startup"
    );

    LogLine(
        L"SamplingIntervalMs=250"
    );

    LogLine(
        L"Scope=hardware_topology+os+memory+cpu+process+game+graphics_api_hint+modules+power_read_only+timer+storage+network+diagnostic_spikes"
    );

    LogLine(
        L"MODIFICATION_POLICY=READ_ONLY"
    );

    CollectStaticInformation();

    gWakeEvent =
        CreateEventW(
            NULL,
            TRUE,
            FALSE,
            NULL
        );

    if (!gWakeEvent) {
        LogLine(
            L"STARTUP_FAIL CreateEvent error=" +
            ErrorText(GetLastError())
        );

        return 1;
    }

    if (!CreateEventWindow()) {
        LogLine(
            L"STARTUP_FAIL CreateEventWindow error=" +
            ErrorText(GetLastError())
        );

        CloseHandle(
            gWakeEvent
        );

        gWakeEvent = NULL;

        return 1;
    }

    gLogTimer =
        SetTimer(
            gEventWindow,
            1,
            250,
            NULL
        );

    if (!gLogTimer) {
        LogLine(
            L"STARTUP_FAIL SetTimer error=" +
            ErrorText(GetLastError())
        );

        DestroyWindow(
            gEventWindow
        );

        gEventWindow = nullptr;

        CloseHandle(
            gWakeEvent
        );

        gWakeEvent = NULL;

        return 1;
    }

    UniqueWinEventHook hook;

    if (!InstallEventHook(hook)) {
        LogLine(
            L"STARTUP_FAIL SetWinEventHook error=" +
            ErrorText(GetLastError())
        );

        KillTimer(
            gEventWindow,
            gLogTimer
        );

        DestroyWindow(
            gEventWindow
        );

        gEventWindow = nullptr;

        CloseHandle(
            gWakeEvent
        );

        gWakeEvent = NULL;

        return 1;
    }

    LogLine(
        L"Foreground event hook installed"
    );

    HWND foreground =
        GetForegroundWindow();

    DWORD pid = 0;

    if (foreground) {
        GetWindowThreadProcessId(
            foreground,
            &pid
        );
    }

    gForegroundPid.store(pid);

    PostMessageW(
        gEventWindow,
        WM_APP + 1,
        0,
        0
    );

    MSG msg;

    while (!gStop.load()) {
        BOOL r =
            GetMessageW(
                &msg,
                NULL,
                0,
                0
            );

        if (r <= 0)
            break;

        TranslateMessage(
            &msg
        );

        DispatchMessageW(
            &msg
        );
    }

    gStop.store(true);

    UnregisterGameExitWatch();

    if (gEventWindow &&
        gLogTimer) {

        KillTimer(
            gEventWindow,
            gLogTimer
        );

        gLogTimer = 0;
    }

    if (gEventWindow) {
        DestroyWindow(
            gEventWindow
        );

        gEventWindow = nullptr;
    }

    if (gWakeEvent) {
        CloseHandle(
            gWakeEvent
        );

        gWakeEvent = NULL;
    }

    LogLine(
        L"MODIFICATION_POLICY_FINAL=READ_ONLY"
    );

    LogLine(
        L"GAME OPTIMIZER INFORMATION COLLECTOR SESSION END"
    );

    LogLine(
        L"============================================================"
    );

    {
        std::lock_guard<std::mutex> lock(
            gLogMutex
        );

        if (gLog.is_open())
            gLog.close();
    }

    return 0;
}

#ifdef _WIN32
int WINAPI WinMain(
    HINSTANCE,
    HINSTANCE,
    LPSTR,
    int
) {
    return RunCollector();
}
#endif

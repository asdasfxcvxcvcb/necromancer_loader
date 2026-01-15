/*
 * Necromancer Loader v2.1
 * Uses GH Injector Library for reliable manual map injection
 * Single EXE with embedded DLL
 * 
 * Flow:
 * 1. User double-clicks exe
 * 2. Auto-elevates to admin
 * 3. Extracts embedded GH Injector DLL to C:\necromancer_tf2
 * 4. Downloads cheat DLL from nightly build
 * 5. Waits for TF2
 * 6. Uses GH Injector Library for manual map injection
 * 7. Closes after 5 seconds
 */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <winternl.h>
#include <wininet.h>
#include <TlHelp32.h>
#include <intrin.h>
#include <iostream>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <thread>
#include <chrono>
#include <Psapi.h>
#include <shellapi.h>

// GH Injector Library header
#include "Injection.h"
#include "resource.h"

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "Psapi.lib")

// Necromancer directory for all files
const wchar_t* NECROMANCER_DIR = L"C:\\necromancer_tf2\\loader";
const wchar_t* GH_INJECTOR_DLL_NAME = L"GH Injector - x64.dll";

// Console colors
namespace Color {
    void Set(int color) { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), color); }
    void Red() { Set(FOREGROUND_RED | FOREGROUND_INTENSITY); }
    void Green() { Set(FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
    void Yellow() { Set(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
    void Cyan() { Set(FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); }
    void White() { Set(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); }
    void Gray() { Set(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); }
    void Magenta() { Set(FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY); }
    void DarkGray() { Set(FOREGROUND_INTENSITY); }
}

// Print status with icon
void PrintStatus(const char* icon, const char* msg, void(*color)() = Color::White) {
    Color::DarkGray();
    std::cout << "  " << icon << " ";
    color();
    std::cout << msg << "\n";
    Color::White();
}

void PrintOK(const char* msg) { PrintStatus("\xFB", msg, Color::Green); }      // checkmark
void PrintInfo(const char* msg) { PrintStatus("\xF9", msg, Color::Cyan); }     // bullet
void PrintWarn(const char* msg) { PrintStatus("!", msg, Color::Yellow); }
void PrintErr(const char* msg) { PrintStatus("X", msg, Color::Red); }

void PrintProgress(int percent) {
    Color::DarkGray();
    std::cout << "\r  [";
    Color::Cyan();
    int filled = percent / 5;
    for (int i = 0; i < 20; i++) {
        if (i < filled) std::cout << "\xDB";
        else std::cout << "\xB0";
    }
    Color::DarkGray();
    std::cout << "] ";
    Color::White();
    std::cout << percent << "%  " << std::flush;
}

// Check if running as administrator
bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

// URLs
const char* URL_RELEASE = "https://nightly.link/asdasfxcvxcvcb/necromancer/workflows/nightly/main/necromancer-Release-x64.zip";
const char* URL_AVX2 = "https://nightly.link/asdasfxcvxcvcb/necromancer/workflows/nightly/main/necromancer-ReleaseAVX2-x64.zip";
const wchar_t* PROCESS_NAME = L"tf_win64.exe";

// GH Injector function types
using f_InjectW = DWORD(__stdcall*)(INJECTIONDATAW* pData);
using f_GetSymbolState = DWORD(__stdcall*)();
using f_GetImportState = DWORD(__stdcall*)();
using f_StartDownload = void(__stdcall*)();
using f_GetDownloadProgressEx = float(__stdcall*)(int index, bool bWow64);

// Global GH Injector handles
HINSTANCE g_hInjectorDll = nullptr;
f_InjectW g_pInjectW = nullptr;
f_GetSymbolState g_pGetSymbolState = nullptr;
f_GetImportState g_pGetImportState = nullptr;
f_StartDownload g_pStartDownload = nullptr;
f_GetDownloadProgressEx g_pGetDownloadProgressEx = nullptr;

// Function prototypes
bool CheckAVX2Support();
DWORD GetProcessId(const wchar_t* processName);
bool IsProcessRunning(const wchar_t* processName);
int GetProcessUptime(DWORD pid);
std::vector<BYTE> DownloadFile(const char* url);
std::vector<BYTE> ExtractDllFromZip(const std::vector<BYTE>& zipData);
bool SaveDllToTemp(const std::vector<BYTE>& dllData, std::wstring& outPath);
bool ExtractEmbeddedDll(std::wstring& outPath);
bool LoadGHInjector();
void UnloadGHInjector();
bool WaitForGHInjectorReady();
bool InjectWithGHInjector(DWORD pid, const std::wstring& dllPath);
void PrintBanner();
void WaitForProcess(const wchar_t* processName, const char* displayName);

// Extract embedded GH Injector DLL from resources
bool ExtractEmbeddedDll(std::wstring& outPath) {
    std::error_code ec;
    std::filesystem::create_directories(NECROMANCER_DIR, ec);
    
    std::wstring x64Dir = std::wstring(NECROMANCER_DIR) + L"\\x64";
    std::wstring x86Dir = std::wstring(NECROMANCER_DIR) + L"\\x86";
    std::filesystem::create_directories(x64Dir, ec);
    std::filesystem::create_directories(x86Dir, ec);
    
    outPath = std::wstring(NECROMANCER_DIR) + L"\\" + GH_INJECTOR_DLL_NAME;
    
    if (std::filesystem::exists(outPath)) {
        HMODULE hTest = LoadLibraryExW(outPath.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (hTest) {
            FreeLibrary(hTest);
            return true;
        }
        std::filesystem::remove(outPath, ec);
    }
    
    HRSRC hRes = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_GH_INJECTOR_DLL), RT_RCDATA);
    if (!hRes) return false;
    
    HGLOBAL hResData = LoadResource(nullptr, hRes);
    if (!hResData) return false;
    
    void* pData = LockResource(hResData);
    DWORD dataSize = SizeofResource(nullptr, hRes);
    if (!pData || dataSize == 0) return false;
    
    std::ofstream file(outPath, std::ios::binary);
    if (!file) return false;
    
    file.write(static_cast<const char*>(pData), dataSize);
    file.close();
    
    return true;
}

// Check if CPU supports AVX2
bool CheckAVX2Support() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);
    int nIds = cpuInfo[0];

    if (nIds >= 7) {
        __cpuidex(cpuInfo, 7, 0);
        return (cpuInfo[1] & (1 << 5)) != 0;
    }
    return false;
}

// Get process ID by name
DWORD GetProcessId(const wchar_t* processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(pe32);
        if (Process32FirstW(snapshot, &pe32)) {
            do {
                if (_wcsicmp(pe32.szExeFile, processName) == 0) {
                    pid = pe32.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &pe32));
        }
        CloseHandle(snapshot);
    }
    return pid;
}

// Check if process is running
bool IsProcessRunning(const wchar_t* processName) {
    return GetProcessId(processName) != 0;
}

// Get process uptime in seconds
int GetProcessUptime(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return -1;

    FILETIME createTime, exitTime, kernelTime, userTime;
    if (!GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
        CloseHandle(hProcess);
        return -1;
    }
    CloseHandle(hProcess);

    FILETIME nowTime;
    GetSystemTimeAsFileTime(&nowTime);

    ULARGE_INTEGER create, now;
    create.LowPart = createTime.dwLowDateTime;
    create.HighPart = createTime.dwHighDateTime;
    now.LowPart = nowTime.dwLowDateTime;
    now.HighPart = nowTime.dwHighDateTime;

    return static_cast<int>((now.QuadPart - create.QuadPart) / 10000000ULL);
}

// Download file from URL
std::vector<BYTE> DownloadFile(const char* url) {
    std::vector<BYTE> data;

    HINTERNET hInternet = InternetOpenA("NecromancerLoader/2.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hInternet) return data;

    HINTERNET hUrl = InternetOpenUrlA(hInternet, url, nullptr, 0, 
        INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 0);
    
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return data;
    }

    BYTE buffer[8192];
    DWORD bytesRead = 0;
    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        data.insert(data.end(), buffer, buffer + bytesRead);
    }

    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    return data;
}

// Extract DLL from ZIP archive
std::vector<BYTE> ExtractDllFromZip(const std::vector<BYTE>& zipData) {
    std::vector<BYTE> dllData;
    
    if (zipData.size() < 30) return dllData;

    // Use PowerShell for reliable extraction
    std::filesystem::path tempDir = std::filesystem::temp_directory_path();
    std::filesystem::path zipPath = tempDir / "necromancer_temp.zip";
    std::filesystem::path extractDir = tempDir / "necromancer_extract";
    
    // Clean up any previous extraction
    std::error_code ec;
    std::filesystem::remove(zipPath, ec);
    std::filesystem::remove_all(extractDir, ec);
    
    // Write zip to temp file
    std::ofstream zipFile(zipPath, std::ios::binary);
    if (!zipFile) return dllData;
    zipFile.write(reinterpret_cast<const char*>(zipData.data()), zipData.size());
    zipFile.close();
    
    // Create extract directory
    std::filesystem::create_directories(extractDir);
    
    // Use PowerShell to extract
    std::wstring cmd = L"powershell -NoProfile -Command \"Expand-Archive -Path '";
    cmd += zipPath.wstring();
    cmd += L"' -DestinationPath '";
    cmd += extractDir.wstring();
    cmd += L"' -Force\"";
    
    STARTUPINFOW si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi;
    
    if (CreateProcessW(nullptr, const_cast<LPWSTR>(cmd.c_str()), nullptr, nullptr, FALSE, 
        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 30000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    
    // Find the DLL in extracted files
    for (const auto& entry : std::filesystem::recursive_directory_iterator(extractDir)) {
        if (entry.is_regular_file() && entry.path().extension() == L".dll") {
            std::ifstream dllFile(entry.path(), std::ios::binary | std::ios::ate);
            if (dllFile) {
                size_t size = dllFile.tellg();
                dllFile.seekg(0);
                dllData.resize(size);
                dllFile.read(reinterpret_cast<char*>(dllData.data()), size);
                dllFile.close();
            }
            break;
        }
    }
    
    // Cleanup
    std::filesystem::remove(zipPath, ec);
    std::filesystem::remove_all(extractDir, ec);
    
    return dllData;
}

// Save DLL to necromancer directory
bool SaveDllToTemp(const std::vector<BYTE>& dllData, std::wstring& outPath) {
    std::wstring dllPath = std::wstring(NECROMANCER_DIR) + L"\\necromancer.dll";
    
    std::ofstream file(dllPath, std::ios::binary);
    if (!file) return false;
    
    file.write(reinterpret_cast<const char*>(dllData.data()), dllData.size());
    file.close();
    
    outPath = dllPath;
    return true;
}

// Global path to extracted DLL
std::wstring g_extractedDllPath;

// Load GH Injector Library
bool LoadGHInjector() {
    if (!ExtractEmbeddedDll(g_extractedDllPath)) {
        PrintErr("Failed to extract injector DLL");
        return false;
    }
    
    SetCurrentDirectoryW(NECROMANCER_DIR);
    
    g_hInjectorDll = LoadLibraryW(g_extractedDllPath.c_str());
    if (!g_hInjectorDll) {
        PrintErr("Failed to load injector DLL");
        return false;
    }
    
    g_pInjectW = reinterpret_cast<f_InjectW>(GetProcAddress(g_hInjectorDll, "InjectW"));
    g_pGetSymbolState = reinterpret_cast<f_GetSymbolState>(GetProcAddress(g_hInjectorDll, "GetSymbolState"));
    g_pGetImportState = reinterpret_cast<f_GetImportState>(GetProcAddress(g_hInjectorDll, "GetImportState"));
    g_pStartDownload = reinterpret_cast<f_StartDownload>(GetProcAddress(g_hInjectorDll, "StartDownload"));
    g_pGetDownloadProgressEx = reinterpret_cast<f_GetDownloadProgressEx>(GetProcAddress(g_hInjectorDll, "GetDownloadProgressEx"));
    
    if (!g_pInjectW) {
        PrintErr("Failed to get inject function");
        FreeLibrary(g_hInjectorDll);
        g_hInjectorDll = nullptr;
        return false;
    }
    
    PrintOK("Injection engine ready");
    return true;
}

// Unload GH Injector Library
void UnloadGHInjector() {
    if (g_hInjectorDll) {
        FreeLibrary(g_hInjectorDll);
        g_hInjectorDll = nullptr;
    }
}

// Wait for GH Injector to be ready (symbols downloaded)
bool WaitForGHInjectorReady() {
    if (!g_pGetSymbolState || !g_pGetImportState) {
        return true;
    }
    
    PrintInfo("Initializing (first run may take a minute)...");
    
    if (g_pStartDownload) {
        g_pStartDownload();
    }
    
    int timeout = 300;
    int elapsed = 0;
    int lastProgress = -1;
    
    while (elapsed < timeout) {
        DWORD symbolState = g_pGetSymbolState();
        DWORD importState = g_pGetImportState();
        
        bool symbolDone = (symbolState != 0x1C && symbolState != 0x1D && symbolState != 0x1E);
        bool importDone = (importState != 0x37);
        
        if (symbolDone && importDone) {
            std::cout << "\r                                        \r";
            PrintOK("Engine initialized");
            return true;
        }
        
        if (g_pGetDownloadProgressEx) {
            float progress = g_pGetDownloadProgressEx(0, false);
            int progressInt = static_cast<int>(progress * 100);
            if (progressInt != lastProgress) {
                PrintProgress(progressInt);
                lastProgress = progressInt;
            }
        }
        
        std::this_thread::sleep_for(std::chrono::seconds(1));
        elapsed++;
    }
    
    std::cout << "\n";
    return false;
}


// Inject using GH Injector Library
bool InjectWithGHInjector(DWORD pid, const std::wstring& dllPath) {
    if (!g_pInjectW) return false;
    
    INJECTIONDATAW injData = { 0 };
    wcscpy_s(injData.szDllPath, dllPath.c_str());
    injData.ProcessID = pid;
    injData.Mode = INJECTION_MODE::IM_ManualMap;
    injData.Method = LAUNCH_METHOD::LM_NtCreateThreadEx;
    injData.Flags = 
        INJ_MM_RESOLVE_IMPORTS |
        INJ_MM_RESOLVE_DELAY_IMPORTS |
        INJ_MM_INIT_SECURITY_COOKIE |
        INJ_MM_EXECUTE_TLS |
        INJ_MM_ENABLE_EXCEPTIONS |
        INJ_MM_RUN_DLL_MAIN |
        INJ_MM_SET_PAGE_PROTECTIONS |
        INJ_THREAD_CREATE_CLOAKED;
    injData.Timeout = 10000;
    injData.GenerateErrorLog = true;
    
    DWORD result = g_pInjectW(&injData);
    
    if (result == 0) {
        return true;
    }
    
    std::string errMsg = "Error code: 0x";
    char hexBuf[16];
    sprintf_s(hexBuf, "%X", result);
    errMsg += hexBuf;
    PrintErr(errMsg.c_str());
    return false;
}

void PrintBanner() {
    system("cls");
    
    // Set console buffer and window size
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD bufferSize = {145, 50};
    SetConsoleScreenBufferSize(hConsole, bufferSize);
    SMALL_RECT windowSize = {0, 0, 144, 35};
    SetConsoleWindowInfo(hConsole, TRUE, &windowSize);
    
    std::cout << "\n";
    Color::Magenta();
    std::cout << "  `7FN.   `7MF'`7CM\"\"\"YMM    .g8\"\"\"bgd `7MM\"\"\"Mq.   .g8\"\"8q. `7MMM.     ,MMF'      db      `7MN.   `7MF' .g8\"\"\"bgd `7MM\"\"\"YMM  `7MM\"\"\"Mq.  \n";
    std::cout << "    BMN.    L    IM    `7  .dP'     `M   MM   `MM..dP'    `YM. MMMb    dPAM       ;MM:       MMN.    M .HP'     `M   SM    `7    WM   `MM. \n";
    Color::Cyan();
    std::cout << "    I YZb   Z    ZM   d    dE'       `   MM   ,M9 dM'      `MM M YM   ,M IM      ,V^MM.      M YMb   M dA'       `   IM   d      IM   ,M9  \n";
    std::cout << "    Z  `MN. M    AMmmMM    MS            MMmmdM9  MM        MM M  Mb  M' MM     ,M  `MM      M  `MN. M MC            LMESPM      NESPdM9   \n";
    Color::White();
    std::cout << "    M   `MA.N    TM   Y  , MP.           MM  YM.  MM.      ,MP M  YM.P'  BM     AbmmmqMA     M   `MM.M MK.           EM   Y  ,   NM  YM.   \n";
    std::cout << "    A     YMO    EM     ,M `Mb.     ,'   MM   `Mb.`Mb.    ,dP' M  `YM'   OM    A'     VML    M     YMM `Sb.     ,'   NM     ,M   EM   `Mb. \n";
    Color::DarkGray();
    std::cout << "  .JNL.    YT  .JRMhackMMM   `\"bmmmd'  .JMML. .JMM. `\"bmmd\"' .JML. `'  .JTML..AMA.   .AMMA..JML.    YM   `\"bmmmd'  .JTMmESPMMM .JRML. .JMM.\n";
    std::cout << "\n";
    
    std::cout << "  =============================================================================================================\n";
    Color::Cyan();
    std::cout << "                                        ";
    Color::White();
    std::cout << "[ ";
    Color::Magenta();
    std::cout << "TF2 Loader";
    Color::White();
    std::cout << " | ";
    Color::Cyan();
    std::cout << "v2.1";
    Color::White();
    std::cout << " | ";
    Color::Yellow();
    std::cout << "by blizzman";
    Color::White();
    std::cout << " ]\n";
    Color::DarkGray();
    std::cout << "  =============================================================================================================\n\n";
    Color::White();
}

void WaitForProcess(const wchar_t* processName, const char* displayName) {
    std::string msg = "Waiting for ";
    msg += displayName;
    msg += "...";
    PrintInfo(msg.c_str());
    
    while (!IsProcessRunning(processName)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    msg = displayName;
    msg += " detected";
    PrintOK(msg.c_str());
}

int main() {
    SetConsoleTitleA("Necromancer - TF2 Loader");
    
    PrintBanner();
    
    // Check for admin privileges
    if (!IsRunningAsAdmin()) {
        PrintErr("Administrator privileges required!");
        PrintErr("Right-click and select 'Run as administrator'");
        std::cout << "\n  Press any key to exit...";
        std::cin.get();
        return 1;
    }
    
    PrintOK("Running as Administrator");

    // Check AVX2 support
    bool hasAVX2 = CheckAVX2Support();
    std::string buildMsg = "Build: ";
    buildMsg += hasAVX2 ? "AVX2 (optimized)" : "Standard";
    PrintInfo(buildMsg.c_str());

    const char* downloadUrl = hasAVX2 ? URL_AVX2 : URL_RELEASE;

    // Load GH Injector Library
    PrintInfo("Loading injection engine...");
    if (!LoadGHInjector()) {
        std::cout << "\n  Press any key to exit...";
        std::cin.get();
        return 1;
    }

    // Check for Steam
    if (!IsProcessRunning(L"steam.exe")) {
        WaitForProcess(L"steam.exe", "Steam");
    } else {
        PrintOK("Steam running");
    }

    // Check for TF2
    if (!IsProcessRunning(L"tf_win64.exe")) {
        WaitForProcess(L"tf_win64.exe", "Team Fortress 2");
    } else {
        PrintOK("TF2 running");
    }

    // Wait for TF2 to initialize
    DWORD tf2Pid = GetProcessId(L"tf_win64.exe");
    int uptime = GetProcessUptime(tf2Pid);
    if (uptime >= 0 && uptime < 25) {
        int waitTime = 25 - uptime;
        std::string waitMsg = "Waiting ";
        waitMsg += std::to_string(waitTime);
        waitMsg += "s for game init...";
        PrintInfo(waitMsg.c_str());
        std::this_thread::sleep_for(std::chrono::seconds(waitTime));
    }

    // Wait for GH Injector to be ready
    if (!WaitForGHInjectorReady()) {
        PrintErr("Injection engine failed to initialize!");
        UnloadGHInjector();
        std::cout << "\n  Press any key to exit...";
        std::cin.get();
        return 1;
    }

    // Download DLL
    PrintInfo("Downloading latest build...");
    std::vector<BYTE> zipData = DownloadFile(downloadUrl);
    
    if (zipData.empty()) {
        PrintErr("Download failed! Try again later.");
        UnloadGHInjector();
        std::cout << "\n  Press any key to exit...";
        std::cin.get();
        return 1;
    }
    PrintOK("Download complete");

    // Extract DLL from ZIP
    PrintInfo("Extracting...");
    std::vector<BYTE> dllData = ExtractDllFromZip(zipData);
    
    if (dllData.empty()) {
        PrintErr("Extraction failed!");
        UnloadGHInjector();
        std::cout << "\n  Press any key to exit...";
        std::cin.get();
        return 1;
    }

    // Save DLL
    std::wstring dllPath;
    if (!SaveDllToTemp(dllData, dllPath)) {
        PrintErr("Failed to prepare DLL!");
        UnloadGHInjector();
        std::cout << "\n  Press any key to exit...";
        std::cin.get();
        return 1;
    }

    // Get TF2 process
    DWORD pid = GetProcessId(L"tf_win64.exe");
    if (pid == 0) {
        PrintErr("TF2 is no longer running!");
        UnloadGHInjector();
        std::cout << "\n  Press any key to exit...";
        std::cin.get();
        return 1;
    }

    std::string injectMsg = "Injecting (PID: ";
    injectMsg += std::to_string(pid);
    injectMsg += ")...";
    PrintInfo(injectMsg.c_str());

    // Inject using GH Injector
    if (InjectWithGHInjector(pid, dllPath)) {
        std::cout << "\n";
        Color::DarkGray();
        std::cout << "    =========================================================\n";
        Color::Green();
        std::cout << "                    INJECTION SUCCESSFUL!\n";
        Color::DarkGray();
        std::cout << "    =========================================================\n\n";
        Color::White();
        
        std::error_code ec;
        std::filesystem::remove(dllPath, ec);
        UnloadGHInjector();
        
        PrintInfo("Closing in 5 seconds...");
        std::this_thread::sleep_for(std::chrono::seconds(5));
        return 0;
    }
    else {
        PrintErr("Injection failed! Check GH_Inj_Log.txt");
    }

    std::error_code ec;
    std::filesystem::remove(dllPath, ec);
    UnloadGHInjector();

    std::cout << "\n  Press any key to exit...";
    std::cin.get();
    return 1;
}

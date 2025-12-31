#include <windows.h>
#include <tlhelp32.h>
#include <wininet.h>
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <fstream>

#pragma comment(lib, "wininet.lib")

namespace fs = std::filesystem;

// Macro for relocation
#define RELOC_FLAG(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW || (RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

// Function prototypes
bool CheckAVX2Support();
bool IsSteamRunning();
bool IsGameRunning(const std::wstring& processName);
DWORD GetProcessId(const std::wstring& processName);
bool DownloadFile(const std::string& url, const std::string& outputPath);
bool ExtractZip(const std::string& zipPath, const std::string& extractPath);
bool ManualMapInject(DWORD processId, const std::string& dllPath);
void CleanupTempFiles();

const std::string AVX2_URL = "https://nightly.link/asdasfxcvxcvcb/necromancer/workflows/nightly/main/necromancer-ReleaseAVX2-x64.zip";
const std::string NORMAL_URL = "https://nightly.link/asdasfxcvxcvcb/necromancer/workflows/nightly/main/necromancer-Release-x64.zip";
const std::wstring GAME_PROCESS = L"tf_win64.exe";
const std::wstring STEAM_PROCESS = L"steam.exe";

int main() {
    std::cout << "=== Necromancer Loader ===" << std::endl;
    std::cout << std::endl;

    // Check AVX2 support
    bool hasAVX2 = CheckAVX2Support();
    if (hasAVX2) {
        std::cout << "[+] CPU supports AVX2 - using optimized build" << std::endl;
    } else {
        std::cout << "[+] CPU does not support AVX2 - using standard build" << std::endl;
    }

    // Check if Steam is running
    if (!IsSteamRunning()) {
        std::cout << "[!] Steam is not running. Please start Steam first." << std::endl;
        std::cout << "Press any key to exit..." << std::endl;
        std::cin.get();
        return 1;
    }
    std::cout << "[+] Steam is running" << std::endl;

    // Check if TF2 is running
    if (!IsGameRunning(GAME_PROCESS)) {
        std::cout << "[!] Team Fortress 2 is not running. Please start the game first." << std::endl;
        std::cout << "Press any key to exit..." << std::endl;
        std::cin.get();
        return 1;
    }
    std::cout << "[+] Team Fortress 2 is running" << std::endl;

    // Download the appropriate DLL
    std::string downloadUrl = hasAVX2 ? AVX2_URL : NORMAL_URL;
    std::string zipPath = "necromancer_temp.zip";
    
    std::cout << "[*] Downloading Necromancer..." << std::endl;
    if (!DownloadFile(downloadUrl, zipPath)) {
        std::cout << "[ERROR] Failed to download DLL. The build might be in progress." << std::endl;
        std::cout << "ERROR: Try later" << std::endl;
        CleanupTempFiles();
        std::cout << "Press any key to exit..." << std::endl;
        std::cin.get();
        return 1;
    }
    std::cout << "[+] Download complete" << std::endl;

    // Extract the ZIP
    std::string extractPath = "necromancer_temp";
    std::cout << "[*] Extracting files..." << std::endl;
    if (!ExtractZip(zipPath, extractPath)) {
        std::cout << "[ERROR] Failed to extract ZIP file" << std::endl;
        CleanupTempFiles();
        std::cout << "Press any key to exit..." << std::endl;
        std::cin.get();
        return 1;
    }
    std::cout << "[+] Extraction complete" << std::endl;

    // Find the DLL file
    std::string dllPath;
    for (const auto& entry : fs::recursive_directory_iterator(extractPath)) {
        if (entry.path().extension() == ".dll") {
            dllPath = entry.path().string();
            break;
        }
    }

    if (dllPath.empty()) {
        std::cout << "[ERROR] Could not find DLL in extracted files" << std::endl;
        CleanupTempFiles();
        std::cout << "Press any key to exit..." << std::endl;
        std::cin.get();
        return 1;
    }
    std::cout << "[+] Found DLL: " << dllPath << std::endl;

    // Get TF2 process ID
    DWORD processId = GetProcessId(GAME_PROCESS);
    if (processId == 0) {
        std::cout << "[ERROR] Failed to get process ID" << std::endl;
        CleanupTempFiles();
        std::cout << "Press any key to exit..." << std::endl;
        std::cin.get();
        return 1;
    }

    // Inject the DLL
    std::cout << "[*] Injecting DLL into Team Fortress 2..." << std::endl;
    if (!ManualMapInject(processId, dllPath)) {
        std::cout << "[ERROR] Injection failed" << std::endl;
        CleanupTempFiles();
        std::cout << "Press any key to exit..." << std::endl;
        std::cin.get();
        return 1;
    }

    std::cout << "[+] Successfully injected Necromancer!" << std::endl;
    
    // Cleanup
    CleanupTempFiles();
    
    std::cout << "Press any key to exit..." << std::endl;
    std::cin.get();
    return 0;
}

// Check if CPU supports AVX2
bool CheckAVX2Support() {
    int cpuInfo[4];
    __cpuidex(cpuInfo, 7, 0);
    return (cpuInfo[1] & (1 << 5)) != 0;
}

// Check if Steam is running
bool IsSteamRunning() {
    return IsGameRunning(STEAM_PROCESS);
}

// Check if a process is running
bool IsGameRunning(const std::wstring& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (_wcsicmp(processEntry.szExeFile, processName.c_str()) == 0) {
                CloseHandle(snapshot);
                return true;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return false;
}

// Get process ID by name
DWORD GetProcessId(const std::wstring& processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snapshot, &processEntry)) {
        do {
            if (_wcsicmp(processEntry.szExeFile, processName.c_str()) == 0) {
                DWORD pid = processEntry.th32ProcessID;
                CloseHandle(snapshot);
                return pid;
            }
        } while (Process32NextW(snapshot, &processEntry));
    }

    CloseHandle(snapshot);
    return 0;
}

// Download file from URL
bool DownloadFile(const std::string& url, const std::string& outputPath) {
    HINTERNET hInternet = InternetOpenA("NecromancerLoader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return false;
    }

    HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return false;
    }

    // Check HTTP status code
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    HttpQueryInfoA(hConnect, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &statusCodeSize, NULL);
    
    if (statusCode != 200) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return false;
    }

    std::ofstream outFile(outputPath, std::ios::binary);
    if (!outFile) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return false;
    }

    char buffer[4096];
    DWORD bytesRead;
    while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        outFile.write(buffer, bytesRead);
    }

    outFile.close();
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return true;
}

// Extract ZIP file (simplified - requires external library or PowerShell)
bool ExtractZip(const std::string& zipPath, const std::string& extractPath) {
    // Create extraction directory
    fs::create_directories(extractPath);

    // Use PowerShell to extract
    std::string command = "powershell -Command \"Expand-Archive -Path '" + zipPath + "' -DestinationPath '" + extractPath + "' -Force\"";
    int result = system(command.c_str());
    
    return result == 0;
}

// Loader data structure for shellcode
struct MANUAL_MAPPING_DATA {
    LPVOID ImageBase;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseReloc;
    PIMAGE_IMPORT_DESCRIPTOR ImportDesc;
    
    // Function pointers
    decltype(&LoadLibraryA) fnLoadLibraryA;
    decltype(&GetProcAddress) fnGetProcAddress;
    decltype(&VirtualProtect) fnVirtualProtect;
};

// Shellcode that runs in target process
DWORD __stdcall LoaderShellcode(MANUAL_MAPPING_DATA* pData) {
    if (!pData)
        return 0;

    BYTE* pBase = reinterpret_cast<BYTE*>(pData->ImageBase);
    auto* pOpt = &pData->NtHeaders->OptionalHeader;

    // Resolve imports
    auto* pImportDesc = pData->ImportDesc;
    while (pImportDesc->Name) {
        char* szMod = reinterpret_cast<char*>(pBase + pImportDesc->Name);
        HINSTANCE hDll = pData->fnLoadLibraryA(szMod);

        ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->OriginalFirstThunk);
        ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->FirstThunk);

        if (!pThunkRef)
            pThunkRef = pFuncRef;

        for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
            if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                *pFuncRef = reinterpret_cast<ULONG_PTR>(pData->fnGetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF)));
            } else {
                auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
                *pFuncRef = reinterpret_cast<ULONG_PTR>(pData->fnGetProcAddress(hDll, pImport->Name));
            }
        }
        ++pImportDesc;
    }

    // Process relocations
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        DWORD_PTR delta = reinterpret_cast<DWORD_PTR>(pBase) - pOpt->ImageBase;

        while (pRelocData->VirtualAddress) {
            UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

            for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo) {
                if (RELOC_FLAG(*pRelativeInfo)) {
                    UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
                    *pPatch += delta;
                }
            }
            pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
        }
    }

    // Set memory protections
    IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pData->NtHeaders);
    for (UINT i = 0; i != pData->NtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->Misc.VirtualSize) {
            DWORD flProtect = PAGE_READONLY;
            if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE)
                flProtect = PAGE_READWRITE;
            if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                flProtect = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;

            DWORD dwOld;
            pData->fnVirtualProtect(pBase + pSectionHeader->VirtualAddress, pSectionHeader->Misc.VirtualSize, flProtect, &dwOld);
        }
    }

    // Call DllMain
    using DllMain = BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID);
    auto fnDllMain = reinterpret_cast<DllMain>(pBase + pOpt->AddressOfEntryPoint);
    fnDllMain(reinterpret_cast<HINSTANCE>(pBase), DLL_PROCESS_ATTACH, nullptr);

    return 1;
}

// Dummy function to mark end of shellcode
DWORD __stdcall LoaderShellcodeEnd() { return 0; }

// Manual map injection implementation
bool ManualMapInject(DWORD processId, const std::string& dllPath) {
    // Read DLL file
    std::ifstream dllFile(dllPath, std::ios::binary | std::ios::ate);
    if (!dllFile) {
        std::cout << "[ERROR] Failed to open DLL file" << std::endl;
        return false;
    }

    size_t dllSize = dllFile.tellg();
    dllFile.seekg(0, std::ios::beg);
    
    std::vector<BYTE> dllData(dllSize);
    dllFile.read(reinterpret_cast<char*>(dllData.data()), dllSize);
    dllFile.close();

    // Open target process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        std::cout << "[ERROR] Failed to open process. Run as administrator!" << std::endl;
        return false;
    }

    // Parse PE headers
    PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(dllData.data());
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "[ERROR] Invalid DOS signature" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(dllData.data() + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "[ERROR] Invalid NT signature" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Allocate memory in target process
    LPVOID remoteImage = VirtualAllocEx(hProcess, nullptr, ntHeaders->OptionalHeader.SizeOfImage,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteImage) {
        std::cout << "[ERROR] Failed to allocate memory in target process" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    // Write headers
    if (!WriteProcessMemory(hProcess, remoteImage, dllData.data(), ntHeaders->OptionalHeader.SizeOfHeaders, nullptr)) {
        std::cout << "[ERROR] Failed to write headers" << std::endl;
        VirtualFreeEx(hProcess, remoteImage, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Write sections
    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (sectionHeader[i].SizeOfRawData > 0) {
            LPVOID sectionDest = reinterpret_cast<LPVOID>(reinterpret_cast<DWORD_PTR>(remoteImage) + sectionHeader[i].VirtualAddress);
            if (!WriteProcessMemory(hProcess, sectionDest, dllData.data() + sectionHeader[i].PointerToRawData,
                                   sectionHeader[i].SizeOfRawData, nullptr)) {
                std::cout << "[ERROR] Failed to write section " << i << std::endl;
                VirtualFreeEx(hProcess, remoteImage, 0, MEM_RELEASE);
                CloseHandle(hProcess);
                return false;
            }
        }
    }

    // Prepare loader data
    MANUAL_MAPPING_DATA loaderData;
    loaderData.ImageBase = remoteImage;
    loaderData.NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<DWORD_PTR>(remoteImage) + dosHeader->e_lfanew);
    loaderData.BaseReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(reinterpret_cast<DWORD_PTR>(remoteImage) + 
                           ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    loaderData.ImportDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(reinterpret_cast<DWORD_PTR>(remoteImage) + 
                            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    // Get function addresses
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    loaderData.fnLoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(GetProcAddress(hKernel32, "LoadLibraryA"));
    loaderData.fnGetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(GetProcAddress(hKernel32, "GetProcAddress"));
    loaderData.fnVirtualProtect = reinterpret_cast<decltype(&VirtualProtect)>(GetProcAddress(hKernel32, "VirtualProtect"));

    // Allocate memory for loader data
    LPVOID loaderDataRemote = VirtualAllocEx(hProcess, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!loaderDataRemote) {
        std::cout << "[ERROR] Failed to allocate loader data memory" << std::endl;
        VirtualFreeEx(hProcess, remoteImage, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, loaderDataRemote, &loaderData, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
        std::cout << "[ERROR] Failed to write loader data" << std::endl;
        VirtualFreeEx(hProcess, loaderDataRemote, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteImage, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Allocate memory for shellcode
    DWORD shellcodeSize = reinterpret_cast<DWORD_PTR>(LoaderShellcodeEnd) - reinterpret_cast<DWORD_PTR>(LoaderShellcode);
    LPVOID shellcodeRemote = VirtualAllocEx(hProcess, nullptr, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!shellcodeRemote) {
        std::cout << "[ERROR] Failed to allocate shellcode memory" << std::endl;
        VirtualFreeEx(hProcess, loaderDataRemote, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteImage, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, shellcodeRemote, LoaderShellcode, shellcodeSize, nullptr)) {
        std::cout << "[ERROR] Failed to write shellcode" << std::endl;
        VirtualFreeEx(hProcess, shellcodeRemote, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, loaderDataRemote, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteImage, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Create remote thread to execute shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, 
                                       reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcodeRemote),
                                       loaderDataRemote, 0, nullptr);
    
    if (!hThread) {
        std::cout << "[ERROR] Failed to create remote thread" << std::endl;
        VirtualFreeEx(hProcess, shellcodeRemote, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, loaderDataRemote, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, remoteImage, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Wait for thread to finish
    WaitForSingleObject(hThread, INFINITE);
    
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    
    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, shellcodeRemote, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, loaderDataRemote, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    return exitCode == 1;
}

// Cleanup temporary files
void CleanupTempFiles() {
    try {
        if (fs::exists("necromancer_temp.zip")) {
            fs::remove("necromancer_temp.zip");
        }
        if (fs::exists("necromancer_temp")) {
            fs::remove_all("necromancer_temp");
        }
    } catch (...) {
        // Ignore cleanup errors
    }
}

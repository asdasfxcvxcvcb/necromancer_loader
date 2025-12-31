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

#pragma comment(lib, "wininet.lib")

// Console colors
namespace Color {
    void Red() { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_INTENSITY); }
    void Green() { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
    void Yellow() { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); }
    void Cyan() { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); }
    void White() { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); }
    void Magenta() { SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY); }
}

// URLs
const char* URL_RELEASE = "https://nightly.link/asdasfxcvxcvcb/necromancer/workflows/nightly/main/necromancer-Release-x64.zip";
const char* URL_AVX2 = "https://nightly.link/asdasfxcvxcvcb/necromancer/workflows/nightly/main/necromancer-ReleaseAVX2-x64.zip";
const wchar_t* PROCESS_NAME = L"tf_win64.exe";
const wchar_t* STEAM_PROCESS = L"steam.exe";

// Manual Map structures
struct MANUAL_MAP_DATA {
    LPVOID pLoadLibraryA;
    LPVOID pGetProcAddress;
    LPVOID pRtlAddFunctionTable;
    LPVOID pbase;
    HINSTANCE hModule;
    DWORD fdwReason;
    LPVOID reserved;
};

// Function prototypes
bool CheckAVX2Support();
DWORD GetProcessId(const wchar_t* processName);
bool IsProcessRunning(const wchar_t* processName);
std::vector<BYTE> DownloadFile(const char* url);
std::vector<BYTE> ExtractDllFromZip(const std::vector<BYTE>& zipData);
bool ManualMap(HANDLE hProcess, const std::vector<BYTE>& dllData);
void PrintBanner();
void WaitForProcess(const wchar_t* processName, const char* displayName);


// Shellcode for manual mapping - runs in target process
void Shellcode(MANUAL_MAP_DATA* pData) {
    if (!pData) return;

    BYTE* pBase = reinterpret_cast<BYTE*>(pData->pbase);
    auto* pOptHeader = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pBase)->e_lfanew)->OptionalHeader;

    auto pLoadLibraryA = reinterpret_cast<decltype(&LoadLibraryA)>(pData->pLoadLibraryA);
    auto pGetProcAddress = reinterpret_cast<decltype(&GetProcAddress)>(pData->pGetProcAddress);
    auto pRtlAddFunctionTable = reinterpret_cast<decltype(&RtlAddFunctionTable)>(pData->pRtlAddFunctionTable);

    // Process relocations
    auto deltaBase = reinterpret_cast<UINT_PTR>(pBase - pOptHeader->ImageBase);
    if (deltaBase) {
        if (!pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) return;

        auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        while (pRelocData->VirtualAddress) {
            UINT numEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

            for (UINT i = 0; i < numEntries; ++i, ++pRelativeInfo) {
                if ((*pRelativeInfo >> 12) == IMAGE_REL_BASED_DIR64) {
                    UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + (*pRelativeInfo & 0xFFF));
                    *pPatch += deltaBase;
                }
                else if ((*pRelativeInfo >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                    DWORD* pPatch = reinterpret_cast<DWORD*>(pBase + pRelocData->VirtualAddress + (*pRelativeInfo & 0xFFF));
                    *pPatch += static_cast<DWORD>(deltaBase);
                }
            }
            pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
        }
    }

    // Process imports
    if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (pImportDesc->Name) {
            char* szModule = reinterpret_cast<char*>(pBase + pImportDesc->Name);
            HINSTANCE hDll = pLoadLibraryA(szModule);

            ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->OriginalFirstThunk);
            ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDesc->FirstThunk);

            if (!pThunkRef) pThunkRef = pFuncRef;

            for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                    *pFuncRef = reinterpret_cast<ULONG_PTR>(pGetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF)));
                }
                else {
                    auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + *pThunkRef);
                    *pFuncRef = reinterpret_cast<ULONG_PTR>(pGetProcAddress(hDll, pImport->Name));
                }
            }
            ++pImportDesc;
        }
    }

    // Process delayed imports
    if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size) {
        auto* pDelayImport = reinterpret_cast<IMAGE_DELAYLOAD_DESCRIPTOR*>(pBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress);
        while (pDelayImport->DllNameRVA) {
            char* szModule = reinterpret_cast<char*>(pBase + pDelayImport->DllNameRVA);
            HINSTANCE hDll = pLoadLibraryA(szModule);

            if (hDll) {
                ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pDelayImport->ImportNameTableRVA);
                ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pDelayImport->ImportAddressTableRVA);

                for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                    if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                        *pFuncRef = reinterpret_cast<ULONG_PTR>(pGetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF)));
                    }
                    else {
                        auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + *pThunkRef);
                        *pFuncRef = reinterpret_cast<ULONG_PTR>(pGetProcAddress(hDll, pImport->Name));
                    }
                }
            }
            ++pDelayImport;
        }
    }

    // TLS callbacks
    if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
        while (pCallback && *pCallback) {
            (*pCallback)(reinterpret_cast<PVOID>(pBase), DLL_PROCESS_ATTACH, nullptr);
            ++pCallback;
        }
    }

    // Exception handling
    if (pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size) {
        auto* pExceptionDir = reinterpret_cast<IMAGE_RUNTIME_FUNCTION_ENTRY*>(pBase + pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
        DWORD numEntries = pOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
        pRtlAddFunctionTable(pExceptionDir, numEntries, reinterpret_cast<DWORD64>(pBase));
    }

    // Call DllMain
    auto pDllMain = reinterpret_cast<BOOL(WINAPI*)(HINSTANCE, DWORD, LPVOID)>(pBase + pOptHeader->AddressOfEntryPoint);
    pData->hModule = reinterpret_cast<HINSTANCE>(pBase);
    pDllMain(reinterpret_cast<HINSTANCE>(pBase), DLL_PROCESS_ATTACH, nullptr);
}


// Check if CPU supports AVX2
bool CheckAVX2Support() {
    int cpuInfo[4] = { 0 };
    __cpuid(cpuInfo, 0);
    int nIds = cpuInfo[0];

    if (nIds >= 7) {
        __cpuidex(cpuInfo, 7, 0);
        return (cpuInfo[1] & (1 << 5)) != 0; // AVX2 bit
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

// Download file from URL
std::vector<BYTE> DownloadFile(const char* url) {
    std::vector<BYTE> data;

    HINTERNET hInternet = InternetOpenA("NecromancerLoader/1.0", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
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

// Simple ZIP extraction - finds and extracts the DLL from the zip
std::vector<BYTE> ExtractDllFromZip(const std::vector<BYTE>& zipData) {
    std::vector<BYTE> dllData;
    
    if (zipData.size() < 30) return dllData;

    // ZIP local file header signature: 0x04034b50
    size_t pos = 0;
    while (pos + 30 <= zipData.size()) {
        if (zipData[pos] == 0x50 && zipData[pos + 1] == 0x4B && 
            zipData[pos + 2] == 0x03 && zipData[pos + 3] == 0x04) {
            
            WORD compressionMethod = *reinterpret_cast<const WORD*>(&zipData[pos + 8]);
            DWORD compressedSize = *reinterpret_cast<const DWORD*>(&zipData[pos + 18]);
            DWORD uncompressedSize = *reinterpret_cast<const DWORD*>(&zipData[pos + 22]);
            WORD fileNameLen = *reinterpret_cast<const WORD*>(&zipData[pos + 26]);
            WORD extraFieldLen = *reinterpret_cast<const WORD*>(&zipData[pos + 28]);

            if (pos + 30 + fileNameLen > zipData.size()) break;

            std::string fileName(reinterpret_cast<const char*>(&zipData[pos + 30]), fileNameLen);
            
            // Check if it's a DLL file
            if (fileName.size() >= 4 && 
                (fileName.substr(fileName.size() - 4) == ".dll" || fileName.substr(fileName.size() - 4) == ".DLL")) {
                
                size_t dataStart = pos + 30 + fileNameLen + extraFieldLen;
                
                if (compressionMethod == 0) { // Stored (no compression)
                    if (dataStart + uncompressedSize <= zipData.size()) {
                        dllData.assign(zipData.begin() + dataStart, zipData.begin() + dataStart + uncompressedSize);
                        return dllData;
                    }
                }
                else if (compressionMethod == 8) { // Deflate
                    // For deflate, we need to decompress
                    // Using Windows built-in decompression
                    if (dataStart + compressedSize <= zipData.size()) {
                        // Allocate buffer for decompressed data
                        dllData.resize(uncompressedSize);
                        
                        // Use RtlDecompressBuffer
                        typedef NTSTATUS(WINAPI* RtlDecompressBufferFn)(
                            USHORT CompressionFormat,
                            PUCHAR UncompressedBuffer,
                            ULONG UncompressedBufferSize,
                            PUCHAR CompressedBuffer,
                            ULONG CompressedBufferSize,
                            PULONG FinalUncompressedSize
                        );
                        
                        // Deflate in ZIP needs manual handling - let's use a simpler approach
                        // Save to temp file and use shell to extract
                        std::filesystem::path tempDir = std::filesystem::temp_directory_path();
                        std::filesystem::path zipPath = tempDir / "necromancer_temp.zip";
                        std::filesystem::path extractDir = tempDir / "necromancer_extract";
                        
                        // Write zip to temp file
                        std::ofstream zipFile(zipPath, std::ios::binary);
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
                        std::error_code ec;
                        std::filesystem::remove(zipPath, ec);
                        std::filesystem::remove_all(extractDir, ec);
                        
                        return dllData;
                    }
                }
            }
            
            // Move to next file
            pos += 30 + fileNameLen + extraFieldLen + compressedSize;
        }
        else {
            pos++;
        }
    }
    
    return dllData;
}


// Manual Map injection
bool ManualMap(HANDLE hProcess, const std::vector<BYTE>& dllData) {
    if (dllData.size() < sizeof(IMAGE_DOS_HEADER)) {
        Color::Red();
        std::cout << "[!] Invalid DLL data - too small\n";
        Color::White();
        return false;
    }

    auto* pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(dllData.data());
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        Color::Red();
        std::cout << "[!] Invalid DOS signature\n";
        Color::White();
        return false;
    }

    if (dllData.size() < pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)) {
        Color::Red();
        std::cout << "[!] Invalid DLL data - NT headers out of bounds\n";
        Color::White();
        return false;
    }

    auto* pNtHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(dllData.data() + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        Color::Red();
        std::cout << "[!] Invalid NT signature\n";
        Color::White();
        return false;
    }

    if (pNtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        Color::Red();
        std::cout << "[!] DLL is not 64-bit\n";
        Color::White();
        return false;
    }

    const auto& optHeader = pNtHeaders->OptionalHeader;
    
    // Allocate memory in target process
    LPVOID pTargetBase = VirtualAllocEx(hProcess, nullptr, optHeader.SizeOfImage, 
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!pTargetBase) {
        Color::Red();
        std::cout << "[!] Failed to allocate memory in target process: " << GetLastError() << "\n";
        Color::White();
        return false;
    }

    Color::Cyan();
    std::cout << "[*] Allocated " << optHeader.SizeOfImage << " bytes at 0x" << std::hex << pTargetBase << std::dec << "\n";
    Color::White();

    // Write headers
    if (!WriteProcessMemory(hProcess, pTargetBase, dllData.data(), optHeader.SizeOfHeaders, nullptr)) {
        Color::Red();
        std::cout << "[!] Failed to write headers\n";
        Color::White();
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    // Write sections
    auto* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData == 0) continue;

        if (pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData > dllData.size()) {
            Color::Yellow();
            std::cout << "[!] Section " << i << " data out of bounds, skipping\n";
            Color::White();
            continue;
        }

        LPVOID pSectionDest = reinterpret_cast<BYTE*>(pTargetBase) + pSectionHeader->VirtualAddress;
        if (!WriteProcessMemory(hProcess, pSectionDest, 
            dllData.data() + pSectionHeader->PointerToRawData, 
            pSectionHeader->SizeOfRawData, nullptr)) {
            Color::Red();
            std::cout << "[!] Failed to write section " << i << "\n";
            Color::White();
            VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
            return false;
        }
    }

    Color::Cyan();
    std::cout << "[*] Sections mapped successfully\n";
    Color::White();

    // Prepare manual map data
    MANUAL_MAP_DATA mapData = { 0 };
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

    mapData.pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    mapData.pGetProcAddress = GetProcAddress(hKernel32, "GetProcAddress");
    mapData.pRtlAddFunctionTable = GetProcAddress(hNtdll, "RtlAddFunctionTable");
    mapData.pbase = pTargetBase;
    mapData.fdwReason = DLL_PROCESS_ATTACH;
    mapData.reserved = nullptr;

    // Allocate memory for map data
    LPVOID pMapData = VirtualAllocEx(hProcess, nullptr, sizeof(MANUAL_MAP_DATA), 
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    
    if (!pMapData) {
        Color::Red();
        std::cout << "[!] Failed to allocate map data memory\n";
        Color::White();
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pMapData, &mapData, sizeof(mapData), nullptr)) {
        Color::Red();
        std::cout << "[!] Failed to write map data\n";
        Color::White();
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pMapData, 0, MEM_RELEASE);
        return false;
    }

    // Allocate and write shellcode
    void* pShellcode = VirtualAllocEx(hProcess, nullptr, 0x1000, 
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
    if (!pShellcode) {
        Color::Red();
        std::cout << "[!] Failed to allocate shellcode memory\n";
        Color::White();
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pMapData, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pShellcode, Shellcode, 0x1000, nullptr)) {
        Color::Red();
        std::cout << "[!] Failed to write shellcode\n";
        Color::White();
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pMapData, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
        return false;
    }

    Color::Cyan();
    std::cout << "[*] Shellcode written, creating remote thread...\n";
    Color::White();

    // Execute shellcode
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, 
        reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pMapData, 0, nullptr);
    
    if (!hThread) {
        Color::Red();
        std::cout << "[!] Failed to create remote thread: " << GetLastError() << "\n";
        Color::White();
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pMapData, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
        return false;
    }

    // Wait for shellcode to complete
    DWORD waitResult = WaitForSingleObject(hThread, 15000);
    
    if (waitResult == WAIT_TIMEOUT) {
        Color::Yellow();
        std::cout << "[!] Shellcode execution timed out (may still be running)\n";
        Color::White();
    }
    else if (waitResult == WAIT_FAILED) {
        Color::Red();
        std::cout << "[!] Wait failed: " << GetLastError() << "\n";
        Color::White();
    }

    CloseHandle(hThread);

    // Cleanup shellcode and map data (leave DLL in memory)
    VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pMapData, 0, MEM_RELEASE);

    // Set proper memory protections for sections
    pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
        DWORD protect = PAGE_READONLY;
        DWORD characteristics = pSectionHeader->Characteristics;

        if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
            if (characteristics & IMAGE_SCN_MEM_WRITE)
                protect = PAGE_EXECUTE_READWRITE;
            else if (characteristics & IMAGE_SCN_MEM_READ)
                protect = PAGE_EXECUTE_READ;
            else
                protect = PAGE_EXECUTE;
        }
        else if (characteristics & IMAGE_SCN_MEM_WRITE) {
            protect = PAGE_READWRITE;
        }
        else if (characteristics & IMAGE_SCN_MEM_READ) {
            protect = PAGE_READONLY;
        }

        DWORD oldProtect;
        VirtualProtectEx(hProcess, reinterpret_cast<BYTE*>(pTargetBase) + pSectionHeader->VirtualAddress,
            pSectionHeader->Misc.VirtualSize, protect, &oldProtect);
    }

    return true;
}


void PrintBanner() {
    Color::Magenta();
    std::cout << R"(
    _   __                                                    
   / | / /__  ____________  ____ ___  ____ _____  _________ 
  /  |/ / _ \/ ___/ ___/ / / / __ `__ \/ __ `/ __ \/ ___/ _ \/ ___/
 / /|  /  __/ /__/ /  / /_/ / / / / / / /_/ / / / / /__/  __/ /    
/_/ |_/\___/\___/_/   \____/_/ /_/ /_/\__,_/_/ /_/\___/\___/_/     
                                                                   
)" << "\n";
    Color::Cyan();
    std::cout << "                    [ Loader v1.0 ]\n\n";
    Color::White();
}

void WaitForProcess(const wchar_t* processName, const char* displayName) {
    Color::Yellow();
    std::cout << "[*] Waiting for " << displayName << "...\n";
    Color::White();
    
    while (!IsProcessRunning(processName)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    Color::Green();
    std::cout << "[+] " << displayName << " detected!\n";
    Color::White();
}

int main() {
    SetConsoleTitleA("Necromancer Loader");
    
    PrintBanner();

    // Check AVX2 support
    bool hasAVX2 = CheckAVX2Support();
    Color::Cyan();
    std::cout << "[*] CPU AVX2 Support: ";
    if (hasAVX2) {
        Color::Green();
        std::cout << "YES\n";
    }
    else {
        Color::Yellow();
        std::cout << "NO\n";
    }
    Color::White();

    const char* downloadUrl = hasAVX2 ? URL_AVX2 : URL_RELEASE;
    Color::Cyan();
    std::cout << "[*] Using " << (hasAVX2 ? "AVX2" : "Standard") << " build\n\n";
    Color::White();

    // Check for Steam
    if (!IsProcessRunning(L"steam.exe")) {
        Color::Yellow();
        std::cout << "[!] Steam is not running!\n";
        std::cout << "[*] Please start Steam first.\n";
        Color::White();
        WaitForProcess(L"steam.exe", "Steam");
        std::cout << "\n";
    }
    else {
        Color::Green();
        std::cout << "[+] Steam is running\n";
        Color::White();
    }

    // Check for TF2
    if (!IsProcessRunning(L"tf_win64.exe")) {
        Color::Yellow();
        std::cout << "[!] Team Fortress 2 is not running!\n";
        std::cout << "[*] Please start TF2 and wait until you're in the main menu.\n";
        Color::White();
        WaitForProcess(L"tf_win64.exe", "Team Fortress 2");
        
        // Give the game time to fully initialize
        Color::Cyan();
        std::cout << "[*] Waiting for game to initialize...\n";
        Color::White();
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    else {
        Color::Green();
        std::cout << "[+] Team Fortress 2 is running\n";
        Color::White();
    }

    std::cout << "\n";

    // Download DLL
    Color::Cyan();
    std::cout << "[*] Downloading Necromancer...\n";
    Color::White();

    std::vector<BYTE> zipData = DownloadFile(downloadUrl);
    
    if (zipData.empty()) {
        Color::Red();
        std::cout << "\n[ERROR] Download failed!\n";
        std::cout << "[ERROR] The DLL might be building right now. Try again later.\n\n";
        Color::White();
        std::cout << "Press any key to exit...";
        std::cin.get();
        return 1;
    }

    Color::Green();
    std::cout << "[+] Downloaded " << zipData.size() << " bytes\n";
    Color::White();

    // Extract DLL from ZIP
    Color::Cyan();
    std::cout << "[*] Extracting DLL from archive...\n";
    Color::White();

    std::vector<BYTE> dllData = ExtractDllFromZip(zipData);
    
    if (dllData.empty()) {
        Color::Red();
        std::cout << "\n[ERROR] Failed to extract DLL from archive!\n";
        std::cout << "[ERROR] The archive might be corrupted or building. Try again later.\n\n";
        Color::White();
        std::cout << "Press any key to exit...";
        std::cin.get();
        return 1;
    }

    Color::Green();
    std::cout << "[+] Extracted DLL: " << dllData.size() << " bytes\n\n";
    Color::White();

    // Get TF2 process
    DWORD pid = GetProcessId(L"tf_win64.exe");
    if (pid == 0) {
        Color::Red();
        std::cout << "[ERROR] Team Fortress 2 is no longer running!\n\n";
        Color::White();
        std::cout << "Press any key to exit...";
        std::cin.get();
        return 1;
    }

    Color::Cyan();
    std::cout << "[*] TF2 Process ID: " << pid << "\n";
    Color::White();

    // Open process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        Color::Red();
        std::cout << "[ERROR] Failed to open TF2 process!\n";
        std::cout << "[ERROR] Try running as Administrator.\n\n";
        Color::White();
        std::cout << "Press any key to exit...";
        std::cin.get();
        return 1;
    }

    Color::Green();
    std::cout << "[+] Process opened successfully\n\n";
    Color::White();

    // Inject
    Color::Cyan();
    std::cout << "[*] Starting manual map injection...\n";
    Color::White();

    if (ManualMap(hProcess, dllData)) {
        Color::Green();
        std::cout << "\n[+] Injection successful!\n";
        std::cout << "[+] Necromancer has been loaded.\n\n";
        Color::White();
    }
    else {
        Color::Red();
        std::cout << "\n[ERROR] Injection failed!\n\n";
        Color::White();
    }

    CloseHandle(hProcess);

    std::cout << "Press any key to exit...";
    std::cin.get();
    return 0;
}

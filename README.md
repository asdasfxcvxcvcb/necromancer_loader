# Necromancer Loader v2.1

A single-exe manual map injector for Team Fortress 2 using the GH Injector Library.

## Features

- **Single EXE**: GH Injector DLL is embedded - just one file to distribute
- **Automatic Admin Elevation**: Double-click and it requests admin privileges automatically
- **AVX2 Detection**: Automatically downloads the correct build for your CPU
- **GH Injector Library**: Uses the battle-tested GuidedHacking injector for reliable manual mapping
- **Full Manual Map Support**: 
  - Import resolution (including API Sets)
  - Relocation processing
  - TLS callback execution
  - Exception handler registration
  - Security cookie initialization
  - Proper page protections
- **Auto-close**: Closes 5 seconds after successful injection
- **Clean Storage**: All files stored in `C:\necromancer_tf2`

## Build Instructions

### Prerequisites

- Visual Studio 2022 (v143 toolset)
- Windows 10 SDK
- C++17 support

### Building

**IMPORTANT**: You must build in this order:

1. Open `NecromancerLoader.sln` in Visual Studio
2. First, build **GH Injector Library** project (Release | x64)
   - This creates `bin\Release\GH Injector - x64.dll`
3. Then, build **NecromancerLoader** project (Release | x64)
   - This embeds the DLL into the exe

The final `NecromancerLoader.exe` in `bin\Release\` contains everything.

### Distribution

Just distribute the single file:
- `NecromancerLoader.exe`

That's it! No additional DLLs needed.

## Usage

1. Start Steam
2. Start Team Fortress 2 (wait until main menu)
3. Double-click `NecromancerLoader.exe`
4. Accept the admin prompt
5. Wait for injection to complete
6. Loader closes automatically after 5 seconds

## File Locations

All loader files are stored in `C:\necromancer_tf2\loader\`:
- `GH Injector - x64.dll` - Extracted injector library
- `necromancer.dll` - Downloaded cheat DLL
- `x64\ntdll.pdb` - Microsoft symbols (downloaded on first run)
- `x86\wntdll.pdb` - Microsoft symbols for WOW64 (optional)
- `GH_Inj_Log.txt` - Error log if injection fails

## How It Works

1. Loader checks for admin privileges, re-launches elevated if needed
2. Extracts embedded GH Injector DLL to `C:\necromancer_tf2`
3. Loads the GH Injector Library
4. Waits for GH Injector to download PDB symbols from Microsoft (first run only)
5. Detects CPU AVX2 support to download optimal DLL build
6. Downloads the Necromancer DLL from nightly builds
7. Saves DLL to `C:\necromancer_tf2`
8. Calls GH Injector's `InjectW` function with Manual Map mode
9. GH Injector handles all the complex injection
10. Cleans up and exits

## Credits

- [GuidedHacking Injector Library](https://github.com/guided-hacking/GuidedHacking-Injector) - The injection engine
- Broihon / Guided Hacking LLC - Original GH Injector code

## Troubleshooting

### "Failed to find embedded DLL resource"
The exe wasn't built correctly. Make sure to build GH Injector Library FIRST, then rebuild NecromancerLoader.

### "Symbol initialization failed"
The GH Injector needs to download PDB files from Microsoft's symbol servers on first run. Make sure you have internet access.

### Injection fails with error code
Check `C:\necromancer_tf2\loader\GH_Inj_Log.txt` for detailed error information.

### Game crashes after injection
The DLL being injected may have issues. This is not a loader problem.

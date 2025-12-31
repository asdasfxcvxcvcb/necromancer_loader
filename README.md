# Necromancer Loader

A DLL loader for the Necromancer cheat for Team Fortress 2.

## Features

- Automatic AVX2 CPU detection and appropriate build download
- Steam and TF2 process verification
- Automatic download from GitHub nightly builds
- ZIP extraction and DLL injection
- Manual map injection
- Automatic cleanup of temporary files

## Download Pre-built

Download the latest build from nightly.link:
https://nightly.link/asdasfxcvxcvcb/necromancer_loader/workflows/nightly/main/NecromancerLoader-Release-x64.zip

## Building

1. Open `NecromancerLoader.sln` in Visual Studio 2019 or later
2. Select Release x64 configuration
3. Build Solution (Ctrl+Shift+B)
4. Executable will be in `bin\Release\NecromancerLoader.exe`

## Usage

1. Start Steam
2. Launch Team Fortress 2
3. Run `NecromancerLoader.exe` as administrator
4. The loader will automatically inject Necromancer


## Links

- Necromancer Normal build: https://nightly.link/asdasfxcvxcvcb/necromancer/workflows/nightly/main/necromancer-Release-x64.zip
- Necromancer AVX2 build: https://nightly.link/asdasfxcvxcvcb/necromancer/workflows/nightly/main/necromancer-ReleaseAVX2-x64.zip


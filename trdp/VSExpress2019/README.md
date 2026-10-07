# Windows Build Validation with MSVC v145

This document describes the successful validation of the TRDP Windows build using Visual Studio 2026 Build Tools and the MSVC v145 platform toolset.

This existing directory name (`VSExpress2019`) is retained for compatibility and traceability. The project files within this directory have been updated to build with the current toolset.

## Prerequisites

- Visual Studio 2026 Build Tools
- MSVC C/C++ platform toolset v145
- Windows SDK
- x64 Native Tools Command Prompt for Visual Studio 2026

Additional components such as AddressSanitizer and vcpkg are not required for the standard build.

## Build the Complete Solution

Open an **x64 Native Tools Command Prompt for Visual Studio 2026**, change to this directory and run:

```cmd
msbuild Win_TRDP_VS2019.sln /p:Configuration=Debug /p:Platform=x64
```

The complete solution has been successfully built in the `Debug|x64` configuration.

## Build the TRDP Static Library

From this directory, run:

```cmd
msbuild TRDP\TRDP.vcxproj /p:Configuration=Release /p:Platform=x64
```

The resulting static library is generated as:

```text
TRDP\Release\x64\TRDP.lib
```

## Build the TRDP Dynamic Library

From this directory, run:

```cmd
msbuild TRDP_DLL\TRDP_DLL.vcxproj /p:Configuration=Release /p:Platform=x64
```

The resulting dynamic library is generated as:

```text
TRDP_DLL\Release\x64\TRDP_DLL.dll
```

## Known Warning

The following linker warning may appear during Debug builds:

```text
LNK4075: ignoring '/EDITANDCONTINUE' due to '/INCREMENTAL:NO' specification
```

This warning indicates that Edit and Continue is disabled because incremental linking is disabled. It does not prevent the build from completing and did not affect the validated runtime behavior.

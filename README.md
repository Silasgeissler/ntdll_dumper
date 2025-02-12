# Syscall and Export Dumper

## Overview
This tool extracts syscall numbers from DLLs by scanning for standard syscall stub patterns. It can also enumerate and display all exports from a given DLL, including function names, ordinals, addresses, and the first eight bytes of each function.

## Features
- Extracts syscall numbers from 64-bit DLLs (e.g., `ntdll.dll`).
- Dumps all exported functions from any DLL.
- Outputs results to console or file.

## Usage
1. Compile with a C compiler (e.g., MSVC, MinGW).
2. Run the executable and select a mode:
   - `1` for syscall stubs.
   - `2` for all exports.
3. Enter the target DLL name (e.g., `ntdll.dll`).
4. Choose output method (console or file).

## Example
```sh
Syscall and Export Dumper
Select Dump Mode:
  1. Dump syscall stubs (ntdll-like)
  2. Dump export information (all functions)
Choice: 1
Enter DLL name: ntdll.dll
Output Options:
  1. Console
  2. File
Choice: 1
```

## Notes
- Requires Windows. (duh)
- The syscall stub is pretty much only found in ntdll.dll. I will update it for other DLLs that provide syscall stubs soon.

## License
do whatever

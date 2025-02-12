#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winnt.h>

//------------------------------------------------------------------------------
// DumpSyscallsFromDLL:
// Loads the specified DLL, enumerates its exports, and for each export that
// matches the expected 64‑bit syscall stub pattern, prints its syscall number.
// The expected pattern is:
//     4C 8B D1          ; mov r10, rcx
//     B8 xx xx xx xx    ; mov eax, <syscall_number>
//     0F 05             ; syscall
//     C3                ; ret
//------------------------------------------------------------------------------
void DumpSyscallsFromDLL(const char* dllName, FILE* out)
{
    HMODULE hModule = LoadLibraryA(dllName);
    if (!hModule)
    {
        fprintf(out, "Failed to load %s: %lu\n", dllName, GetLastError());
        return;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        fprintf(out, "Invalid DOS signature in %s\n", dllName);
        FreeLibrary(hModule);
        return;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        fprintf(out, "Invalid NT signature in %s\n", dllName);
        FreeLibrary(hModule);
        return;
    }

    IMAGE_DATA_DIRECTORY exportDataDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDataDir.VirtualAddress == 0)
    {
        fprintf(out, "No export directory found in %s\n", dllName);
        FreeLibrary(hModule);
        return;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDataDir.VirtualAddress);
    DWORD numberOfNames = pExportDir->NumberOfNames;
    DWORD* pNames = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfNames);
    WORD* pOrdinals = (WORD*)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);
    DWORD* pFunctions = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfFunctions);

    fprintf(out, "\nDumping syscall stubs from %s:\n", dllName);
    fprintf(out, "-------------------------------------------------\n");

    int countFound = 0;
    for (DWORD i = 0; i < numberOfNames; i++)
    {
        char* funcName = (char*)((BYTE*)hModule + pNames[i]);
        WORD ordinal = pOrdinals[i];
        void* funcAddress = (void*)((BYTE*)hModule + pFunctions[ordinal]);
        unsigned char* pFunc = (unsigned char*)funcAddress;

        // Check for the expected syscall stub pattern mentioned above.
        if (pFunc[0] == 0x4C &&
            pFunc[1] == 0x8B &&
            pFunc[2] == 0xD1 &&
            pFunc[3] == 0xB8)
        {
            DWORD syscallNumber = *(DWORD*)(pFunc + 4);
            fprintf(out, "%-40s: Syscall Number = 0x%X\n", funcName, syscallNumber);
            countFound++;
        }
    }

    if (!countFound)
        fprintf(out, "No syscall stubs matching the expected pattern were found in %s.\n", dllName);

    FreeLibrary(hModule);
}

//------------------------------------------------------------------------------
// DumpExportsFromDLL:
// Loads the specified DLL, enumerates all its exports, and prints for each export:
//   - Function name
//   - Ordinal
//   - Function address
//   - The first 8 bytes of the function in hex
//------------------------------------------------------------------------------
void DumpExportsFromDLL(const char* dllName, FILE* out)
{
    HMODULE hModule = LoadLibraryA(dllName);
    if (!hModule)
    {
        fprintf(out, "Failed to load %s: %lu\n", dllName, GetLastError());
        return;
    }

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        fprintf(out, "Invalid DOS signature in %s\n", dllName);
        FreeLibrary(hModule);
        return;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        fprintf(out, "Invalid NT signature in %s\n", dllName);
        FreeLibrary(hModule);
        return;
    }

    IMAGE_DATA_DIRECTORY exportDataDir = pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exportDataDir.VirtualAddress == 0)
    {
        fprintf(out, "No export directory found in %s\n", dllName);
        FreeLibrary(hModule);
        return;
    }

    PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportDataDir.VirtualAddress);
    DWORD numberOfNames = pExportDir->NumberOfNames;
    DWORD* pNames = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfNames);
    WORD* pOrdinals = (WORD*)((BYTE*)hModule + pExportDir->AddressOfNameOrdinals);
    DWORD* pFunctions = (DWORD*)((BYTE*)hModule + pExportDir->AddressOfFunctions);

    fprintf(out, "\nDumping export information from %s:\n", dllName);
    fprintf(out, "-------------------------------------------------\n");
    for (DWORD i = 0; i < numberOfNames; i++)
    {
        char* funcName = (char*)((BYTE*)hModule + pNames[i]);
        WORD ordinal = pOrdinals[i];
        void* funcAddress = (void*)((BYTE*)hModule + pFunctions[ordinal]);
        unsigned char* pFunc = (unsigned char*)funcAddress;

        fprintf(out, "Function: %-40s Ordinal: %u, Address: 0x%p, Bytes: ", funcName, ordinal, funcAddress);
        for (int j = 0; j < 8; j++)
        {
            fprintf(out, "%02X ", pFunc[j]);
        }
        fprintf(out, "\n");
    }

    FreeLibrary(hModule);
}

//------------------------------------------------------------------------------
// Main function: Self-explanatory. Presents a menu to select the dump mode and DLL, 
// asks for theoutput destination (console or file), then calls the appropriate dumping function.
int main(void)
{
    int mode;
    char dllName[256];
    int outputOption;
    FILE* outFile = stdout;
    char fileName[256];

    printf("Select Dump Mode:\n");
    printf("  1. Dump syscall stubs (ntdll-like)\n");
    printf("  2. Dump export information (all functions)\n");
    printf("Choice: ");
    if (scanf_s("%d", &mode) != 1)
    {
        printf("Invalid input.\n");
        return 1;
    }
    while (getchar() != '\n');

    printf("Enter DLL name (e.g., ntdll.dll, kernel32.dll): ");
    if (!fgets(dllName, sizeof(dllName), stdin))
    {
        printf("Failed to read input.\n");
        return 1;
    }
    size_t len = strlen(dllName);
    if (len > 0 && dllName[len - 1] == '\n')
        dllName[len - 1] = '\0';

    printf("Output Options:\n");
    printf("  1. Write output to console\n");
    printf("  2. Write output to file\n");
    printf("Choice: ");
    if (scanf_s("%d", &outputOption) != 1)
    {
        printf("Invalid input.\n");
        return 1;
    }
    while (getchar() != '\n');

    if (outputOption == 2)
    {
        printf("Enter output file name: ");
        if (!fgets(fileName, sizeof(fileName), stdin))
        {
            printf("Failed to read file name.\n");
            return 1;
        }
        len = strlen(fileName);
        if (len > 0 && fileName[len - 1] == '\n')
            fileName[len - 1] = '\0';

        if (fopen_s(&outFile, fileName, "w") != 0 || outFile == NULL);
    }

    if (mode == 1)
    {
        DumpSyscallsFromDLL(dllName, outFile);
    }
    else if (mode == 2)
    {
        DumpExportsFromDLL(dllName, outFile);
    }
    else
    {
        fprintf(outFile, "Invalid mode selected.\n");
        if (outFile != stdout)
            fclose(outFile);
        return 1;
    }

    if (outFile != stdout)
    {
        fclose(outFile);
        printf("Output written to file successfully.\n");
    }

    return 0;
}

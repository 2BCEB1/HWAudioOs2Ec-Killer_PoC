# HWAudioOs2Ec-Killer_PoC
Huntressが公開したインシデントレポートで使用されていたBYOVDに関する調査<br>
->https://www.huntress.com/blog/w2-malvertising-to-kernel-mode-edr-kill

# 脆弱なドライバ「HWAudioOs2Ec.sys」の情報

|プロパティ|データ|
|-|-|
|ファイル名|HWAudioOs2Ec.sys|
|SHA256|5ABE477517F51D81061D2E69A9ADEBDCDA80D36667D0AFABE103FDA4802D33DB|
|作成タイムスタンプ|‎2021‎年‎11‎月‎15‎日　‏‎23:19:16|
|署名者|Huawei Device Co., Ltd.|
|署名時刻|‎2021‎年‎11‎月‎16‎日 11:51:33|
|製品名|Huawei Audio Driver|
|製品バージョン|1.0.0.0|

# 脆弱性情報

|プロパティ|データ|
|-|-|
|脆弱なIOCTLコード|`0x2248dc`|
|デバイス名|`\\.\HWAudioX64`  (SymbolicLink: `\DosDevices\HWAudioX64`)|
|使用可能なZw*関数|`ZwOpenProcess`, `ZwTerminateProcess`|
|メソッド|METHOD_BUFFERED (SystemBuffer使用)|
|入力バッファサイズ| 4バイト (0x4)|
|入力バッファ内容|ターゲットプロセスのPID (32bit)|
|出力バッファ|不要 (0x0)|

---
# HWAudioOs2Ec.sys — Arbitrary Process Termination PoC

Proof-of-Concept for an arbitrary process termination vulnerability in the Huawei laptop audio kernel driver **HWAudioOs2Ec.sys**.

This driver has been observed in the wild as a BYOVD (Bring Your Own Vulnerable Driver) weapon to terminate EDR/AV processes from kernel mode.

## Vulnerability Summary

| Item | Detail |
|---|---|
| **Driver** | HWAudioOs2Ec.sys (Huawei Device Co., Ltd.) |
| **SHA256** | `5ABE477517F51D81061D2E69A9ADEBDCDA80D36667D0AFABE103FDA4802D33DB` |
| **Device** | `\\.\HWAudioX64` |
| **IOCTL** | `0x2248DC` |
| **Method** | `METHOD_BUFFERED` (SystemBuffer) |
| **Access** | `FILE_ANY_ACCESS` — SDDL restricts device to SYSTEM/Administrators |
| **Input** | 4 bytes — target process PID (`DWORD`) |
| **Impact** | Terminate any process including PPL-protected processes (EDR/AV) |

## Vulnerability Detail

The IOCTL dispatch handler for `0x2248DC` performs the following without any validation:

1. Reads a 4-byte PID from `SystemBuffer` via `memcpy_s`
2. Passes the PID directly to an internal kill function
3. The kill function calls `ZwOpenProcess` with `PROCESS_ALL_ACCESS` (`0x1FFFFF`) — **without `OBJ_FORCE_ACCESS_CHECK`**
4. Immediately calls `ZwTerminateProcess` on the obtained handle

Because `ZwOpenProcess` executes in kernel context without `OBJ_FORCE_ACCESS_CHECK`, it bypasses all user-mode process protections including Protected Process Light (PPL) and anti-tamper mechanisms used by security products.

### IOCTL Code Breakdown

```
IOCTL = 0x002248DC

DeviceType  = (0x002248DC >> 16) & 0xFFFF = 0x0022 (FILE_DEVICE_UNKNOWN)
Function    = (0x002248DC >> 2)  & 0xFFF  = 0x237  (custom)
Method      = 0x002248DC & 0x3            = 0x0    (METHOD_BUFFERED)
Access      = (0x002248DC >> 14) & 0x3    = 0x0    (FILE_ANY_ACCESS)
```

## Build

```
"C:\Program Files\Microsoft Visual Studio\<version>\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcpoc.c /link /OUT:poc.exe /SUBSYSTEM:CONSOLE /MACHINE:x64
```

## Usage
Requires Administrator privileges. The driver must be loaded:

```
sc create HwAudio type= kernel binPath= C:\path\to\HWAudioOs2Ec.sys
sc start HwAudio
```

```
poc.exe <PID>
```

### Safe Test

```
1. Open notepad.exe
2. Find PID:  tasklist | findstr notepad
3. Run:       poc.exe <notepad_pid>
```

## References

This PoC is based entirely on publicly available information. The vulnerability was first publicly documented by Huntress on March 19, 2026:

- **Huntress Blog (primary source):** [From W-2 to BYOVD: How a Tax Search Leads to Kernel-Mode AV/EDR Kill](https://www.huntress.com/blog/w2-malvertising-to-kernel-mode-edr-kill) — Anna Pham, Huntress, 2026-03-19
- **YARA Rules:** [FatMalloc](https://github.com/RussianPanda95/Yara-Rules/blob/main/FatMalloc/win_mal_fatmalloc.yar) / [HwAudKiller](https://github.com/RussianPanda95/Yara-Rules/blob/main/FatMalloc/HwAudKiller.yar)
- **LOLDrivers:** [https://www.loldrivers.io/](https://www.loldrivers.io/) — driver was not listed as of original publication

<!--
## Recommended Mitigations
**For driver vendors:**
1. **Delete the IOCTL entirely** — an audio driver has no legitimate need for process termination
2. If deletion is not possible, add `OBJ_FORCE_ACCESS_CHECK` to `ObjectAttributes` in `ZwOpenProcess` calls
3. Change `FILE_ANY_ACCESS` to `FILE_WRITE_ACCESS` (defense-in-depth only — easily bypassed by local admin)
-->

**For defenders:**

- Block the driver hash via WDAC / Microsoft recommended driver block list
- Monitor kernel driver service creation from non-standard paths (`%TEMP%`) — Sysmon Event ID 6, 7045
- Enable HVCI (Hypervisor-Protected Code Integrity)
- Deploy the Huntress YARA rules linked above

## Disclaimer

This tool is provided for **authorized security testing and research purposes only**. Use only in environments you own or have explicit written permission to test. The author is not responsible for any misuse or damage caused by this tool.

## Author
2BCEB1 (skybreaker)

# HWAudioOs2Ec-Killer_PoC
Huntressが公開したインシデントレポートで使用されていたBYOVDに関する調査
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

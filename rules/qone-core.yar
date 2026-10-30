/*
  Qone Security 内置 YARA 规则
  ------------------------------------------------------------------
  作者：Sun2530
  许可证：MIT（与本项目一致）
  说明：本文件中的规则为本项目自行编写，未复制第三方规则集。
        如需更强的覆盖，可把 MIT 许可的规则集（例如 ReversingLabs 的
        reversinglabs-yara-rules）放进 %LOCALAPPDATA%\Qone Security\yara\，
        程序会自动加载，那份规则集的版权与许可由它自己的 LICENSE 约束。

  写规则的取舍：宁可少报，不可乱报。所以每条规则都要求「两个以上
  互不相关的信号同时出现」，而不是单凭一个字符串就判定。
*/

import "pe"

/*
  全局规则：本文件（以及任何把本文件内容原样保存下来的副本）不是检测对象。
  规则文件里必然写着它自己要匹配的那些字符串，不挡这一下，扫描器会把自己的
  规则文件一条不漏地全报出来——实机上就是这么自咬一口的。
  global 规则的条件会对同文件内所有规则生效。
  private 让它自己不出现在命中结果里——否则每个文件都会"命中"它。
*/
private global rule Qone_Not_Rule_Source
{
    strings:
        $self = "Qone Security 内置 YARA 规则"
    condition:
        not $self
}

rule EICAR_Test_File
{
    meta:
        description = "EICAR 反病毒测试文件（本身无害，用于验证检测链路是否通畅）"
        severity = "high"
        family = "test"
        author = "Sun2530"
        license = "MIT"
    strings:
        $e = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"
    condition:
        $e
}

rule Process_Injection_API_Triad
{
    meta:
        description = "同时导入远程注入三件套：分配、写入、远程执行"
        severity = "high"
        family = "backdoor"
        author = "Sun2530"
        license = "MIT"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 3MB and
        /* 排除有正规签名的程序：微信小程序运行时（WeChatAppEx）这类
           带沙箱的合法软件确实会用这三件套，签过名的就不该按恶意算。
           这一条是实机跑出来的误报，不是理论顾虑。 */
        pe.number_of_signatures == 0 and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        pe.imports(/kernel32\.dll|kernelbase\.dll/i, /CreateRemoteThread|NtCreateThreadEx/i)
}

rule Suspicious_PowerShell_Download_Cradle
{
    meta:
        description = "PowerShell 下载执行（DownloadString + IEX 或隐藏窗口 + 编码命令）"
        severity = "high"
        family = "downloader"
        author = "Sun2530"
        license = "MIT"
    strings:
        $ps  = "powershell" nocase
        $hid = "-w hidden" nocase
        $enc = "-enc" nocase
        $dl  = "DownloadString" nocase
        /* IEX 有写成一坨的 iex(...)，也有带空格的 IEX (New-Object ...)，
           字面量抓不全，用正则收口 */
        $iex = /iex\s*\(/i
        $ive = "Invoke-Expression" nocase
        $b64 = "FromBase64String" nocase
    condition:
        filesize < 2MB and
        /* 有签名的程序不按这个字符串规则报——微软不少系统 DLL
           （如 Windows.ApplicationModel.Store.dll）里就常驻这些字符串，
           pe.number_of_signatures 能识别目录签名，把它们排除掉 */
        pe.number_of_signatures == 0 and
        (
            ($dl and any of ($iex, $ive)) or
            ($ps and $hid and $enc) or
            ($b64 and any of ($iex, $ive))
        )
}

rule Base64_Encoded_PE_Loader
{
    meta:
        description = "脚本里内嵌 Base64 编码的 PE 头，典型的内存加载器"
        severity = "high"
        family = "downloader"
        author = "Sun2530"
        license = "MIT"
    strings:
        $mz = "TVqQAAMAAAAEAAAA"
        $s1 = "powershell" nocase
        $s2 = "wscript" nocase
        $s3 = "eval" nocase
        $s4 = "ActiveXObject" nocase
    condition:
        filesize < 4MB and
        pe.number_of_signatures == 0 and
        $mz and any of ($s*)
}

rule Credential_Dumping_Strings
{
    meta:
        description = "凭据导出工具的典型命令串"
        severity = "high"
        family = "stealer"
        author = "Sun2530"
        license = "MIT"
    strings:
        $a1 = "sekurlsa::logonpasswords" nocase
        $a2 = "lsadump::sam" nocase
        $a3 = "mimikatz" nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 6MB and
        (any of ($a1, $a2) or $a3)
}

rule Remote_Access_Trojan_Strings
{
    meta:
        description = "常见远程控制木马家族的特征串"
        severity = "high"
        family = "rat"
        author = "Sun2530"
        license = "MIT"
    strings:
        $r1 = "AsyncRAT" nocase
        $r2 = "QuasarRAT" nocase
        $r3 = "njRAT" nocase
        $r4 = "Remcos" nocase
        $r5 = "DarkComet" nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 8MB and
        any of ($r*)
}

rule Ransomware_Note_Text
{
    meta:
        description = "勒索信正文特征"
        severity = "high"
        family = "ransom"
        author = "Sun2530"
        license = "MIT"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "all your files are encrypted" nocase
        $c = "files have been encrypted" nocase
        $d = "bitcoin" nocase
        $e = "decrypt" nocase
    condition:
        filesize < 200KB and
        (any of ($a, $b, $c)) and
        any of ($d, $e)
}

rule Worm_Panda_Burning_Incense
{
    meta:
        description = "熊猫烧香 / 武汉男生 / 威金（Worm.WhBoy、Worm.Win32.Fujack）家族特征串"
        severity = "high"
        family = "worm"
        author = "Sun2530"
        license = "MIT"
        reference = "2006 李俊编写，感染 EXE/SCR/PIF/COM 与网页文件，替换图标为烧香熊猫"
    strings:
        $xboy  = "xboy" nocase
        $whboy = "whboy" nocase
        /* 「武汉男生」「感染下载者」在样本里是 GBK（ANSI）编码，YARA 的
           中文直写默认按 UTF-8 匹配，老样本对不上。这里用十六进制字节序列
           同时覆盖 GBK 与 UTF-8 两种编码，避免漏报。 */
        $cn1 = { CE E4 BA BA C4 D0 C9 FA }                    // 武汉男生 GBK
        $cn2 = { B8 D0 C8 BE CF C2 D4 D8 D5 DF }              // 感染下载者 GBK
        $cn3 = { E6 AD A6 E6 B1 89 E7 94 B7 E7 94 9F }        // 武汉男生 UTF-8
        $cn4 = { E6 84 9F E6 9F 93 E4 B8 8B E8 BD BD E8 80 85 } // 感染下载者 UTF-8
        $fj   = "fujack" nocase
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            (any of ($xboy, $whboy) and any of ($cn1, $cn2, $cn3, $cn4)) or
            $fj
        )
}

rule Obfuscated_Script_Loader
{
    meta:
        description = "脚本经过编码混淆后再动态执行"
        severity = "medium"
        family = "script"
        author = "Sun2530"
        license = "MIT"
    strings:
        $a1 = "FromBase64String" nocase
        $a2 = "Invoke-Expression" nocase
        $a3 = "[char]" nocase
        $a4 = "-join" nocase
    condition:
        filesize < 1MB and
        pe.number_of_signatures == 0 and
        $a1 and any of ($a2, $a3, $a4)
}

rule Packed_PE_With_Network_Download
{
    meta:
        description = "加壳程序同时具备网络下载能力"
        severity = "medium"
        family = "downloader"
        author = "Sun2530"
        license = "MIT"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 4MB and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].name == ".upx0" or
            pe.sections[i].name == ".aspack" or
            pe.sections[i].name == ".mpress1"
        ) and
        pe.imports(/urlmon\.dll|wininet\.dll|winhttp\.dll/i, /URLDownloadToFile|InternetOpen|WinHttpOpen/i)
}

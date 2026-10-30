"""
PE 静态启发式 —— 不跑样本，只看结构。

这里所有信号都是「很多正常程序也会沾一点、但凑齐了很难解释」的类型，
所以按权重累加、设阈值，而不是单条命中就报警。真实杀软也是这么干的：
单看「有可写可执行节区」，一堆运行时生成代码的语言（Go、部分加壳安装器）都中；
再加上「导入表里有远程注入三件套」，就没法解释了。

阈值：>=70 判危险，>=45 判可疑。签名有效的文件扣 35 分——
有正规代码签名的程序被误判，用户会直接卸载我们，这个代价比漏一点高。
"""
import math
import os

try:
    import pefile
except Exception:            # 打包环境缺了也不该让整个程序起不来
    pefile = None

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# 加壳器常用的节区名
PACKER_SECTIONS = {
    "upx0", "upx1", "upx2", ".aspack", ".adata", ".nsp0", ".nsp1", ".nsp2",
    ".petite", ".mpress1", ".mpress2", ".themida", ".vmp0", ".vmp1",
    ".enigma1", ".enigma2", ".y0da", ".perplex", ".wwpack", ".packed",
}

# 远程注入三件套：分配内存 → 写入 → 远程执行
INJECT_APIS = {"virtualallocex", "virtualprotectex", "writeprocessmemory",
               "createremotethread", "ntcreatethreadex", "queueuserapc",
               "setthreadcontext", "ntunmapviewofsection"}
# 键盘记录
KEYLOG_APIS = {"setwindowshookexa", "setwindowshookexw",
               "getasynckeystate", "getkeyboardstate", "getforegroundwindow"}
# 下载后执行
NET_APIS = {"urldownloadtofilea", "urldownloadtofilew", "internetopenurla",
            "internetopenurlw", "internetreadfile", "winhttpopen"}
EXEC_APIS = {"winexec", "shellexecutea", "shellexecutew", "createprocessa",
             "createprocessw"}

DANGER, WARN = 70, 45


def _entropy(data: bytes) -> float:
    """香农熵。用 bytes.count 走 C 层统计，256 次扫描，
    比逐字节 for 循环快两个数量级——pefile 自带的 get_entropy()
    就是逐字节算的，在 20 MB 的 DLL 上要 1.5 秒。
    熵只用来判断「是否接近随机」，采样 256 KB 足够得出结论。"""
    data = data[:262144]
    n = len(data)
    if not n:
        return 0.0
    e = 0.0
    for i in range(256):
        c = data.count(i)
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e


def available() -> bool:
    return pefile is not None


# 微软系统目录：这些目录里的文件由微软用「目录签名（catalog）」统一签名，
# PE 文件里往往没有嵌入证书，常规的 Authenticode 检查认不出来，会被误判成
# 未签名。而系统资源文件（.dll.mun）天然高熵 + 入口点异常，几乎条条踩中
# 启发式特征。微软自己签名并维护的系统文件，不该由我们静态启发式去报警。
_SYS_DIRS = (
    "\\windows\\systemresources\\",
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
)


def _is_microsoft_system(path: str) -> bool:
    p = os.path.normcase(os.path.normpath(path))
    return any(d in p for d in _SYS_DIRS)


def analyze(path: str, size: int):
    """返回 {score, reasons, verdict} 或 None（不是 PE / 解析失败 / 太大）。"""
    if pefile is None or size <= 0 or size > 48 * 1024 * 1024:
        return None

    # 微软系统目录下的文件：启发式直接放行，交给哈希 / YARA / clamd 去认。
    # 这是实机跑出来的教训——SystemResources 里的 .dll.mun 被批量误报成可疑。
    if _is_microsoft_system(path):
        return None

    try:
        pe = pefile.PE(path, fast_load=True)
    except Exception:
        return None

    try:
        return _score(pe, path, size)
    except Exception:
        return None
    finally:
        try:
            pe.close()
        except Exception:
            pass


def _score(pe, path: str, size: int) -> dict:
    score = 0
    reasons = []

    sections = list(pe.sections or [])
    sec_names = []
    for s in sections:
        try:
            sec_names.append(s.Name.rstrip(b"\x00").decode("latin-1").lower())
        except Exception:
            sec_names.append("")

    # ---- 加壳特征 ----
    hit = PACKER_SECTIONS.intersection(sec_names)
    if hit:
        score += 25
        reasons.append("加壳节区 " + hit.pop())

    # ---- 可写且可执行 ----
    wx = 0
    for s in sections:
        ch = s.Characteristics
        if (ch & IMAGE_SCN_MEM_EXECUTE) and (ch & IMAGE_SCN_MEM_WRITE):
            wx += 1
    if wx:
        score += 25
        reasons.append("可写可执行节区")

    # ---- 高熵节区（加密/压缩） ----
    hot = 0
    for sec in sections:
        try:
            if sec.SizeOfRawData > 65536:
                raw = pe.get_data(sec.PointerToRawData,
                                  min(sec.SizeOfRawData, 262144))
                if _entropy(raw) >= 7.2:
                    hot += 1
        except Exception:
            pass
    if hot:
        score += 18
        reasons.append("高熵节区")

    # ---- 入口点不在任何节区里 ----
    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    inside = False
    for s in sections:
        va = s.VirtualAddress
        vs = max(s.Misc_VirtualSize, s.SizeOfRawData)
        if va <= ep < va + vs:
            inside = True
            break
    if sections and not inside:
        score += 22
        reasons.append("入口点位于节区之外")

    # ---- 导入表 ----
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
    except Exception:
        pass

    imports = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        for imp in entry.imports:
            if imp.name:
                try:
                    imports.add(imp.name.decode("latin-1").lower())
                except Exception:
                    pass

    # .NET 程序集：托管代码几乎没有导入表，下面这些规则对它不适用
    try:
        com = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        is_dotnet = bool(com.VirtualAddress and com.Size)
    except Exception:
        is_dotnet = False

    if not is_dotnet:
        inj = imports & INJECT_APIS
        if len(inj) >= 3:
            score += 35
            reasons.append("远程注入 API")
            if wx:
                score += 20      # 注入三件套 + 可写可执行，基本没有正当用法
        elif len(inj) == 2:
            score += 12

        if len(imports & KEYLOG_APIS) >= 2:
            score += 20
            reasons.append("键盘记录 API")

        if (imports & NET_APIS) and (imports & EXEC_APIS):
            score += 15
            reasons.append("下载并执行")

        if not imports:
            score += 10
            reasons.append("无导入表")

    # ---- TLS 回调：正常程序少用，恶意程序常用来抢在入口点之前跑 ----
    if getattr(pe, "DIRECTORY_ENTRY_TLS", None):
        score += 8
        reasons.append("TLS 回调")

    # ---- 校验和 ----
    # 这里原本算 generate_checksum()，纯 Python 逐 4 字节累加，21 MB 的 DLL 要 5 秒。
    # 它只值 4 分（正常程序校验和不对很常见，改过的程序也常懒得修），
    # 为这点信号让整个扫描慢一个数量级，不划算。直接不算。

    # ---- 有正规签名就大幅扣分 ----
    if score >= WARN:
        try:
            import procwatch
            if procwatch.has_signature(path):
                score -= 35
                reasons.append("代码签名有效")
        except Exception:
            pass

    score = max(0, min(100, score))
    verdict = "danger" if score >= DANGER else ("warn" if score >= WARN else "clean")
    return {"score": score, "reasons": reasons, "verdict": verdict}

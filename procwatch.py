"""
进程启动日志采集（UI 演示用）

只做两件事：
1. 用 Toolhelp 快照 + GetProcessTimes 找出「最近启动」的进程
2. 用路径 + 数字签名，给每条打一个标记：系统 / 应用 / 正常 / 可疑 / 危险

不阻断、不清除、不做实时防护，纯读取。
"""
import ctypes
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from ctypes import wintypes as wt

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
wintrust = ctypes.WinDLL("wintrust", use_last_error=True)
advapi = ctypes.WinDLL("advapi32", use_last_error=True)

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
MAX_PATH_LONG = 32768


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wt.DWORD),
        ("cntUsage", wt.DWORD),
        ("th32ProcessID", wt.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wt.DWORD),
        ("cntThreads", wt.DWORD),
        ("th32ParentProcessID", wt.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wt.DWORD),
        ("szExeFile", wt.WCHAR * 260),
    ]


k32.CreateToolhelp32Snapshot.restype = wt.HANDLE
k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
k32.Process32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.Process32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
k32.OpenProcess.restype = wt.HANDLE
k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
k32.CloseHandle.argtypes = [wt.HANDLE]
k32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD,
                                           wt.LPWSTR, ctypes.POINTER(wt.DWORD)]


def _creation_time(pid):
    """返回进程创建时间（Unix 秒）。拿不到就返回 None。"""
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return None
    try:
        ct, et, kt, ut = (wt.FILETIME() for _ in range(4))
        if not k32.GetProcessTimes(h, ctypes.byref(ct), ctypes.byref(et),
                                   ctypes.byref(kt), ctypes.byref(ut)):
            return None
        v = (ct.dwHighDateTime << 32) | ct.dwLowDateTime
        if not v:
            return None
        # FILETIME: 1601-01-01 起的 100ns，转 Unix 秒
        return v / 1e7 - 11644473600
    finally:
        k32.CloseHandle(h)


def _image_path(pid):
    h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not h:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(MAX_PATH_LONG)
        size = wt.DWORD(MAX_PATH_LONG)
        if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return buf.value
        return ""
    finally:
        k32.CloseHandle(h)


# ---------------- 数字签名 ----------------

class _GUID(ctypes.Structure):
    _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD), ("Data3", wt.WORD),
                ("Data4", ctypes.c_ubyte * 8)]


class _WINTRUST_FILE_INFO(ctypes.Structure):
    _fields_ = [("cbStruct", wt.DWORD), ("pcwszFilePath", wt.LPCWSTR),
                ("hFile", wt.HANDLE), ("pgKnownSubject", ctypes.c_void_p)]


class _WINTRUST_DATA(ctypes.Structure):
    _fields_ = [
        ("cbStruct", wt.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", wt.DWORD),
        ("fdwRevocationChecks", wt.DWORD),
        ("dwUnionChoice", wt.DWORD),
        ("pFile", ctypes.POINTER(_WINTRUST_FILE_INFO)),
        ("dwStateAction", wt.DWORD),
        ("hWVTStateData", wt.HANDLE),
        ("pwszURLReference", wt.LPCWSTR),
        ("dwProvFlags", wt.DWORD),
        ("dwUIContext", wt.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


_ACTION_GENERIC_VERIFY_V2 = _GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE))

WTD_UI_NONE = 2
WTD_REVOKE_NONE = 0
WTD_CHOICE_FILE = 1
WTD_STATEACTION_VERIFY = 1
WTD_STATEACTION_CLOSE = 2
WTD_REVOCATION_CHECK_NONE = 0x10
WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000

_sig_lock = threading.Lock()
_sig_cache = {}


def has_signature(path: str) -> bool:
    """检查 PE 是否带有效的 Authenticode 签名（不联网、不查吊销，够快）。

    只查**嵌入签名**。微软不少系统文件走目录签名（catalog），PE 里没有证书，
    这里会返回 False —— 所以系统目录 / Program Files 一律先按路径归类，
    不参与签名判定，避免把 cmd.exe 这类误标成无签名。
    """
    if not path:
        return False
    # WinVerifyTrust 只认反斜杠路径，正斜杠会直接判失败
    path = os.path.normpath(path)

    # 微软系统目录下的文件走「目录签名」，WinVerifyTrust 查嵌入证书必然 False，
    # 但它们确实是微软签过名的。这里直接按「有签名」处理，
    # 否则 peheur 的「签名有效扣 35 分」对这些文件形同虚设，批量误报。
    p = path.lower()
    if p.startswith("c:\\windows\\"):
        return True

    key = p
    with _sig_lock:
        if key in _sig_cache:
            return _sig_cache[key]
    result = False
    try:
        if os.path.isfile(path):
            fi = _WINTRUST_FILE_INFO()
            fi.cbStruct = ctypes.sizeof(_WINTRUST_FILE_INFO)
            fi.pcwszFilePath = path
            fi.hFile = None
            fi.pgKnownSubject = None

            wd = _WINTRUST_DATA()
            wd.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
            wd.pPolicyCallbackData = None
            wd.pSIPClientData = None
            wd.dwUIChoice = WTD_UI_NONE
            wd.fdwRevocationChecks = WTD_REVOKE_NONE
            wd.dwUnionChoice = WTD_CHOICE_FILE
            wd.pFile = ctypes.pointer(fi)
            wd.dwStateAction = WTD_STATEACTION_VERIFY
            wd.hWVTStateData = None
            wd.pwszURLReference = None
            wd.dwProvFlags = WTD_REVOCATION_CHECK_NONE | WTD_CACHE_ONLY_URL_RETRIEVAL
            wd.dwUIContext = 0
            wd.pSignatureSettings = None

            res = wintrust.WinVerifyTrust(
                None, ctypes.byref(_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wd))
            result = (res == 0)

            wd.dwStateAction = WTD_STATEACTION_CLOSE
            wintrust.WinVerifyTrust(
                None, ctypes.byref(_ACTION_GENERIC_VERIFY_V2), ctypes.byref(wd))
    except Exception:
        result = False
    with _sig_lock:
        _sig_cache[key] = result
    return result


# ---------------- 分类 ----------------

KIND_LABEL = {
    "trusted": "可信",
    "sys": "系统",
    "app": "应用",
    "normal": "正常",
    "warn": "可疑",
    "danger": "危险",
}

# ---- 可信应用白名单 ----
# 自己做的软件，用户明确授权为可信。可信优先级最高：即使它从临时目录、
# 下载目录启动，也不升格成可疑/危险。
#
# BUILTIN_TRUSTED 是出厂内置项，界面上不可移除；TRUSTED_STEMS 是运行时集合，
# 会在启动时把用户自定义项也并进来。分开存是为了「删干净」——否则用户删了
# 自定义项，重置后又会因为它在内置集合里冒出来。
BUILTIN_TRUSTED = {
    "hitouch",          # Hitouch（Electron，dev.hitouch.app）
    "qone security",    # 本软件自身
}
TRUSTED_STEMS = set(BUILTIN_TRUSTED)

# 界面上显示的名字（进程名全小写不好看）
TRUSTED_DISPLAY = {
    "hitouch": "Hitouch",
    "qone security": "Qone Security",
}

# 只额外放行「名字-版本号」这种打包形态，例如 Hitouch-0.1.0-portable。
# 绝不能用宽松前缀（startswith("hitouch_") 之类）——恶意程序改名叫
# hitouch_update.exe 就能白嫖信任，这是白名单最经典的绕过手法。
_VERSION_SUFFIX = re.compile(r"-\d[\w.\-]*$")


def norm_stem(name: str) -> str:
    """把用户输入/进程名归一成白名单里存的形式：小写、去掉 .exe。"""
    n = (name or "").strip().lower()
    if n.endswith(".exe"):
        n = n[:-4]
    return n.strip()


def _is_trusted(name: str, path: str = "") -> bool:
    stem = norm_stem(name)
    for t in TRUSTED_STEMS:
        if stem == t:
            return True
        if stem.startswith(t) and _VERSION_SUFFIX.fullmatch(stem[len(t):]):
            return True
    return False

_TEMP_MARKERS = ("\\appdata\\local\\temp\\",)
_DL_MARKERS = ("\\downloads\\",)

# AppData\Local\Programs 是标准的「用户级安装目录」（VS Code / Python / Electron 应用
# 都装这里），算应用而不是可疑 —— 否则一堆正经开发工具会被标红。
_APP_MARKERS = ("\\program files", "\\programdata\\",
                "\\appdata\\local\\programs\\")


def classify(path: str, name: str = "") -> str:
    """返回 trusted / sys / app / normal / warn / danger。路径拿不到的不进列表。

    判定顺序是「先看白名单，再看位置，最后看签名」：
      - 白名单命中                          -> 可信
      - Windows 目录                        -> 系统
      - Program Files / Programs / ProgramData -> 应用
      - 临时目录(Temp)                      -> 无签名=危险，有签名=可疑
      - 下载目录(Downloads)                 -> 无签名=可疑，有签名=正常
      - 其余位置                            -> 正常

    「未签名」本身不算可疑 —— Python、Git 这类正经工具官方就不签 EXE，
    全标黄会让面板变成一片警报色，反而看不出真正需要警惕的东西。
    只有从临时目录、下载目录启动的未知程序才值得提示。
    """
    # 白名单最优先：用户授权过的程序，位置再可疑也不报警
    if _is_trusted(name, path):
        return "trusted"

    # 统一分隔符，否则 c:/windows 会漏判成用户目录
    p = path.replace("/", "\\").lower()
    if not p:
        return ""
    if p.startswith("c:\\windows\\"):
        return "sys"
    if any(m in p for m in _APP_MARKERS):
        return "app"
    if any(m in p for m in _TEMP_MARKERS):
        return "danger" if not has_signature(path) else "warn"
    if any(m in p for m in _DL_MARKERS):
        return "warn" if not has_signature(path) else "normal"
    return "normal"


# ---------------- 采集器 ----------------

class Watch:
    """轮询进程快照，维护一份「最近启动」列表（最新在前）。"""

    def __init__(self, keep: int = 24, interval: float = 1.5):
        self.keep = keep
        self.interval = interval
        self._lock = threading.Lock()
        self._items = []          # [{"id","t","name","kind","pid"}]
        self._seen = set()        # (pid, create_time)
        self._stop = threading.Event()
        self._started = False
        # 设置页会改这两个：暂停采集 / 是否收系统进程
        self.paused = False
        self.show_sys = True

    # -- 快照 --
    @staticmethod
    def _snapshot():
        rows = []
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        if snap == INVALID_HANDLE_VALUE:
            return rows
        try:
            pe = PROCESSENTRY32W()
            pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
            ok = k32.Process32FirstW(snap, ctypes.byref(pe))
            while ok:
                pid = int(pe.th32ProcessID)
                if pid > 4:
                    rows.append((pid, pe.szExeFile))
                ok = k32.Process32NextW(snap, ctypes.byref(pe))
        finally:
            k32.CloseHandle(snap)
        return rows

    def _collect(self, limit: int = 30):
        """只给「最近启动的 limit 个」查路径和签名。

        全量扫（本机 200+ 进程）光签名校验就要 2.6 秒，而面板最多显示 5 条，
        没必要为看不见的进程付这个代价。
        """
        raw = []
        for pid, name in self._snapshot():
            ct = _creation_time(pid)
            if ct is None:
                continue
            key = (pid, round(ct, 3))
            if key in self._seen:
                continue
            raw.append((ct, pid, name, key))

        raw.sort(key=lambda r: r[0], reverse=True)
        cand = []
        for ct, pid, name, key in raw[:limit]:
            self._seen.add(key)
            cand.append((ct, pid, name, _image_path(pid)))
        if not cand:
            return []

        # 签名校验走系统证书链，单个约 200ms，串行会拖到 2 秒以上，这里并发做
        kinds = [classify(c[3], c[2]) for c in cand] if len(cand) == 1 else None
        if kinds is None:
            with ThreadPoolExecutor(max_workers=8) as ex:
                kinds = list(ex.map(lambda c: classify(c[3], c[2]), cand))

        out = []
        for (ct, pid, name, path), kind in zip(cand, kinds):
            if not kind:
                continue
            out.append({
                "id": f"{pid}-{int(ct)}",
                "ts": ct,
                "t": time.strftime("%H:%M", time.localtime(ct)),
                "name": name,
                "kind": kind,
                "pid": pid,
                "path": path,        # 可执行文件路径，供实时防护做真实检测
            })
        return out

    def seed(self, minutes: int = 30):
        """启动时先捞一批刚启动的，否则面板空着没内容看。"""
        rows = self._collect()
        cutoff = time.time() - minutes * 60
        with self._lock:
            for it in sorted(rows, key=lambda r: r["ts"], reverse=True):
                if it["ts"] >= cutoff:
                    self._items.append(it)
            self._items.sort(key=lambda r: r["ts"], reverse=True)
            del self._items[self.keep:]
            self._started = True

    def _loop(self):
        while not self._stop.wait(self.interval):
            if self.paused:
                continue
            try:
                new = self._collect()
            except Exception:
                continue
            if not new:
                continue
            with self._lock:
                have = {i["id"] for i in self._items}
                for it in new:
                    if it["id"] not in have:
                        self._items.insert(0, it)
                self._items.sort(key=lambda r: r["ts"], reverse=True)
                del self._items[self.keep:]

    def start(self):
        # 首次采样要查签名，可能耗时几百毫秒，扔后台别卡窗口显示
        threading.Thread(target=self._boot, daemon=True).start()

    def clear(self):
        """清空已记录的条目。

        只清 _items，**不清 _seen**：_seen 记的是「这些进程已经计数过了」，
        清掉的话下一轮会把当前所有存活进程当成新启动的重新灌进来，
        用户会看到列表刚清空又瞬间填满。
        """
        with self._lock:
            self._items.clear()

    def _boot(self):
        try:
            self.seed()
        except Exception:
            pass
        self._loop()

    def latest(self, n: int = 5):
        """同一程序只留最新一条 —— 面板要的是「哪几个程序刚起来」，不是逐条流水。"""
        # WebView2 的渲染子进程是宿主实现细节，对用户没有意义
        skip = {"msedgewebview2.exe"}
        with self._lock:
            items = list(self._items)
        out, seen = [], set()
        for it in items:
            name = it["name"].lower()
            if name in skip or name in seen:
                continue
            # 设置里关掉「显示系统进程」后，C:\Windows 下的就不进日志了
            if not self.show_sys and it["kind"] == "sys":
                continue
            seen.add(name)
            # 前端只要这几个字段，省得传一堆
            out.append({"id": it["id"], "t": it["t"],
                        "name": it["name"], "kind": it["kind"],
                        "pid": it.get("pid"), "path": it.get("path", "")})
            if len(out) >= n:
                break
        return out

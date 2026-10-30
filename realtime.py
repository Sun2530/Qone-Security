"""
实时防护：文件落地监控 + 进程启动防御。

文件落地：用 ReadDirectoryChangesW 监控关键目录（Temp、下载、桌面、启动目录），
新文件写完后立刻过一遍检测管线（复用 scanner.Job 的单文件判定），命中即产生告警。

进程启动：复用 procwatch 的采集与分类。只对「可疑/危险」级别的新进程告警，
询问用户是否是本人允许的——本人放行，非本人拦截（结束进程）。

两个监控都不自动处置，只把决策交回给用户，符合「弹窗询问」的定位。
"""
import os
import re
import threading
import time
import ctypes
from ctypes import wintypes as wt

import config
import scanner
import signatures
import yrules
import peheur
import clamdc
import threatcat

# ---------------- 检测：复用 scanner 的单文件判定 ----------------

class _Detector:
    """一份轻量检测上下文，等价于 scanner.Job 里那套管线，但独立于扫描任务。

    不依赖 scanner._CURRENT，扫描和实时防护可以同时存在互不干扰。
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._loaded = False
        self.yara = None
        self.use_yara = True
        self.use_heur = True
        self.use_clamd = False
        self.clamd_addr = "127.0.0.1:3310"

    def reload(self):
        """按当前设置重载引擎开关。首次或设置变更时调用。"""
        data = config.load()
        self.use_yara = bool(data.get("engine_yara", True))
        self.use_heur = bool(data.get("engine_heur", True))
        self.use_clamd = bool(data.get("engine_clamd", False))
        self.clamd_addr = data.get("clamd_addr", "127.0.0.1:3310")
        signatures.init()
        if self.use_yara and yrules.available():
            try:
                eng = yrules.load_engine()
                self.yara = eng if eng.ready else None
            except Exception:
                self.yara = None
        self._loaded = True

    def scan_file(self, path):
        """判定单个文件。返回命中 dict 或 None。"""
        if not self._loaded:
            self.reload()
        try:
            size = os.path.getsize(path)
        except OSError:
            return None
        if size <= 0 or size > scanner.HASH_MAX:
            return None

        sha, md5, is_pe = signatures.digests_of(path, size)
        if not sha:
            return None

        reasons, engines = [], []
        verdict, score, fam, tname = "", 0, "", ""

        name = signatures.lookup(sha, md5)
        if name:
            reasons.append(f"命中已知样本 · {name}")
            engines.append("哈希")
            verdict, score, tname = "danger", 100, name

        if not verdict and self.yara and 0 < size <= scanner.YARA_MAX:
            hits = self.yara.match(path)
            if hits:
                worst = "danger" if any(h["severity"] == "high" for h in hits) else "warn"
                for h in hits[:3]:
                    reasons.append(h["rule"] + (f" · {h['desc']}" if h["desc"] else ""))
                    if not fam and h.get("family"):
                        fam = h["family"]
                engines.append("YARA")
                verdict, score = worst, (90 if worst == "danger" else 55)

        if not verdict and self.use_heur and is_pe and 0 < size <= scanner.PE_MAX:
            r = peheur.analyze(path, size)
            if r and r["verdict"] != "clean":
                verdict, score = r["verdict"], r["score"]
                reasons.extend(r["reasons"])
                engines.append("启发式")

        if not verdict and self.use_clamd:
            host, _, port = self.clamd_addr.partition(":")
            try:
                res = clamdc.scan(path, host or "127.0.0.1", int(port or 3310))
                if res["status"] == "infected":
                    verdict, score, tname = "danger", 100, res["name"]
                    reasons.append(res["name"])
                    engines.append("clamd")
            except Exception:
                pass

        if not verdict:
            return None
        return {
            "p": path,
            "n": os.path.basename(path),
            "v": verdict,
            "s": score,
            "why": reasons,
            "e": "、".join(engines),
            "fam": threatcat.classify(family=fam, text=" ".join(reasons),
                                      name=tname, verdict=verdict),
            "t": int(time.time()),
        }


# ---------------- 目录监控（ReadDirectoryChangesW） ----------------

FILE_NOTIFY_CHANGE_FILE_NAME = 0x0001
FILE_NOTIFY_CHANGE_DIR_NAME = 0x0002
FILE_NOTIFY_CHANGE_SIZE = 0x0008
FILE_NOTIFY_CHANGE_LAST_WRITE = 0x0010
FILE_LIST_DIRECTORY = 0x0001
FILE_SHARE_READ = 0x0001
FILE_SHARE_WRITE = 0x0002
FILE_SHARE_DELETE = 0x0004
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
FILE_FLAG_OVERLAPPED = 0x40000000
INFINITE = 0xFFFFFFFF
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 0x00000102
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class _OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_size_t),
        ("InternalHigh", ctypes.c_size_t),
        ("Offset", wt.DWORD),
        ("OffsetHigh", wt.DWORD),
        ("hEvent", wt.HANDLE),
    ]


# 正确声明 Win32 函数原型。不声明 argtypes 时，ctypes 会把指针按 C int 传，
# 在 64 位下高位被截断，直接段错误——这是 ReadDirectoryChangesW 最常见的坑。
_k32 = ctypes.WinDLL("kernel32", use_last_error=True)
_k32.CreateFileW.restype = wt.HANDLE
_k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, wt.LPVOID,
                             wt.DWORD, wt.DWORD, wt.HANDLE]
_k32.ReadDirectoryChangesW.restype = wt.BOOL
_k32.ReadDirectoryChangesW.argtypes = [
    wt.HANDLE, wt.LPVOID, wt.DWORD, wt.BOOL, wt.DWORD,
    ctypes.POINTER(wt.DWORD), ctypes.POINTER(_OVERLAPPED), wt.LPVOID]
_k32.WaitForSingleObject.restype = wt.DWORD
_k32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
_k32.CreateEventW.restype = wt.HANDLE
_k32.CreateEventW.argtypes = [wt.LPVOID, wt.BOOL, wt.BOOL, wt.LPCWSTR]
_k32.ResetEvent.restype = wt.BOOL
_k32.ResetEvent.argtypes = [wt.HANDLE]
_k32.CancelIo.restype = wt.BOOL
_k32.CancelIo.argtypes = [wt.HANDLE]
_k32.CloseHandle.restype = wt.BOOL
_k32.CloseHandle.argtypes = [wt.HANDLE]

_ACTION_NAME = {
    1: "新增", 2: "删除", 3: "修改", 4: "重命名旧名", 5: "重命名新名",
}

# 只监控这些目录。桌面/下载/Temp 是「文件落地」的高发地，启动目录是持久化重灾区。
def _watch_roots():
    """返回要监控的目录列表（绝对路径、去重）。"""
    out = []
    temp = os.environ.get("TEMP") or os.environ.get("TMP") or ""
    if temp:
        out.append(temp)
    home = os.environ.get("USERPROFILE") or ""
    if home:
        for sub in ("Downloads", "Desktop"):
            p = os.path.join(home, sub)
            if os.path.isdir(p):
                out.append(p)
    appdata = os.environ.get("APPDATA") or ""
    if appdata:
        p = os.path.join(appdata, "Microsoft", "Windows",
                          "Start Menu", "Programs", "Startup")
        if os.path.isdir(p):
            out.append(p)
    # 去重（realpath 消掉 8.3 短名差异）
    seen, kept = set(), []
    for p in out:
        rp = os.path.realpath(os.path.normpath(p))
        if rp and rp not in seen:
            seen.add(rp)
            kept.append(rp)
    return kept


class DirWatcher:
    """每目录一个后台线程 + 一个句柄，阻塞 ReadDirectoryChangesW 拿事件。"""

    def __init__(self, detector, on_hit):
        self.detector = detector
        self.on_hit = on_hit          # 回调：(hit_dict) -> None
        self._stop = threading.Event()
        self._threads = []
        self._handles = []            # 各线程的目录句柄，stop 时 CancelIo 打断
        self._hlock = threading.Lock()
        self._recent = {}             # 路径 -> 上次扫描时间，短时间去重
        self._rlock = threading.Lock()
        self.paused = False

    def _dedupe(self, path):
        """同一路径 3 秒内的重复事件只扫一次（新增+修改会连发两个事件）。"""
        now = time.time()
        with self._rlock:
            last = self._recent.get(path, 0)
            if now - last < 3.0:
                return True
            self._recent[path] = now
        return False

    def _watch(self, path):
        path = os.path.normpath(path)
        if not os.path.isdir(path):
            return
        hdir = _k32.CreateFileW(
            path, FILE_LIST_DIRECTORY,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None)
        if not hdir or hdir == INVALID_HANDLE_VALUE:
            return
        with self._hlock:
            self._handles.append(hdir)

        buf = ctypes.create_string_buffer(64 * 1024)
        try:
            # 同步阻塞版：ReadDirectoryChangesW 不带 overlapped，直接阻塞在
            # 内核上等变化。退出靠另一个线程 CancelIo 打断（在 stop() 里做）。
            while not self._stop.is_set():
                nread = wt.DWORD(0)
                ok = _k32.ReadDirectoryChangesW(
                    hdir, buf, len(buf), True,
                    FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_SIZE |
                    FILE_NOTIFY_CHANGE_LAST_WRITE,
                    ctypes.byref(nread), None, None)
                if not ok or self._stop.is_set():
                    break
                if nread.value > 0:
                    self._drain(buf, nread.value, path)
        finally:
            _k32.CloseHandle(hdir)

    def _drain(self, buf, nbytes, root):
        if nbytes <= 0:
            return
        off = 0
        pending = {}
        # FILE_NOTIFY_INFORMATION 布局：
        #   +0 NextEntryOffset  +4 Action  +8 FileNameLength  +12 FileName(WCHAR)
        while off + 12 <= nbytes:
            next_off = ctypes.c_uint32.from_buffer(buf, off).value
            action = ctypes.c_uint32.from_buffer(buf, off + 4).value
            name_len = ctypes.c_uint32.from_buffer(buf, off + 8).value
            raw = buf[off + 12: off + 12 + name_len]
            try:
                name = raw.decode("utf-16-le", errors="ignore").rstrip("\x00")
            except Exception:
                name = ""
            if name and action in (1, 3, 5):        # 新增 / 修改 / 重命名新名
                full = os.path.join(root, name)
                pending[full] = action
            if not next_off:
                break
            off += next_off

        for full, action in pending.items():
            if self.paused or self._stop.is_set():
                return
            self._scan_soon(full)

    def _scan_soon(self, path):
        """落地后立即扫描，但给写入留一点余量：先试，读不到就重试一次。"""
        if self.paused:
            return
        if self._dedupe(path):
            return
        threading.Thread(target=self._scan_retry, args=(path,), daemon=True).start()

    def _scan_retry(self, path):
        for _ in range(3):
            if not os.path.isfile(path):
                time.sleep(0.3)
                continue
            try:
                if os.path.getsize(path) == 0:
                    time.sleep(0.2)
                    continue
                break
            except OSError:
                return
        hit = self.detector.scan_file(path)
        if hit:
            try:
                self.on_hit(hit)
            except Exception:
                pass

    def start(self):
        roots = _watch_roots()
        for r in roots:
            t = threading.Thread(target=self._watch, args=(r,), daemon=True)
            t.start()
            self._threads.append(t)

    def stop(self):
        self._stop.set()
        # 打断阻塞在 ReadDirectoryChangesW 上的线程，否则它们会一直挂着
        with self._hlock:
            for h in list(self._handles):
                try:
                    _k32.CancelIo(h)
                except Exception:
                    pass


# ---------------- 实时防护总控 ----------------

class Realtime:
    """把文件监控和进程监控串起来，对外暴露给 Bridge 与界面。"""

    def __init__(self):
        self.detector = _Detector()
        self.filewatch = DirWatcher(self.detector, self._on_file_hit)
        self.alerts = []          # 最近告警，界面展示
        self._lock = threading.Lock()
        self.enabled = True
        self._callback = None     # 由 Bridge 注入：有新告警时推给界面

    def set_callback(self, cb):
        self._callback = cb

    def start(self):
        self.detector.reload()
        self.filewatch.start()

    def stop(self):
        self.filewatch.stop()

    def set_enabled(self, on):
        self.enabled = bool(on)
        self.filewatch.paused = not self.enabled

    def _on_file_hit(self, hit):
        if not self.enabled:
            return
        self._push({"kind": "file", "hit": hit, "t": time.time()})

    def _push(self, alert):
        with self._lock:
            self.alerts.insert(0, alert)
            del self.alerts[50:]
        if self._callback:
            try:
                self._callback(alert)
            except Exception:
                pass

    def recent(self, n=10):
        with self._lock:
            return list(self.alerts[:n])

    def clear(self):
        with self._lock:
            self.alerts.clear()

    # 进程启动判定：由 procwatch 的采集结果驱动。
    # 这里提供「给定一个进程名+路径，判断是否要告警」的纯函数。
    def judge_process(self, name, path, kind):
        """kind 来自 procwatch.classify。只对 warn/danger 告警。"""
        if kind not in ("warn", "danger"):
            return None
        return {
            "kind": "proc",
            "hit": {"n": name, "p": path or "", "v": kind, "why": [],
                    "e": "进程启动", "fam": "unknown", "t": int(time.time())},
            "t": time.time(),
        }

    # 结束一个进程（拦截用）
    @staticmethod
    def kill_process(pid):
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return False
        if pid <= 4:
            return False
        PROCESS_TERMINATE = 0x0001
        h = ctypes.windll.kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if not h:
            return False
        try:
            return bool(ctypes.windll.kernel32.TerminateProcess(h, 1))
        finally:
            ctypes.windll.kernel32.CloseHandle(h)


# 全局单例，供 Bridge 使用
_instance = None
_lock = threading.Lock()


def get() -> Realtime:
    global _instance
    with _lock:
        if _instance is None:
            _instance = Realtime()
        return _instance

"""
扫描调度器：快速扫描 / 全盘扫描。

一次扫描分两段：先建立文件清单，再交给线程池逐文件过检测管线。
分两段而不是边遍历边扫，是为了能给出**真实百分比**——不知道总数时
进度条只能转圈，"还要多久"这个问题就永远答不上来。

每个文件的检测顺序：哈希 → YARA → PE 启发式 → clamd（可选）。
哈希命中直接定案，其余几层只在前一层没定案时才跑，避免白读一遍文件。
"""
import ctypes
import os
import string
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

import clamdc
import config
import peheur
import signatures
import threatcat
import yrules

MAX_FILES = 800_000              # 清单上限，超了就截断并如实上报
WORKERS = 12          # 哈希与 YARA 匹配都释放 GIL，多开几个才吃得满 IO
YARA_MAX = 24 * 1024 * 1024      # 超过这个大小不做 YARA，规则多在字符串上，大文件纯烧时间
PE_MAX = 48 * 1024 * 1024
HASH_MAX = 512 * 1024 * 1024     # 超大文件（虚拟机镜像之类）只记账不读

# 这些目录跳过：要么是系统的组件仓库（WinSxS 里全是硬链接，扫一遍毫无意义，
# 只是把时间耗在自己身上），要么是纯缓存。全盘扫描时也跳过。
SKIP_DIRS = {
    "$recycle.bin", "system volume information", "winsxs", "driverstore",
    "cache", "code cache", "gpucache", "shadercache", "cachestorage",
    "service worker", "crashpad", "blob_storage",
}
SKIP_FILES = {
    "pagefile.sys", "hiberfil.sys", "swapfile.sys", "dumpstack.log.tmp",
    "ntuser.dat.log1", "ntuser.dat.log2",
}


def _env(name: str) -> str:
    return os.environ.get(name, "") or ""


def _under(path: str, parent: str) -> bool:
    try:
        p = os.path.normcase(os.path.abspath(path))
        q = os.path.normcase(os.path.abspath(parent))
        return p == q or p.startswith(q + os.sep)
    except Exception:
        return False


def quick_targets():
    """常见感染位置。故意不收整个 C 盘——「快速」这两个字要对得起它。"""
    home = _env("USERPROFILE")
    appdata = _env("APPDATA")
    local = _env("LOCALAPPDATA")
    win = _env("WINDIR") or r"C:\Windows"
    prog = _env("PROGRAMDATA")

    raw = [
        _env("TEMP"), _env("TMP"),
        os.path.join(win, "Temp"),
        os.path.join(local, "Temp"),
        os.path.join(local, "Programs"),
        appdata,
        os.path.join(home, "Downloads"),
        os.path.join(home, "Desktop"),
        os.path.join(home, "Documents"),
        os.path.join(appdata, "Microsoft", "Windows", "Start Menu", "Programs", "Startup"),
        os.path.join(prog, "Microsoft", "Windows", "Start Menu", "Programs", "StartUp"),
    ]

    # 目标之间大量重叠（%TEMP% 就在 %LOCALAPPDATA% 下面），只留最外层那几个。
    # 必须用 realpath：环境变量里同时存在 8.3 短名（ADMINI~1）与长名，
    # 字符串比较认不出它们是同一个目录，同一批文件会被扫两遍、报两遍。
    kept = []
    for p in sorted({os.path.realpath(p) for p in raw if p and os.path.isdir(p)},
                    key=len):
        if not any(_under(p, k) for k in kept):
            kept.append(p)
    return kept


def full_targets():
    """所有固定磁盘。"""
    out = []
    for letter in string.ascii_uppercase:
        root = f"{letter}:\\"
        try:
            if (os.path.exists(root)
                    and ctypes.windll.kernel32.GetDriveTypeW(root) == 3):
                out.append(root)
        except Exception:
            pass
    return out


class Job:
    """一次扫描。状态字段全部由扫描线程写、由界面线程读，
    读写都走 _lock，界面那边永远看到一个自洽的快照。"""

    def __init__(self, mode: str):
        self.mode = mode
        self.state = "loading"      # loading | walking | scanning | done | cancelled | error
        self.total = 0
        self.done = 0
        self.walked = 0
        self.skipped = 0
        self.errors = 0
        self.current = ""
        self.message = "正在加载检测引擎"
        self.threats = []
        self.handled = 0          # 本次扫描里已被处置掉的条数
        self.started = time.time()
        self.ended = 0.0
        self.engines = {"hash": 0, "yara": 0, "heur": False, "clamd": False}
        self._stop = threading.Event()
        self._lock = threading.Lock()

    # ---- 外部接口 ----
    def cancel(self):
        self._stop.set()

    def stopped(self) -> bool:
        return self._stop.is_set()

    def mark_handled(self, path: str) -> bool:
        """某个威胁已经被处置（隔离/删除），把它从结果里摘掉。
        done 之后用户还在看结果页，处置动作必须真的让列表短一格，
        否则会出现「文件已经不在了，列表里还挂着」的矛盾状态。"""
        key = os.path.normcase(os.path.normpath(str(path or "")))
        with self._lock:
            before = len(self.threats)
            self.threats = [t for t in self.threats
                            if os.path.normcase(os.path.normpath(t.get("p", ""))) != key]
            hit = len(self.threats) != before
            if hit:
                self.handled += 1
            return hit

    def snapshot(self) -> dict:
        with self._lock:
            elapsed = (self.ended or time.time()) - self.started
            return {
                "state": self.state,
                "mode": self.mode,
                "total": self.total,
                "done": self.done,
                "walked": self.walked,
                "skipped": self.skipped,
                "errors": self.errors,
                "current": self.current,
                "message": self.message,
                "elapsed": round(elapsed, 1),
                "count": len(self.threats),
                "handled": self.handled,
                "threats": self.threats[:120],
                "engines": dict(self.engines),
            }

    # ---- 主流程 ----
    def run(self):
        try:
            self._load_engines()
            if self.stopped():
                return self._finish("cancelled")

            self._set(state="walking", message="正在建立文件清单")
            files = self._collect()
            if self.stopped():
                return self._finish("cancelled")

            with self._lock:
                self.total = len(files)
                self.state = "scanning"
                self.message = "正在扫描"

            self._scan_all(files)
            self._finish("cancelled" if self.stopped() else "done")
        except Exception as e:                       # 兜底：任何异常都要让界面收到结局
            self._finish("error", f"{type(e).__name__}: {e}")

    def _finish(self, state: str, msg: str = ""):
        with self._lock:
            self.state = state
            self.ended = time.time()
            if msg:
                self.message = msg
            if state == "done":
                self.message = "扫描完成"
            elif state == "cancelled":
                self.message = "已停止"

    def _set(self, **kw):
        with self._lock:
            for k, v in kw.items():
                setattr(self, k, v)

    # ---- 引擎装载 ----
    def _load_engines(self):
        data = config.load()
        self.use_yara = bool(data.get("engine_yara", True))
        self.use_heur = bool(data.get("engine_heur", True))
        self.use_clamd = bool(data.get("engine_clamd", False))
        self.clamd_addr = data.get("clamd_addr", "127.0.0.1:3310")

        signatures.init()
        cnt = signatures.count()
        self.engines["hash"] = cnt.get("total", 0)

        self.yara = None
        if self.use_yara and yrules.available():
            self._set(message="正在编译 YARA 规则")
            eng = yrules.load_engine()
            self.yara = eng if eng.ready else None
            self.engines["yara"] = eng.rules_total
            self.engines["yara_err"] = len(eng.errors)

        self.engines["heur"] = bool(peheur.available() and self.use_heur)
        self.engines["clamd"] = self.use_clamd
        self.engines["yara_on"] = bool(self.yara)

    # ---- 建清单 ----
    def _collect(self):
        targets = quick_targets() if self.mode == "quick" else full_targets()
        out = []
        skip_exe = config.exe_path()
        # 不扫自己的东西：签名库、规则库、配置目录，还有 PyInstaller 把单文件
        # exe 解包到的 _MEIxxxx 临时目录（里面有一份同样的规则文件）
        skip_dirs = [signatures.sig_dir(), config.config_dir()]
        meipass = getattr(sys, "_MEIPASS", "")
        if meipass:
            skip_dirs.append(meipass)
        for root in targets:
            if self.stopped():
                break
            self._walk(root, out, skip_exe, skip_dirs)
        return out

    def _walk(self, root, out, skip_exe, skip_dirs):
        stack = [root]
        while stack:
            if self.stopped() or len(out) >= MAX_FILES:
                return
            d = stack.pop()
            if any(_under(d, s) for s in skip_dirs):
                continue
            try:
                with os.scandir(d) as it:
                    for e in it:
                        try:
                            if e.is_dir(follow_symlinks=False):
                                if e.name.lower() in SKIP_DIRS:
                                    continue
                                stack.append(e.path)
                            elif e.is_file(follow_symlinks=False):
                                n = e.name.lower()
                                if n in SKIP_FILES:
                                    continue
                                if skip_exe and e.path == skip_exe:
                                    continue
                                out.append((e.path, e.stat(follow_symlinks=False).st_size))
                                if len(out) % 500 == 0:
                                    with self._lock:
                                        self.walked = len(out)
                        except OSError:
                            with self._lock:
                                self.errors += 1
            except OSError:
                with self._lock:
                    self.errors += 1
        with self._lock:
            self.walked = len(out)

    # ---- 扫描 ----
    def _scan_all(self, files):
        it = iter(files)
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            pending = {}
            # 有界提交：一次性 submit 几十万个 future，光排队就能吃掉几百兆
            for _ in range(WORKERS * 4):
                nxt = next(it, None)
                if nxt is None:
                    break
                pending[ex.submit(self._one, *nxt)] = nxt
            while pending:
                finished, _ = wait(pending, return_when=FIRST_COMPLETED)
                for fut in finished:
                    pending.pop(fut, None)
                    try:
                        hit = fut.result()
                    except Exception:
                        hit = None
                        with self._lock:
                            self.errors += 1
                    if hit:
                        with self._lock:
                            self.threats.append(hit)
                            if len(self.threats) > 3000:      # 极端情况下别把内存撑爆
                                del self.threats[:1000]
                    if self.stopped():
                        for f in pending:
                            f.cancel()
                        return
                    nxt = next(it, None)
                    if nxt is not None:
                        pending[ex.submit(self._one, *nxt)] = nxt

    def _one(self, path: str, size: int):
        with self._lock:
            self.done += 1
            self.current = path

        if size > HASH_MAX:
            with self._lock:
                self.skipped += 1
            return None

        sha, md5, is_pe = signatures.digests_of(path, size)
        if not sha:
            with self._lock:
                self.errors += 1
            return None

        reasons, engines = [], []
        verdict = ""
        score = 0
        fam = ""        # 家族：YARA 规则自己声明的，或下面逐步补
        tname = ""      # 报毒名，哈希库与 clamd 会填

        # 1) 哈希
        name = signatures.lookup(sha, md5)
        if name:
            reasons.append(f"命中已知样本 · {name}")
            engines.append("哈希")
            verdict = "danger"
            score = 100
            tname = name

        # 2) YARA
        if not verdict and self.yara and 0 < size <= YARA_MAX:
            hits = self.yara.match(path)
            if hits:
                worst = "danger" if any(h["severity"] == "high" for h in hits) else "warn"
                for h in hits[:3]:
                    # 引擎名由 e 字段统一标注，这里只写规则名，避免「YARA · YARA xxx」
                    label = h["rule"] + (f" · {h['desc']}" if h["desc"] else "")
                    reasons.append(label)
                    if not fam and h.get("family"):
                        fam = h["family"]
                engines.append("YARA")
                verdict = worst
                score = 90 if worst == "danger" else 55

        # 3) PE 启发式
        if not verdict and self.engines.get("heur") and is_pe and 0 < size <= PE_MAX:
            r = peheur.analyze(path, size)
            if r and r["verdict"] != "clean":
                verdict = r["verdict"]
                score = r["score"]
                reasons.extend(r["reasons"])
                engines.append("启发式")

        # 4) clamd（可选）
        if not verdict and self.use_clamd:
            host, _, port = self.clamd_addr.partition(":")
            res = clamdc.scan(path, host or "127.0.0.1", int(port or 3310))
            if res["status"] == "infected":
                verdict = "danger"
                score = 100
                reasons.append(res["name"])
                engines.append("clamd")
                tname = res["name"]

        if not verdict:
            return None

        return {
            "p": path,
            "n": os.path.basename(path),
            "v": verdict,
            "s": score,
            "why": reasons,
            "e": "、".join(engines),
            # 身份标签：界面按它选图标和标记，不在前端猜规则名
            "fam": threatcat.classify(family=fam, text=" ".join(reasons),
                                      name=tname, verdict=verdict),
            "t": int(time.time()),
        }


# ---- 进程内当前任务 ----
_CURRENT = None
_CUR_LOCK = threading.Lock()


def start(mode: str) -> dict:
    global _CURRENT
    if mode not in ("quick", "full"):
        return {"ok": False, "err": "未知扫描类型"}
    with _CUR_LOCK:
        if _CURRENT and _CURRENT.state in ("loading", "walking", "scanning"):
            return {"ok": False, "err": "已有扫描在进行中"}
        job = Job(mode)
        _CURRENT = job
    threading.Thread(target=job.run, daemon=True, name="qone-scan").start()
    return {"ok": True}


def current() -> Job:
    return _CURRENT


def status() -> dict:
    j = _CURRENT
    if not j:
        return {"state": "idle"}
    return j.snapshot()


def mark_handled(path: str) -> bool:
    j = _CURRENT
    return bool(j and j.mark_handled(path))


def cancel() -> bool:
    j = _CURRENT
    if j and j.state in ("loading", "walking", "scanning"):
        j.cancel()
        return True
    return False

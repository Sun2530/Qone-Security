"""
哈希签名库 —— 检测管线最底下那一层。

存 SQLite（标准库自带，无第三方依赖、无许可证问题），按摘要精确匹配。
选 SQLite 而不是 dict：从 MalwareBazaar 导出几十万条时，dict 要吃几百兆内存，
而这里是每扫一个文件查一次索引，代价可以忽略。

支持的导入格式：
  1) 本库自己的 seed 格式：  <摘要>\\t<名字>
  2) 通用列表：               <摘要>,<名字>   或   <名字>,<摘要>
  3) MalwareBazaar CSV 导出： 带 sha256_hash / md5_hash / sha1_hash 表头
"""
import csv
import hashlib
import io
import json
import os
import sqlite3
import threading
import urllib.parse
import urllib.request

import config
import paths

APP_DIR = "Qone Security"

# 导入时按长度区分摘要类型：64=SHA-256，40=SHA-1，32=MD5
HEX_LEN = {64: "sha256", 40: "sha1", 32: "md5"}

_lock = threading.Lock()
_local = threading.local()


def sig_dir() -> str:
    d = os.path.join(config.config_dir(), "signatures")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


def db_path() -> str:
    return os.path.join(sig_dir(), "hashes.db")


def _conn() -> sqlite3.Connection:
    """每线程一条连接：sqlite 连接不能跨线程共用，
    而扫描是线程池并发查的。"""
    c = getattr(_local, "c", None)
    if c is None:
        c = sqlite3.connect(db_path(), timeout=8)
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("PRAGMA synchronous=NORMAL")
        _local.c = c
    return c


def init() -> int:
    """建表 + 首次把随程序附带的 seed 导进去。返回本次新导入的条数。"""
    with _lock:
        c = _conn()
        c.execute("CREATE TABLE IF NOT EXISTS h (d TEXT PRIMARY KEY, n TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS meta (k TEXT PRIMARY KEY, v TEXT)")
        c.commit()

        row = c.execute("SELECT v FROM meta WHERE k='seed'").fetchone()
        if row:
            return 0

    n, _ = import_file(paths.res("assets", "sig", "seed.txt"), quiet=True)

    with _lock:
        c = _conn()
        c.execute("INSERT OR REPLACE INTO meta VALUES ('seed','1')")
        c.commit()
    return n


def count() -> dict:
    """按摘要长度分类统计，界面要显示这个。"""
    out = {"sha256": 0, "sha1": 0, "md5": 0, "total": 0}
    try:
        c = _conn()
        for length, kind in HEX_LEN.items():
            out[kind] = c.execute(
                "SELECT COUNT(*) FROM h WHERE length(d)=?", (length,)).fetchone()[0]
        out["total"] = c.execute("SELECT COUNT(*) FROM h").fetchone()[0]
    except sqlite3.Error:
        pass
    return out


def lookup(sha256: str, md5: str = "") -> str:
    """命中返回名字，未命中返回空串。先查 SHA-256，再退 MD5。"""
    try:
        c = _conn()
        if sha256:
            r = c.execute("SELECT n FROM h WHERE d=?", (sha256,)).fetchone()
            if r:
                return r[0] or "未命名样本"
        if md5:
            r = c.execute("SELECT n FROM h WHERE d=?", (md5,)).fetchone()
            if r:
                return r[0] or "未命名样本"
    except sqlite3.Error:
        pass
    return ""


def _is_hex(s: str, lengths) -> bool:
    if len(s) not in lengths:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


def import_file(path: str, quiet: bool = False):
    """导入一个签名文件，返回 (新增条数, 错误说明)。"""
    if not path or not os.path.isfile(path):
        return 0, "文件不存在"

    try:
        if os.path.getsize(path) > 512 * 1024 * 1024:
            return 0, "文件超过 512 MB，请先拆分"
        with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
            head = f.readline()
            f.seek(0)
            rows = _parse_csv(f) if "sha256_hash" in head.lower() else _parse_plain(f)
            return _insert(rows)
    except OSError as e:
        return 0, f"读取失败：{e}"
    except sqlite3.Error as e:
        return 0, f"写入签名库失败：{e}"


def _parse_csv(f):
    """MalwareBazaar CSV 导出。"""
    rd = csv.DictReader(f)
    for row in rd:
        name = (row.get("signature") or row.get("file_name") or "").strip()
        if not name or name.lower() in ("n/a", "none"):
            name = "未命名样本"
        for key in ("sha256_hash", "md5_hash", "sha1_hash"):
            v = (row.get(key) or "").strip().lower()
            if _is_hex(v, HEX_LEN):
                yield v, name


def _parse_plain(f):
    """纯文本 / 普通 CSV：一行一个摘要，名字可有可无。"""
    for line in f:
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        parts = [p.strip() for p in line.replace("\t", ",").replace(";", ",").split(",")]
        digest, name = "", ""
        for p in parts:
            q = p.lower()
            if not digest and _is_hex(q, HEX_LEN):
                digest = q
            elif p and not name:
                name = p
        if digest:
            yield digest, name or "未命名样本"


def _insert(rows) -> tuple:
    added = 0
    seen = 0
    with _lock:
        c = _conn()
        batch = []
        for digest, name in rows:
            batch.append((digest, name))
            seen += 1
            if len(batch) >= 5000:
                added += _flush(c, batch)
                batch = []
        added += _flush(c, batch)
        c.commit()
    return added, ""


def _flush(c, batch) -> int:
    if not batch:
        return 0
    before = c.total_changes
    c.executemany("INSERT OR IGNORE INTO h VALUES (?,?)", batch)
    return c.total_changes - before


# ---------------- abuse.ch 在线同步 ----------------
# 只拉最近样本的摘要，不下载样本本体、不转存他们的数据；
# 按 abuse.ch 的公平使用原则，非商业用途可直接用免费 Auth-Key。
MB_API = "https://mb-api.abuse.ch/api/v1/"


def sync_abuse(auth_key: str, limit: int = 10) -> dict:
    """拉取 MalwareBazaar 最近样本的摘要并入库。limit 以 100 条为一页。"""
    auth_key = (auth_key or "").strip()
    if len(auth_key) < 8:
        return {"ok": False, "err": "请先填写 abuse.ch 的 Auth-Key（免费申请）"}

    limit = max(1, min(20, int(limit or 10)))
    total = 0
    try:
        for _ in range(limit):
            body = urllib.parse.urlencode(
                {"query": "get_recent", "selector": "time"}).encode()
            req = urllib.request.Request(
                MB_API, data=body,
                headers={"Auth-Key": auth_key,
                         "User-Agent": "QoneSecurity/1.0"})
            with urllib.request.urlopen(req, timeout=20) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
            if data.get("query_status") != "ok":
                return {"ok": False, "err": f"接口返回：{data.get('query_status')}"}
            rows = []
            for item in data.get("data") or []:
                name = (item.get("signature") or item.get("file_name")
                        or "未命名样本").strip()
                d = (item.get("sha256_hash") or "").strip().lower()
                if _is_hex(d, HEX_LEN):
                    rows.append((d, name))
            added, _ = _insert(rows)
            total += added
    except urllib.error.HTTPError as e:
        return {"ok": False, "err": f"HTTP {e.code}，可能是 Auth-Key 无效"}
    except Exception as e:
        return {"ok": False, "err": f"网络请求失败：{type(e).__name__}"}

    return {"ok": True, "added": total, "count": count()}


def digests_of(path: str, size: int):
    """读一遍文件，同时算 SHA-256 与 MD5，顺带看出它是不是 PE。

    返回 (sha256, md5, is_pe)。PE 判断塞在这里是为了省一次 open：
    一次扫描里每多开一次文件，全盘就是几十万次多余的系统调用。
    """
    h256 = hashlib.sha256()
    hmd5 = hashlib.md5()
    is_pe = False
    first = True
    try:
        with open(path, "rb", buffering=0) as f:
            while True:
                chunk = f.read(1024 * 1024)
                if not chunk:
                    break
                if first:
                    is_pe = chunk[:2] == b"MZ"
                    first = False
                h256.update(chunk)
                hmd5.update(chunk)
    except (OSError, PermissionError):
        return "", "", False
    return h256.hexdigest(), hmd5.hexdigest(), is_pe

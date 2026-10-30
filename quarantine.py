"""
隔离区：把判定为威胁的文件挪出原位、改名并打乱内容存放，随时可以原样取回。

设计上的几个取舍，都是想清楚才定的：

1. **不建索引数据库。** 元数据直接写进隔离文件的头部，文件本身就是唯一数据源。
   用索引的话迟早会出现「数据库说有五个、磁盘上只剩四个」这种对不上的状态，
   而这种状态在安全软件里最要命——用户会以为文件还在隔离区，其实早就没了。
   代价是列表要逐个读头，但隔离区的量级是几十到几百，无所谓。

2. **加密的目的不是保密，是「不可执行」。** 被隔离的 exe 必须双击也跑不起来，
   否则「隔离」就只是把文件挪了个地方。这里用 SHAKE-256 生成密钥流做异或，
   破坏掉 PE 头即可；真正的保护来自「文件已经被移到用户不会去点的目录」。
   界面上不把它吹成加密保险箱，写的是「打乱内容，双击也无法运行」。

3. **先完整写出、fsync、再删原文件。** 顺序反了就是数据丢失的经典写法。
   删原文件失败（文件被占用是常态）就把隔离副本也撤掉，当没发生过，
   绝不留两份——两份里必有一份会被用户当成"我已经处理过了"。

4. **恢复绝不覆盖。** 原位置已有同名文件时改名放回，并明确告诉用户改成了什么。
   隔离区里躺着的往往是误报，用户取回来的东西不能顺手把别的文件顶掉。
"""
import ctypes
import hashlib
import json
import os
import struct
import time
import uuid
from ctypes import wintypes

import config

MAGIC = b"QONEQ01\n"
EXT = ".qbin"
SALT_LEN = 16
KBLOCK = 1 << 20                 # 1 MB 一块，大文件不整只吃进内存
MAX_SIZE = 512 * 1024 * 1024     # 比这更大的不隔离，直接建议删除


def qdir() -> str:
    d = os.path.join(config.config_dir(), "quarantine")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


# ---------------- 内容打乱 ----------------

def _xor(a: bytes, key: bytes) -> bytes:
    """整块异或。走 int 的大整数运算，是 C 层实现；
    用 `bytes(i ^ j for ...)` 逐字节循环在 20 MB 文件上要好几秒。"""
    n = len(a)
    if not n:
        return b""
    return (int.from_bytes(a, "big") ^ int.from_bytes(key, "big")).to_bytes(n, "big")


def _keystream(salt: bytes, ctr: int, n: int) -> bytes:
    """每块用 (salt, 块序号) 派生独立密钥流，块之间不会互相影响。"""
    return hashlib.shake_256(salt + ctr.to_bytes(8, "little")).digest(n)


def _crypt_copy(src: str, fout, salt: bytes, offset: int = 0) -> int:
    """把 src 从 offset 起读出来，打乱后写进 fout。异或对称，加密和解密是同一个函数。"""
    total, ctr = 0, 0
    with open(src, "rb", buffering=0) as f:
        if offset:
            f.seek(offset)
        while True:
            chunk = f.read(KBLOCK)
            if not chunk:
                break
            fout.write(_xor(chunk, _keystream(salt, ctr, len(chunk))))
            total += len(chunk)
            ctr += 1
    return total


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, "rb", buffering=0) as f:
            while True:
                b = f.read(KBLOCK)
                if not b:
                    break
                h.update(b)
    except OSError:
        return ""
    return h.hexdigest()


# ---------------- 头 ----------------

def _hkey(salt: bytes, n: int) -> bytes:
    """头部用的密钥流。加 b"H" 前缀和正文的流分开，
    同一份 salt 派生出两条互不相干的流，不会出现重复密钥材料。"""
    return hashlib.shake_256(b"H" + salt).digest(n)


def _write_header(f, meta: dict, salt: bytes) -> None:
    """头也加密。明文头里带着原文件名和「命中 XX 病毒」这类字眼，
    留着明文等于让隔离文件自己变成一份通缉令——别的杀软扫到这堆字照样报警。"""
    hb = json.dumps(meta, ensure_ascii=False).encode("utf-8")
    f.write(MAGIC)
    f.write(salt)                     # 只有 salt 是明文，别无他物
    f.write(struct.pack("<I", len(hb)))
    f.write(_xor(hb, _hkey(salt, len(hb))))


def _read_header(path: str):
    """返回 (元数据, salt, payload 起始偏移)；不合法则 (None, b"", 0)。"""
    base = len(MAGIC) + SALT_LEN + 4
    try:
        with open(path, "rb") as f:
            if f.read(len(MAGIC)) != MAGIC:
                return None, b"", 0
            salt = f.read(SALT_LEN)
            raw = f.read(4)
            if len(salt) != SALT_LEN or len(raw) != 4:
                return None, b"", 0
            n = struct.unpack("<I", raw)[0]
            if n <= 0 or n > 65536:      # 头不该有这么大，防坏文件把内存撑爆
                return None, b"", 0
            hb = f.read(n)
            if len(hb) != n:
                return None, b"", 0
            meta = json.loads(_xor(hb, _hkey(salt, n)).decode("utf-8"))
            if not isinstance(meta, dict):
                return None, b"", 0
            return meta, salt, base + n
    except (OSError, ValueError):
        return None, b"", 0


def _qpath(qid: str) -> str:
    # 只认十六进制 id，杜绝 ../ 这类把路径带出隔离目录的输入
    safe = "".join(c for c in str(qid) if c in "0123456789abcdef")
    return os.path.join(qdir(), safe + EXT)


# ---------------- 放入隔离区 ----------------

def add(path: str, meta: dict = None) -> dict:
    """把一个文件移进隔离区。成功返回 {ok, id, ...}，失败给出人话的原因。"""
    path = os.path.normpath(str(path or ""))
    if not path or not os.path.isfile(path):
        return {"ok": False, "path": path, "err": "文件已不存在，可能已被移动或删除"}

    try:
        size = os.path.getsize(path)
    except OSError as e:
        return {"ok": False, "path": path, "err": "无法读取文件大小：%s" % e}
    if size > MAX_SIZE:
        return {"ok": False, "path": path,
                "err": "文件超过 512 MB，不适合隔离，建议直接删除"}

    meta = dict(meta or {})
    qid = uuid.uuid4().hex
    salt = os.urandom(SALT_LEN)
    final = _qpath(qid)
    part = final + ".part"

    header = {
        "id": qid,
        "name": os.path.basename(path),
        "path": path,
        "size": size,
        "ts": int(time.time()),
        "sha": _sha256(path),
        "v": meta.get("v") or "danger",
        "e": meta.get("e") or "",
        # 家族代号跟着隔离记录一起存：隔离区里也要能看出「这是个后门还是勒索」，
        # 不能进了隔离区就退化成一堆无名文件
        "fam": meta.get("fam") or "",
        "why": list(meta.get("why") or [])[:6],
    }

    try:
        with open(part, "wb") as f:
            _write_header(f, header, salt)
            _crypt_copy(path, f, salt)
            f.flush()
            os.fsync(f.fileno())     # 落到盘上再删原件，中途断电也不会两边都不完整
        os.replace(part, final)
    except OSError as e:
        for p in (part, final):
            try:
                os.remove(p)
            except OSError:
                pass
        return {"ok": False, "path": path, "err": "写入隔离区失败：%s" % e}

    try:
        os.remove(path)
    except OSError as e:
        # 撤掉隔离副本，回到未处置的状态。留着两份才是真出问题
        try:
            os.remove(final)
        except OSError:
            pass
        hint = "文件正在被使用，先结束相关进程再试" if getattr(e, "winerror", 0) in (32, 33) \
            else "没有权限或文件被占用"
        return {"ok": False, "path": path, "err": "无法移除原文件（%s）" % hint}

    _drop_empty_dir(path)
    return {"ok": True, "id": qid, "path": path, "item": header}


def _drop_empty_dir(path: str) -> None:
    """原文件所在目录空了就顺手删掉——恶意程序爱在 Temp 里建随机名目录，
    留着这些空壳只会让 Temp 越来越乱。只删空目录，非空一律不碰。"""
    d = os.path.dirname(path)
    tmp = os.path.realpath(os.environ.get("TEMP", ""))
    try:
        if not d or not tmp or not os.path.realpath(d).startswith(tmp):
            return
        if os.path.realpath(d) == tmp:
            return
        if not os.listdir(d):
            os.rmdir(d)
    except OSError:
        pass


# ---------------- 查询 ----------------

def listing() -> list:
    out, d = [], qdir()
    try:
        names = os.listdir(d)
    except OSError:
        return out
    for n in names:
        if not n.endswith(EXT):
            continue
        meta, _salt, _off = _read_header(os.path.join(d, n))
        if meta:
            out.append(meta)
    out.sort(key=lambda x: x.get("ts", 0), reverse=True)
    return out


def count() -> int:
    return len(listing())


def stat() -> dict:
    items = listing()
    return {"count": len(items), "bytes": sum(int(i.get("size") or 0) for i in items)}


# ---------------- 恢复 ----------------

def _free_name(target: str) -> str:
    if not os.path.exists(target):
        return target
    d, name = os.path.split(target)
    stem, ext = os.path.splitext(name)
    for i in range(2, 1000):
        cand = os.path.join(d, "%s (%d)%s" % (stem, i, ext))
        if not os.path.exists(cand):
            return cand
    return os.path.join(d, "%s (restored)%s" % (stem, ext))


def restore(qid: str) -> dict:
    src = _qpath(qid)
    meta, salt, off = _read_header(src)
    if not meta:
        return {"ok": False, "err": "隔离记录已损坏或已被删除"}

    original = str(meta.get("path") or "")
    if not original:
        return {"ok": False, "err": "这条记录缺少原路径信息，无法恢复"}

    d = os.path.dirname(original)
    if d and not os.path.isdir(d):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError as e:
            return {"ok": False, "err": "原目录不存在且无法重建：%s" % e}

    target = _free_name(original)
    part = target + ".qone-part"

    try:
        with open(part, "wb") as f:
            _crypt_copy(src, f, salt, off)
            f.flush()
            os.fsync(f.fileno())
        os.replace(part, target)
    except OSError as e:
        try:
            os.remove(part)
        except OSError:
            pass
        return {"ok": False, "err": "写回失败：%s" % e}

    try:
        os.remove(src)
    except OSError:
        # 恢复已经成功，隔离副本删不掉不该让用户以为失败了
        pass

    renamed = os.path.normcase(target) != os.path.normcase(original)
    return {"ok": True, "path": target, "renamed": renamed,
            "name": os.path.basename(target)}


# ---------------- 永久删除 ----------------

def remove(qid: str) -> dict:
    p = _qpath(qid)
    if not os.path.isfile(p):
        return {"ok": False, "err": "记录不存在"}
    try:
        os.remove(p)
        return {"ok": True}
    except OSError as e:
        return {"ok": False, "err": "删除失败：%s" % e}


def clear() -> dict:
    n = 0
    d = qdir()
    try:
        names = os.listdir(d)
    except OSError:
        return {"ok": True, "n": 0}
    for name in names:
        if not name.endswith(EXT):
            continue
        try:
            os.remove(os.path.join(d, name))
            n += 1
        except OSError:
            pass
    return {"ok": True, "n": n}


# ---------------- 送回收站 ----------------

class _SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [("hwnd", wintypes.HWND),
                ("wFunc", wintypes.UINT),
                ("pFrom", wintypes.LPCWSTR),
                ("pTo", wintypes.LPCWSTR),
                ("fFlags", ctypes.c_ushort),
                ("fAnyOperationsAborted", wintypes.BOOL),
                ("hNameMappings", ctypes.c_void_p),
                ("lpszProgressTitle", wintypes.LPCWSTR)]


FO_DELETE = 0x0003
FOF_SILENT = 0x0004
FOF_NOCONFIRMATION = 0x0010
FOF_ALLOWUNDO = 0x0040       # 进回收站，而不是直接抹掉
FOF_NOERRORUI = 0x0400


def to_recycle_bin(path: str) -> dict:
    """把文件送进回收站。比 os.remove 安全：用户后悔了还能捞回来。"""
    path = os.path.normpath(str(path or ""))
    if not os.path.isfile(path):
        return {"ok": False, "err": "文件已不存在"}
    try:
        op = _SHFILEOPSTRUCTW()
        op.hwnd = None
        op.wFunc = FO_DELETE
        # 列表要以两个 NUL 结尾；ctypes 传 str 会自动补一个，所以这里补到两个
        op.pFrom = path + "\0"
        op.pTo = None
        op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI
        res = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
        if res != 0:
            return {"ok": False, "err": "无法移入回收站（代码 %d）" % res}
        if op.fAnyOperationsAborted:
            return {"ok": False, "err": "操作被中止"}
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "err": "无法移入回收站：%s" % e}

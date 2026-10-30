"""
规则包更新 —— 类似安全厂商的「病毒库升级」，但只升级能升级的东西。

这里有一条不能越的线，先说清楚：
  · 分发的只有「本项目自己写的 YARA 规则」（MIT），这是我们的作品，随便发。
  · 第三方哈希摘要（MalwareBazaar 等）不在此列，它们不是 CC0，转存即违约。
    那部分走用户自己的 Auth-Key，数据只落在他本机。
所以这个模块只搬 .yar 文件，一条哈希都不碰。

不需要服务器：GitHub 仓库就是更新源，raw / jsDelivr / Gitee 三个地址依次退让，
零成本，也不会因为哪天忘了续费而全量用户失联。

下载下来的规则等同「代码」，不是数据。所以落盘前必须三关：
  1) SHA-256 与清单一致
  2) 拒绝 include（它能读本机文件）、import 只允许白名单
  3) 试编译一次，语法不过或编译超时就整包丢弃
三关全过才写盘，任何一关不过都当作攻击对待，不降级、不部分生效。
"""
import hashlib
import json
import os
import re
import threading
import time
import urllib.request

import config
import paths
import yrules

try:
    import yara
except Exception:
    yara = None

# 仓库里放规则的目录。改仓库名要同步改这三行。
# 顺序即退让顺序：jsDelivr 走 CDN，国内最稳，排第一；raw 权威但偶发超时，排第二；Gitee 备用。
# 注意：GitHub 路径对大小写敏感，仓库名是 Qone-Security（大写 Q、S），写错会 404。
SOURCES = (
    "https://cdn.jsdelivr.net/gh/Sun2530/Qone-Security@main/rules",
    "https://raw.githubusercontent.com/Sun2530/Qone-Security/main/rules",
    "https://gitee.com/Sun2530/Qone-Security/raw/main/rules",
)

UA = "QoneSecurity/%s (+https://github.com/Sun2530/Qone-Security)" % config.APP_VERSION

GAP_OK = 86400     # 上次成功：一天查一次
GAP_FAIL = 3600    # 上次失败：一小时后再试，别把断网的用户钉死
NET_TIMEOUT = 6    # 清单很小，6 秒足够；等太久会把启动拖住

# YARA 能 import 的模块里，真正需要在扫描时用到的就这几个。
# 其余（比如 cuckoo）要外部喂数据，规则作者自己都跑不通，收进来只会污染目录。
ALLOWED_IMPORT = {"pe", "hash", "math", "time", "dotnet", "elf", "magic"}

_INC_RE = re.compile(r"""\binclude\s*["']""", re.I)
_IMP_RE = re.compile(r"""\bimport\s*"([^"]+)\"""", re.I)
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._\-]{1,64}$")


# ---------------- 版本 ----------------

def _vkey(v: str):
    """把 2026.10.30 拆成元组比大小；非纯数字段一律当 0，
    这样写错的版本号不会把比较炸掉，只会排到最后。"""
    out = []
    for part in str(v or "").replace("-", ".").split("."):
        try:
            out.append(int(part))
        except ValueError:
            out.append(0)
    return tuple(out)


def builtin_version() -> str:
    """随程序打包的那份规则版本，写在 assets/yara/manifest.json 里。"""
    try:
        p = paths.res("assets", "yara", "manifest.json")
        with open(p, encoding="utf-8") as f:
            return str(json.load(f).get("version") or "").strip()
    except Exception:
        return ""


def status() -> dict:
    """给界面看的当前状态，不发网络请求。"""
    data = config.load()
    bv = builtin_version()
    sv = (data.get("rules_version") or "").strip()
    # 线上版本只有「不旧于内置」才算数：用户装了新版程序，
    # 本地那个去年的规则包不该把内置的新规则盖回去
    online = bool(sv) and _vkey(sv) >= _vkey(bv)
    info = yrules.info()
    return {
        "version": sv if online else (bv or "—"),
        "builtin": bv or "—",
        "source": "线上" if online else "内置",
        "custom": bool((data.get("rules_url") or "").strip()),
        "custom_url": str(data.get("rules_url") or ""),
        "auto": bool(data.get("rules_auto", True)),
        "checked_at": int(data.get("rules_checked_at") or 0),
        "last_ok": bool(data.get("rules_ok", False)),
        "notes": str(data.get("rules_notes") or ""),
        "rules": info.get("rules", 0),
        "files": info.get("files", 0),
        "engine": info.get("engine", False),
    }


# ---------------- 网络 ----------------

def _sources(data) -> list:
    """自定义源排第一（用户自己填的优先），其余按默认顺序退让。"""
    out = []
    custom = (data.get("rules_url") or "").strip()
    if custom:
        out.append(custom.rstrip("/"))
    for s in SOURCES:
        if s not in out:
            out.append(s)
    return out


def _get(url: str, timeout: int) -> bytes:
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        # 规则包会变，任何中间层都不许缓存，否则用户永远拿到旧清单
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        if r.status != 200:
            raise OSError("HTTP %s" % r.status)
        return r.read(8 * 1024 * 1024)


def _host(url: str) -> str:
    try:
        return re.sub(r"^https?://", "", url).split("/")[0]
    except Exception:
        return url[:24]


# ---------------- 规则体检 ----------------

def _try_compile(text: str):
    """编译一次看语法。放线程里是为了防正则回溯卡死——
    yara-python 的 compile 没有超时参数，只能在外面兜。"""
    if yara is None:
        return False, "未安装 yara-python"
    box = {}

    def run():
        try:
            yara.compile(source=text, includes=False)
            box["ok"] = True
        except Exception as e:
            box["ok"] = False
            box["err"] = str(e).strip().splitlines()[0][:90]

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(10)
    if t.is_alive():
        return False, "规则编译超时（疑似正则回溯），已拒绝"
    if not box.get("ok"):
        return False, "语法错误：%s" % (box.get("err") or "未知")
    return True, ""


def vet(text: str) -> str:
    """返回拒绝理由，空串表示通过。"""
    if _INC_RE.search(text):
        return "含 include 指令，可以读本机文件，已拒绝"
    for m in _IMP_RE.finditer(text):
        mod = m.group(1).strip().lower()
        if mod not in ALLOWED_IMPORT:
            return '含不允许的模块 import "%s"' % m.group(1)
    ok, why = _try_compile(text)
    return "" if ok else why


# ---------------- 落盘 ----------------

def _write_atomic(dst: str, raw: bytes) -> bool:
    tmp = dst + ".tmp"
    try:
        with open(tmp, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, dst)
        return True
    except OSError:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
        return False


def _install(man: dict, base: str):
    """下载 → 三关体检 → 全部通过才写盘。返回 (写入数, 错误)。"""
    files = man.get("files")
    if not isinstance(files, list) or not files:
        return 0, "清单里没有列任何规则文件"

    staged = []
    for item in files:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").strip()
        if not _SAFE_NAME.fullmatch(name) or not name.lower().endswith((".yar", ".yara")):
            return 0, "文件名不合法：%s" % (name or "(空)")
        want = str(item.get("sha256") or "").strip().lower()

        try:
            raw = _get(base + "/" + name, 12)
        except Exception as e:
            return 0, "下载 %s 失败：%s" % (name, type(e).__name__)

        if len(raw) > 4 * 1024 * 1024:
            return 0, "%s 超过 4 MB，正常规则文件不会这么大" % name
        got = hashlib.sha256(raw).hexdigest()
        if want and got != want:
            return 0, "%s 校验不一致，可能是传输被篡改" % name

        why = vet(raw.decode("utf-8", "replace"))
        if why:
            return 0, "%s：%s" % (name, why)

        staged.append((name, raw))

    if not staged:
        return 0, "清单里没有可用的规则文件"

    ok = 0
    for name, raw in staged:
        if _write_atomic(os.path.join(yrules.rules_dir(), name), raw):
            ok += 1
    if ok != len(staged):
        return ok, "有 %d 个文件写入失败，可能是目录权限" % (len(staged) - ok)
    return ok, ""


# ---------------- 主流程 ----------------

def check(force: bool = False) -> dict:
    """检查并应用更新。force=True 时无视节流（手动点按钮走这条）。"""
    data = config.load()
    now = int(time.time())
    last = int(data.get("rules_checked_at") or 0)
    gap = GAP_OK if data.get("rules_ok") else GAP_FAIL

    if not force and last and (now - last) < gap:
        return dict(status(), ok=True, skipped=True, updated=False)

    man, base, errs = None, "", []
    for src in _sources(data):
        try:
            raw = _get(src + "/manifest.json", NET_TIMEOUT)
            obj = json.loads(raw.decode("utf-8", "replace"))
            if not isinstance(obj, dict) or not str(obj.get("version") or "").strip():
                raise ValueError("清单缺少 version")
            man, base = obj, src
            break
        except Exception as e:
            errs.append("%s → %s" % (_host(src), type(e).__name__))

    data = config.load()
    data["rules_checked_at"] = now
    data["rules_ok"] = man is not None
    config.save(data)

    if man is None:
        return dict(status(), ok=False, offline=True,
                    err="连不上更新源，已使用本地规则", detail=errs)

    remote = str(man.get("version")).strip()
    cur = status()["version"]

    # 程序太旧，规则包用不了：不动磁盘，如实回话
    need = str(man.get("min_app") or "").strip()
    if need and _vkey(need) > _vkey(config.APP_VERSION):
        return dict(status(), ok=False, updated=False, remote=remote,
                    err="这个规则包需要 %s 或更新的程序版本" % need)

    if _vkey(remote) <= _vkey(cur):
        return dict(status(), ok=True, updated=False, remote=remote,
                    latest=True)

    n, why = _install(man, base)
    if why:
        return dict(status(), ok=False, updated=False, remote=remote, err=why)

    data = config.load()
    data["rules_version"] = remote
    data["rules_notes"] = str(man.get("notes") or "")[:280]
    data["rules_ok"] = True
    config.save(data)

    return dict(status(), ok=True, updated=True, remote=remote, files=n)

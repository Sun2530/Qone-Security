"""
YARA 规则层。

规则从两个地方读：
  1) 随程序附带的 assets/yara/ （本项目自写，MIT）
  2) %LOCALAPPDATA%\\Qone Security\\yara\\ （用户自己放，例如 ReversingLabs 的 MIT 规则集）

逐个文件编译，而不是把所有规则拼成一大坨：一条写错的规则不该让整套规则失效。
编译失败的文件会被记下来并在界面上报出来，不静默吞掉。

yara-python 是 Apache-2.0（绑定层），YARA 引擎本体是 BSD-3-Clause，
两者都允许与 MIT 项目共存，义务是在第三方许可文件里保留版权与许可声明。
"""
import os
import re
import threading

import config
import paths

try:
    import yara
except Exception:
    yara = None

_RULE_RE = re.compile(r"^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z_][\w]*)", re.M)
_CACHE = {}
_CACHE_LOCK = threading.Lock()


def _count_rules(text: str) -> int:
    """数规则条数。global 规则只是前置条件，不产出命中，
    算进「多少条规则」会虚报，所以排除掉。"""
    n = 0
    for m in _RULE_RE.finditer(text):
        if "global" in m.group(0):
            continue
        n += 1
    return n


def available() -> bool:
    return yara is not None


def rules_dir() -> str:
    d = os.path.join(config.config_dir(), "yara")
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


def rule_files():
    """返回 [(路径, 来源)]，来源用于界面区分「内置」与「自定义」。

    自定义目录里的同名文件会盖掉内置的那一份，而不是两份一起加载——
    线上更新的规则包就叫 qone-core.yar，两份都读进来等于每条规则命中两次。
    覆盖而不是追加，也让「新版删掉了一条规则」能真的删掉。
    """
    builtin_dir = paths.res("assets", "yara")
    custom_dir = rules_dir()

    try:
        custom = sorted(n for n in os.listdir(custom_dir)
                        if n.lower().endswith((".yar", ".yara")))
    except OSError:
        custom = []
    shadowed = {n.lower() for n in custom}

    out = []
    try:
        for name in sorted(os.listdir(builtin_dir)):
            if (name.lower().endswith((".yar", ".yara"))
                    and name.lower() not in shadowed):
                out.append((os.path.join(builtin_dir, name), "builtin"))
    except OSError:
        pass
    for name in custom:
        out.append((os.path.join(custom_dir, name), "custom"))
    return out


class Engine:
    """一个装了若干「已编译规则集」的容器。"""

    def __init__(self):
        self.compiled = []       # [(来源路径, yara.Rules)]
        self.rules_total = 0
        self.files_total = 0
        self.errors = []         # ["xxx.yar: 错误原因"]
        self.ready = False

    def load(self) -> "Engine":
        self.compiled = []
        self.errors = []
        self.rules_total = 0
        self.files_total = 0

        if yara is None:
            self.errors.append("未安装 yara-python，YARA 层不可用")
            return self

        for path, _src in rule_files():
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    text = f.read()
            except OSError as e:
                self.errors.append(f"{os.path.basename(path)}: {e}")
                continue

            count = _count_rules(text)
            if not count:
                continue

            try:
                # filepath 而不是 source：让规则里的 include "xxx.yar"
                # 能按相对路径解析，和 yara 命令行的行为一致
                rules = yara.compile(filepath=path, includes=True)
            except Exception as e:
                self.errors.append(f"{os.path.basename(path)}: {str(e)[:120]}")
                continue

            self.compiled.append((path, rules))
            self.rules_total += count
            self.files_total += 1

        self.ready = bool(self.compiled)
        return self

    def match(self, path: str):
        """返回 [{'rule':.., 'desc':.., 'severity':..}]。"""
        if not self.compiled:
            return []
        hits = []
        for src, rules in self.compiled:
            try:
                found = rules.match(path, timeout=8)
            except Exception:
                # 超时（timeout）或文件被占用：这一层放弃，不阻断其它层
                continue
            for m in found:
                meta = getattr(m, "meta", {}) or {}
                hits.append({
                    "rule": m.rule,
                    "desc": (meta.get("description") or meta.get("desc") or "").strip(),
                    "severity": (meta.get("severity") or "high").strip().lower(),
                    # 家族由规则作者自己声明（meta: family = "ransom"），
                    # 比事后按字符串猜准得多；没写就留空，交给 threatcat 兜底
                    "family": (meta.get("family") or "").strip().lower(),
                    "file": os.path.basename(src),
                })
        return hits


def load_engine() -> Engine:
    """按规则文件集合做一次进程内缓存：同一套规则不重复编译。"""
    files = rule_files()
    key = tuple((p, os.path.getmtime(p) if os.path.exists(p) else 0) for p, _ in files)
    with _CACHE_LOCK:
        eng = _CACHE.get(key)
        if eng is None:
            eng = Engine().load()
            _CACHE.clear()      # 只留当前这一套，规则改了旧的不再占内存
            _CACHE[key] = eng
        return eng


def info() -> dict:
    """给界面看的规则库概况（不触发编译）。"""
    files = rule_files()
    total = 0
    bad = 0
    for p, _ in files:
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                total += _count_rules(f.read())
        except OSError:
            bad += 1
    return {"files": len(files), "rules": total, "unreadable": bad,
            "engine": yara is not None}

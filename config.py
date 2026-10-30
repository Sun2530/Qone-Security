"""
设置与白名单的本地持久化。

全部放在 %LOCALAPPDATA%\\Qone Security\\ 下，不往程序目录写、不散落到注册表
（开机自启除外，那是它唯一该在的地方）。卸载时删掉这一个文件夹就干净了。
"""
import json
import os
import sys
import tempfile
import threading
import time
import winreg

APP_VERSION = "1.4.0.0"

APP_DIR_NAME = "Qone Security"

RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "Qone Security"


def config_dir() -> str:
    base = os.environ.get("LOCALAPPDATA") or tempfile.gettempdir()
    d = os.path.join(base, APP_DIR_NAME)
    try:
        os.makedirs(d, exist_ok=True)
    except OSError:
        pass
    return d


PATH = os.path.join(config_dir(), "settings.json")

DEFAULTS = {
    "monitor": True,        # 进程启动监控
    "show_sys": True,       # 日志里是否显示系统进程
    "autostart": False,     # 开机启动
    "whitelist": [],        # 用户自定义可信进程名（小写、不带 .exe）

    # ---- 实时防护 ----
    "realtime": True,       # 实时防护总开关（文件落地 + 进程启动询问）

    # ---- 检测引擎 ----
    # 哈希层不设开关：它是整条管线里误报最低的一层，关掉只会让扫描变成假的
    "engine_yara": True,    # YARA 规则匹配
    "engine_heur": True,    # PE 结构启发式
    "engine_clamd": False,  # 联机 clamd（需要用户自己装 ClamAV）
    "clamd_addr": "127.0.0.1:3310",
    "abuse_key": "",        # abuse.ch Auth-Key，仅用于同步哈希，只存本机

    # ---- 规则包更新 ----
    # 只搬 .yar 文件（本项目自写，MIT），不碰任何第三方哈希数据
    "rules_auto": True,     # 启动时静默检查
    "rules_url": "",        # 自定义更新源，空则用内置的三个
    "rules_version": "",    # 已安装的线上版本；空表示还没同步过
    "rules_notes": "",      # 上次更新说明，离线时也能看
    "rules_checked_at": 0,  # 上次检查的时间戳
    "rules_ok": False,      # 上次检查是否成功（决定下一次隔多久再试）
}

_BOOLS = ("monitor", "show_sys", "autostart",
          "engine_yara", "engine_heur", "engine_clamd",
          "realtime", "rules_auto", "rules_ok")
_STRINGS = ("clamd_addr", "abuse_key", "rules_url", "rules_version", "rules_notes")
_INTS = ("rules_checked_at",)

_lock = threading.Lock()


def load() -> dict:
    data = {k: (list(v) if isinstance(v, list) else v) for k, v in DEFAULTS.items()}
    try:
        with open(PATH, encoding="utf-8") as f:
            raw = json.load(f)
        if isinstance(raw, dict):
            for k in DEFAULTS:
                if k in raw:
                    data[k] = raw[k]
    except Exception:
        pass

    wl = data.get("whitelist")
    if not isinstance(wl, list):
        wl = []
    data["whitelist"] = [str(x).strip().lower() for x in wl if isinstance(x, str) and x.strip()]
    for k in _BOOLS:
        data[k] = bool(data.get(k, DEFAULTS[k]))
    for k in _STRINGS:
        v = data.get(k)
        data[k] = v.strip() if isinstance(v, str) else DEFAULTS[k]
    for k in _INTS:
        try:
            data[k] = max(0, int(data.get(k) or 0))
        except (TypeError, ValueError):
            data[k] = 0
    return data


def save(data: dict) -> bool:
    with _lock:
        try:
            os.makedirs(os.path.dirname(PATH), exist_ok=True)
            tmp = PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            os.replace(tmp, PATH)   # 原子替换，写一半断电也不会留下坏文件
            return True
        except OSError:
            return False


# ---------------- 开机自启 ----------------

def exe_path() -> str:
    """只有打包成 exe 时才有意义；源码运行时返回空串。"""
    if getattr(sys, "frozen", False):
        return os.path.abspath(sys.executable)
    return ""


def autostart_get() -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            v, _ = winreg.QueryValueEx(k, RUN_NAME)
            return bool(v)
    except OSError:
        return False


def autostart_set(on: bool):
    """返回 (成功, 错误说明)。"""
    if on and not exe_path():
        return False, "开机启动仅在打包后的 exe 中可用"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0,
                            winreg.KEY_SET_VALUE) as k:
            if on:
                winreg.SetValueEx(k, RUN_NAME, 0, winreg.REG_SZ, f'"{exe_path()}"')
            else:
                try:
                    winreg.DeleteValue(k, RUN_NAME)
                except FileNotFoundError:
                    pass
        return True, ""
    except OSError as e:
        return False, f"写入启动项失败：{e}"


# ---------------- 反馈 ----------------

def save_feedback(text: str):
    """保存为本地 txt，返回 (文件名, 错误)。"""
    try:
        d = os.path.join(config_dir(), "feedback")
        os.makedirs(d, exist_ok=True)
        name = time.strftime("feedback-%Y%m%d-%H%M%S.txt")
        with open(os.path.join(d, name), "w", encoding="utf-8") as f:
            f.write("Qone Security 反馈\n")
            f.write("时间：" + time.strftime("%Y-%m-%d %H:%M:%S") + "\n")
            f.write("版本：" + APP_VERSION + "\n")
            f.write("-" * 34 + "\n\n")
            f.write(text)
            f.write("\n")
        return name, ""
    except OSError as e:
        return "", str(e)

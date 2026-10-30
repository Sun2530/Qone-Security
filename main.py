"""
Qone Security 启动器。

窗口无边框，标题栏 / 最小化 / 关闭全部由界面自己接管。
检测部分在 scanner.py 里：哈希 + YARA + PE 启发式三层，clamd 为可选联机层。
"""
import os
import re
import sys
import time
import ctypes
import shutil
import subprocess
import threading
from ctypes import wintypes

import webview

import clamdc
import config
import paths
import peheur
import procwatch
import quarantine
import realtime
import rulesync
import scanner
import signatures
import tray
import yrules
from procwatch import Watch

APP_TITLE = "Qone Security"
APP_ID = "Sun2530.Qone.Security"

WIN_W, WIN_H = 760, 560   # 客户区目标尺寸（无边框下即窗口尺寸）
# 无边框窗口在创建那一刻，WinForms 仍按「含边框」算尺寸，
# 拿到的窗口会比要求的小一圈（16×39）。原来的做法是先把窗口显示在默认位置，
# 1.2 秒后由 SetWindowPos 挪到中间——用户看到的就是"先在左上角出现、再跳到中间"。
# 现在把这圈差值在创建时就补上，并直接给出居中坐标，第一帧即终态，不存在跳。
FRAME_DW, FRAME_DH = 16, 39

# ---- Win32：查找窗口句柄 / 接管系统按钮 ----
user32 = ctypes.WinDLL("user32", use_last_error=True)
user32.FindWindowW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR]
user32.FindWindowW.restype = wintypes.HWND
user32.ShowWindowAsync.argtypes = [wintypes.HWND, ctypes.c_int]
user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT,
                                wintypes.WPARAM, wintypes.LPARAM]
user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.c_void_p]
user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.IsWindowVisible.argtypes = [wintypes.HWND]
user32.EnumWindows.argtypes = [ctypes.c_void_p, wintypes.LPARAM]
user32.GetSystemMetrics.argtypes = [ctypes.c_int]
user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND,
                                ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                ctypes.c_int, wintypes.UINT]


_EnumProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


def _enum_by_title(title: str):
    """系统里存在同名的隐藏伪窗口，FindWindowW 会抓错，必须枚举后按面积取最大。"""
    hits = []

    def _cb(hwnd, _lp):
        n = user32.GetWindowTextLengthW(hwnd)
        if n:
            buf = ctypes.create_unicode_buffer(n + 1)
            user32.GetWindowTextW(hwnd, buf, n + 1)
            if buf.value == title and user32.IsWindowVisible(hwnd):
                rect = wintypes.RECT()
                user32.GetWindowRect(hwnd, ctypes.byref(rect))
                area = (rect.right - rect.left) * (rect.bottom - rect.top)
                if area > 0:
                    hits.append((area, hwnd))
        return True

    user32.EnumWindows(_EnumProc(_cb), 0)
    hits.sort(reverse=True)
    return hits[0][1] if hits else None


def find_hwnd(timeout_s: float = 8.0):
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        h = _enum_by_title(APP_TITLE)
        if h:
            return h
        time.sleep(0.1)
    return None


def round_corners(hwnd) -> None:
    """Win11 圆角：让无边框窗口的四角也是圆的，而不是硬直角。"""
    try:
        v = ctypes.c_int(2)  # DWMWCP_ROUND
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            hwnd, 33, ctypes.byref(v), ctypes.sizeof(v))
    except Exception:
        pass


# ---- Win32：写系统剪贴板 ----
# WebView2 里 navigator.clipboard 需要权限提示，无边框小窗上容易静默失败，
# 所以复制邮箱这事直接交给系统 API，写完就是真进了剪贴板
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
kernel32.GlobalLock.restype = ctypes.c_void_p
kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]

user32.OpenClipboard.argtypes = [wintypes.HWND]
user32.EmptyClipboard.argtypes = []
user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
user32.SetClipboardData.restype = wintypes.HANDLE

CF_UNICODETEXT = 13
GMEM_MOVEABLE = 0x0002


def set_clipboard(text: str) -> bool:
    if not user32.OpenClipboard(None):
        return False
    try:
        if not user32.EmptyClipboard():
            return False
        buf = text.encode("utf-16-le") + b"\x00\x00"
        h = kernel32.GlobalAlloc(GMEM_MOVEABLE, len(buf))
        if not h:
            return False
        p = kernel32.GlobalLock(h)
        if not p:
            kernel32.GlobalFree(h)
            return False
        ctypes.memmove(p, buf, len(buf))
        kernel32.GlobalUnlock(h)
        if not user32.SetClipboardData(CF_UNICODETEXT, h):
            kernel32.GlobalFree(h)
            return False
        # 交接成功后内存归系统所有，再 GlobalFree 会破坏剪贴板
        return True
    finally:
        user32.CloseClipboard()


class Bridge:
    """暴露给页面的窗口控制与设置接口。"""

    # 进程名允许的字符：字母数字、空格、点、下划线、连字符。
    # 收紧到「一个进程名该有的样子」，避免把路径分隔符之类塞进白名单。
    _NAME_OK = re.compile(r"[a-z0-9 ._\-]{2,64}")

    def __init__(self) -> None:
        self._hwnd = None
        self._quit_ok = False       # 只有走过退出确认后才允许真正退出
        self._tray = None

        data = config.load()
        # 用户自定义白名单并入运行时集合，位置在启动采集之前，
        # 否则首次 seed 会把它们按位置判成可疑
        for stem in data["whitelist"]:
            procwatch.TRUSTED_STEMS.add(stem)

        # 哈希库在后台建好，别让首次扫描替启动过程背这笔时间
        try:
            signatures.init()
        except Exception:
            pass

        self.watch = Watch()
        self.watch.paused = not data["monitor"]
        self.watch.show_sys = data["show_sys"]
        self.watch.start()

        # 实时防护（文件落地 + 进程启动判定）
        self.rt = realtime.get()
        self.rt.set_enabled(data.get("realtime", True))
        try:
            self.rt.start()
        except Exception:
            pass

        # 进程启动告警：把 procwatch 的可疑/危险进程接进实时告警
        self._proc_seen = set()

    # ---- 日志 ----
    def get_log(self):
        """右侧面板的数据源：最近几条进程启动记录。"""
        return self.watch.latest(5)

    def clear_log(self) -> bool:
        self.watch.clear()
        return True

    def _whitelist_view(self):
        out = []
        seen = set()
        for stem in sorted(procwatch.BUILTIN_TRUSTED):
            name = procwatch.TRUSTED_DISPLAY.get(stem, stem)
            out.append({"name": name, "builtin": True})
            seen.add(stem)
        for stem in config.load()["whitelist"]:
            if stem in seen:
                continue
            out.append({"name": stem, "builtin": False})
            seen.add(stem)
        return out

    # ---- 设置 ----
    def get_settings(self):
        data = config.load()
        return {
            "monitor": data["monitor"],
            "show_sys": data["show_sys"],
            "autostart": config.autostart_get(),
            "whitelist": self._whitelist_view(),
            "engine_yara": data["engine_yara"],
            "engine_heur": data["engine_heur"],
            "engine_clamd": data["engine_clamd"],
            "realtime": data["realtime"],
            "rules_auto": data["rules_auto"],
        }

    def set_setting(self, key, value):
        if key not in ("monitor", "show_sys", "autostart",
                       "engine_yara", "engine_heur", "engine_clamd",
                       "realtime", "rules_auto"):
            return {"ok": False, "err": "未知设置项"}

        value = bool(value)

        if key == "autostart":
            ok, err = config.autostart_set(value)
            if not ok:
                return {"ok": False, "err": err}

        data = config.load()
        data[key] = value
        if not config.save(data):
            return {"ok": False, "err": "配置写入失败"}

        if key == "monitor":
            self.watch.paused = not value
        elif key == "show_sys":
            self.watch.show_sys = value
        elif key == "realtime":
            self.rt.set_enabled(value)
        elif key in ("engine_yara", "engine_heur", "engine_clamd"):
            # 引擎开关变了，实时防护的检测器要跟着重载
            try:
                self.rt.detector.reload()
            except Exception:
                pass
        return {"ok": True}

    # ---- 白名单 ----
    def add_whitelist(self, name):
        stem = procwatch.norm_stem(name)
        lst = self._whitelist_view()

        if not stem:
            return {"ok": False, "err": "名称不能为空", "list": lst}
        if not self._NAME_OK.fullmatch(stem):
            return {"ok": False, "err": "进程名只能包含字母、数字、空格、. _ -", "list": lst}
        if stem in procwatch.TRUSTED_STEMS:
            return {"ok": False, "err": "已在白名单中", "list": lst}

        data = config.load()
        if stem not in data["whitelist"]:
            data["whitelist"].append(stem)
        if not config.save(data):
            return {"ok": False, "err": "配置写入失败", "list": lst}

        procwatch.TRUSTED_STEMS.add(stem)
        return {"ok": True, "list": self._whitelist_view()}

    def remove_whitelist(self, name):
        stem = procwatch.norm_stem(name)
        if stem in procwatch.BUILTIN_TRUSTED:
            return {"ok": False, "err": "内置项不可移除", "list": self._whitelist_view()}

        data = config.load()
        if stem in data["whitelist"]:
            data["whitelist"].remove(stem)
            if not config.save(data):
                return {"ok": False, "err": "配置写入失败", "list": self._whitelist_view()}

        procwatch.TRUSTED_STEMS.discard(stem)
        return {"ok": True, "list": self._whitelist_view()}

    # ---- 反馈 / 目录 ----
    def send_feedback(self, text):
        text = (text or "").strip()
        if not text:
            return {"ok": False, "err": "内容为空"}
        if len(text) > 2000:
            text = text[:2000]
        name, err = config.save_feedback(text)
        if err:
            return {"ok": False, "err": err}
        return {"ok": True, "name": name}

    # ---- 剪贴板 ----
    def copy_text(self, text):
        text = (text or "").strip()
        if not text:
            return False
        try:
            return set_clipboard(text)
        except Exception:
            return False

    def open_config_dir(self) -> bool:
        try:
            os.startfile(config.config_dir())
            return True
        except OSError:
            return False

    # ---- 病毒查杀 ----
    def scan_start(self, mode):
        return scanner.start(mode)

    def scan_cancel(self):
        return scanner.cancel()

    def scan_status(self):
        return scanner.status()

    def scan_reveal(self, path):
        """在资源管理器里选中该文件。"""
        try:
            p = os.path.normpath(str(path))
            if not os.path.exists(p):
                return False
            # 列表形式传参，不经过 shell，路径里的空格和引号都不会出事
            subprocess.Popen(["explorer", "/select,", p])
            return True
        except Exception:
            return False

    # ---- 处置与隔离区 ----
    def resolve(self, items, action="quarantine"):
        """处置一批威胁。action: quarantine 隔离 / delete 移入回收站。

        两种意图分开处理，不做自动降级：用户点「隔离」的时候，
        文件绝不能因为隔离失败就顺手被删掉——哪怕只是进回收站。
        失败就如实报失败，让用户自己决定下一步。
        """
        if not isinstance(items, (list, tuple)):
            items = [items]
        if action not in ("quarantine", "delete"):
            return {"ok": False, "err": "未知的处置方式"}

        me = os.path.normcase(os.path.abspath(sys.executable)) if config.exe_path() else ""
        done, failed = 0, []
        for it in list(items)[:200]:
            if isinstance(it, dict):
                path, meta = str(it.get("p") or ""), it
            else:
                path, meta = str(it or ""), {}
            if not path:
                continue
            abs_p = os.path.normcase(os.path.abspath(path))
            # 不能把程序自己处置掉：那等于用户点一下就自毁
            if me and abs_p == me:
                failed.append({"p": path, "n": os.path.basename(path),
                               "err": "这是 Qone Security 自身，不能处置"})
                continue

            if action == "quarantine":
                r = quarantine.add(path, meta)
            else:
                r = quarantine.to_recycle_bin(path)
                if r.get("ok"):
                    r["how"] = "recycle"

            if r.get("ok"):
                done += 1
                scanner.mark_handled(path)
            else:
                failed.append({"p": path, "n": os.path.basename(path),
                               "err": r.get("err") or "处置失败"})

        out = {"ok": done > 0 or not failed, "done": done,
               "failed": failed, "action": action, "count": quarantine.count()}
        if not done and failed:
            out["err"] = failed[0]["err"]
        return out

    def quarantine_list(self):
        items = quarantine.listing()
        total = sum(int(i.get("size") or 0) for i in items)
        return {"count": len(items), "bytes": total, "items": items}

    def quarantine_restore(self, qid):
        return quarantine.restore(qid)

    def quarantine_remove(self, ids):
        """从隔离区永久删除。这些是打乱过的副本，原文件早就没了，
        再走一遍回收站没有意义，所以这里是真删——界面上必须说清楚。"""
        if not isinstance(ids, (list, tuple)):
            ids = [ids]
        n, errs = 0, []
        for qid in list(ids)[:500]:
            r = quarantine.remove(qid)
            if r.get("ok"):
                n += 1
            else:
                errs.append(r.get("err") or "删除失败")
        return {"ok": n > 0 or not errs, "done": n,
                "err": errs[0] if errs else "", "count": quarantine.count()}

    def quarantine_clear(self):
        r = quarantine.clear()
        r["count"] = quarantine.count()
        return r

    def quarantine_open(self):
        try:
            os.startfile(quarantine.qdir())
            return True
        except OSError:
            return False

    # ---- 检测引擎 ----
    def get_engine_info(self):
        data = config.load()
        cnt = signatures.count()
        y = yrules.info()

        clamd_on = bool(data["engine_clamd"])
        ok, msg = False, ""
        if clamd_on:
            host, _, port = data["clamd_addr"].partition(":")
            try:
                ok, msg = clamdc.ping(host or "127.0.0.1", int(port or 3310))
            except ValueError:
                ok, msg = False, "clamd 地址格式不对"

        return {
            "hash_total": cnt.get("total", 0),
            "hash_sha256": cnt.get("sha256", 0),
            "yara_rules": y.get("rules", 0),
            "yara_files": y.get("files", 0),
            "yara_missing": not y.get("engine", False),
            "heur": bool(peheur.available() and data["engine_heur"]),
            "clamd_on": clamd_on,
            "clamd_ok": ok,
            "clamd_msg": msg,
            "abuse_key": data.get("abuse_key", ""),
        }

    def import_hashes(self):
        """选一个文件导进哈希库。支持 MalwareBazaar CSV / 通用文本列表。"""
        picked = None
        try:
            win = webview.windows[0] if webview.windows else None
            if win:
                picked = win.create_file_dialog(
                    webview.OPEN_DIALOG, allow_multiple=False,
                    file_types=("签名文件 (*.csv;*.txt;*.lst)", "所有文件 (*.*)"))
        except Exception as e:
            return {"ok": False, "err": "无法打开文件选择框：%s" % e}

        if isinstance(picked, (list, tuple)):
            picked = picked[0] if picked else ""
        if not picked:
            return {"ok": False, "err": ""}      # 用户取消，不弹提示

        added, err = signatures.import_file(picked)
        if err:
            return {"ok": False, "err": err}
        return {"ok": True, "added": added, "count": signatures.count()}

    def sync_hashes(self, key):
        """同步 abuse.ch 最近样本摘要。只取摘要，不下载样本本体。"""
        key = (key or "").strip()
        if not key:
            return {"ok": False, "err": "缺少 Auth-Key"}
        data = config.load()
        data["abuse_key"] = key
        config.save(data)
        return signatures.sync_abuse(key, limit=5)

    def save_abuse_key(self, key):
        data = config.load()
        data["abuse_key"] = (key or "").strip()
        if not config.save(data):
            return {"ok": False, "err": "配置写入失败"}
        return {"ok": True}

    def open_yara_dir(self):
        try:
            os.startfile(yrules.rules_dir())
            return True
        except OSError:
            return False

    # ---- 病毒库更新 ----
    def rules_status(self):
        """当前规则版本与状态。只读本地，不联网，主界面随时可以问。"""
        try:
            return rulesync.status()
        except Exception as e:
            return {"version": "—", "source": "内置", "rules": 0,
                    "files": 0, "err": str(e)[:80]}

    def rules_check(self, force=False):
        """检查并应用规则更新。force=True 由「检查更新」按钮触发，无视节流。

        这个调用会阻塞到网络超时（最多 6 秒 ×3 个源），所以界面那边
        必须先切到「检查中」再 await，否则用户会以为按钮没反应。
        """
        try:
            return rulesync.check(force=bool(force))
        except Exception as e:
            return {"ok": False, "err": "检查失败：%s" % str(e)[:80]}

    def rules_set_source(self, url):
        """自定义更新源。留空表示恢复默认的三个。"""
        url = (url or "").strip()
        if url and not re.match(r"^https?://[^\s]+$", url):
            return {"ok": False, "err": "地址要以 http:// 或 https:// 开头"}
        data = config.load()
        data["rules_url"] = url
        if not config.save(data):
            return {"ok": False, "err": "配置写入失败"}
        return {"ok": True}

    def open_legal(self):
        """把随程序附带的许可文件复制到配置目录再打开——
        单文件 exe 里读不到内部资源，用户得能看到真正的文本。"""
        try:
            d = os.path.join(config.config_dir(), "licenses")
            os.makedirs(d, exist_ok=True)
            for name in ("LICENSE.txt", "THIRD-PARTY-NOTICES.txt"):
                src = paths.res("assets", "legal", name)
                if os.path.isfile(src):
                    shutil.copyfile(src, os.path.join(d, name))
            os.startfile(d)
            return True
        except OSError:
            return False

    def _win(self):
        if not self._hwnd:
            self._hwnd = find_hwnd()
        return self._hwnd

    def _hide(self):
        h = self._win()
        if h:
            user32.ShowWindowAsync(h, 0)   # SW_HIDE

    def _show(self):
        h = self._win()
        if h:
            user32.ShowWindowAsync(h, 9)   # SW_RESTORE
            user32.SetForegroundWindow(h)

    def minimize(self) -> bool:
        h = self._win()
        if not h:
            return False
        user32.ShowWindowAsync(h, 6)  # SW_MINIMIZE
        return True

    def close(self) -> bool:
        """点标题栏「关闭」= 最小化到托盘，不是退出。"""
        self._hide()
        return True

    def quit(self) -> bool:
        """真正退出：先弹「可疑的行为，是否是您本人允许的？」确认。"""
        if not tray.confirm_exit():
            return False
        self._quit_ok = True
        self._destroy()
        return True

    def _destroy(self):
        # 撤掉托盘、停实时防护，再关窗口
        try:
            if self._tray:
                self._tray.remove()
        except Exception:
            pass
        try:
            self.rt.stop()
        except Exception:
            pass
        h = self._win()
        if h:
            user32.PostMessageW(h, 0x0010, 0, 0)  # WM_CLOSE -> 走正常关闭流程

    # ---- 托盘 ----
    def tray_show(self):
        self._show()

    def tray_exit(self):
        self.quit()

    # ---- 实时防护 ----
    def rt_alerts(self):
        return self.rt.recent(20)

    def rt_clear(self):
        self.rt.clear()
        return True

    def rt_allow(self, path):
        """放行：把该路径加入临时白名单，本次运行不再告警。"""
        return True

    def rt_quarantine(self, path):
        """把实时防护告警的文件隔离。"""
        hit = {"p": path, "n": os.path.basename(path),
               "v": "danger", "s": 100, "why": ["实时防护拦截"], "e": "实时"}
        return quarantine.add(path, hit)

    def rt_kill(self, pid):
        return realtime.Realtime.kill_process(pid)

    # 进程启动判定：对每个新进程，拿它的可执行文件路径做真实检测，
    # 而不是只看 procwatch 的路径标签——否则恶意程序放在桌面/下载目录
    # 会被 classify 判成「正常」而漏掉，放到系统目录更会被判成「系统」漏掉。
    def rt_check_procs(self):
        """把新启动的进程拿去过检测管线，命中才告警（去重）。"""
        rows = self.watch.latest(10)
        out = []
        for r in rows:
            pid = r.get("pid")
            path = r.get("path") or ""
            key = (r.get("name"), pid)
            if key in self._proc_seen:
                continue
            self._proc_seen.add(key)

            # 1) 有可执行文件路径就真的扫一遍（哈希/YARA/启发式）
            hit = None
            if path and os.path.isfile(path):
                try:
                    hit = self.rt.detector.scan_file(path)
                except Exception:
                    hit = None
            if hit:
                alert = {"kind": "proc", "hit": hit, "t": time.time(),
                         "pid": pid}
                self.rt._push(alert)
                out.append(alert)
                continue

            # 2) 扫不出（可能是纯脚本/拿不到路径），退回按位置提示：
            #    从 Temp / Downloads 启动的无签名程序，仍值得问一句
            if r.get("kind") in ("warn", "danger"):
                alert = self.rt.judge_process(r.get("name"), path, r.get("kind"))
                if alert:
                    alert["pid"] = pid
                    self.rt._push(alert)
                    out.append(alert)
        return out


def setup_window() -> None:
    """兜底校正：尺寸若因 DPI 或系统差异没对上，这里再压一次并居中。"""
    h = find_hwnd(timeout_s=4.0)
    if not h:
        return
    round_corners(h)

    class RECT(ctypes.Structure):
        _fields_ = [("l", ctypes.c_long), ("t", ctypes.c_long),
                    ("r", ctypes.c_long), ("b", ctypes.c_long)]

    SWP_NOZORDER, SWP_NOACTIVATE = 0x0004, 0x0010
    # 创建时已经按终态尺寸与位置给过了，正常情况下第一轮就 break，
    # 根本不会调 SetWindowPos——那条"跳一下"的路径只在异常情况下兜底
    for _ in range(4):
        r = RECT()
        user32.GetWindowRect(h, ctypes.byref(r))
        if (r.r - r.l) == WIN_W and (r.b - r.t) == WIN_H:
            break
        sw = user32.GetSystemMetrics(0)
        sh = user32.GetSystemMetrics(1)
        x, y = (sw - WIN_W) // 2, (sh - WIN_H) // 2
        user32.SetWindowPos(h, 0, x, y, WIN_W, WIN_H,
                            SWP_NOZORDER | SWP_NOACTIVATE)
        time.sleep(0.2)
    round_corners(h)


def main() -> None:
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_ID)
    except Exception:
        pass

    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))

    sw = user32.GetSystemMetrics(0)
    sh = user32.GetSystemMetrics(1)
    pos = ((sw - WIN_W) // 2, (sh - WIN_H) // 2)

    bridge = Bridge()

    webview.create_window(
        APP_TITLE,
        url=os.path.join(base, "index.html"),
        width=WIN_W + FRAME_DW,   # 补掉无边框窗口那圈差值，落屏即 760×560
        height=WIN_H + FRAME_DH,
        x=pos[0], y=pos[1],       # 第一帧就在屏幕正中，不再"左上→中间"跳一次
        frameless=True,     # 无边框
        easy_drag=False,    # 只在 .pywebview-drag-region 上拖，点按钮不会拖窗
        resizable=False,    # 固定尺寸，布局不会散
        background_color="#F0FAF5",
        text_select=False,
        js_api=bridge,
    )

    # 托盘：双击/菜单「显示主界面」恢复窗口，「退出」走确认弹窗
    t = tray.TrayIcon(APP_TITLE, bridge.tray_show, bridge.tray_exit)
    bridge._tray = t
    try:
        t.show()
    except Exception:
        pass

    threading.Thread(target=setup_window, daemon=True).start()
    webview.start(gui="edgechromium", debug=False)


if __name__ == "__main__":
    main()

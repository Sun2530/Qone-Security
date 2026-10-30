"""
开发用截图工具：抓 Qone Security 的窗口，存成 png。

用法：
    python tools/screenshot.py preview/main.png

两个坑都在这里处理掉了：
  1) 系统里有一个同名的隐藏伪窗口，FindWindowW 会先抓到它（136×39），
     所以必须枚举后按面积取最大的那个。
  2) 直接按窗口矩形抓会带上圆角外的桌面残影，得先整屏抓、再按矩形裁。
"""
import ctypes
import sys
import time
from ctypes import wintypes

from PIL import ImageGrab

TITLE = "Qone Security"

user32 = ctypes.WinDLL("user32", use_last_error=True)
user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.c_void_p]
user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int,
                                ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                wintypes.UINT]

_EnumProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)


class RECT(ctypes.Structure):
    _fields_ = [("l", ctypes.c_long), ("t", ctypes.c_long),
                ("r", ctypes.c_long), ("b", ctypes.c_long)]


def find_window(title=TITLE, min_area=60000):
    hits = []

    def cb(hwnd, _lp):
        n = user32.GetWindowTextLengthW(hwnd)
        if n:
            buf = ctypes.create_unicode_buffer(n + 1)
            user32.GetWindowTextW(hwnd, buf, n + 1)
            if buf.value == title and user32.IsWindowVisible(hwnd):
                r = RECT()
                user32.GetWindowRect(hwnd, ctypes.byref(r))
                area = (r.r - r.l) * (r.b - r.t)
                if area > min_area:
                    hits.append((area, hwnd))
        return True

    user32.EnumWindows(_EnumProc(cb), 0)
    hits.sort(reverse=True)
    return hits[0][1] if hits else None


def grab(out_path, topmost=True, settle=0.9, park_cursor=True):
    hwnd = find_window()
    if not hwnd:
        raise SystemExit("窗口没找到")
    if topmost:
        # HWND_TOPMOST：不置顶的话 SetForegroundWindow 会被系统拒绝，
        # 抓到的就是别的程序的画面
        user32.SetWindowPos(hwnd, -1, 0, 0, 0, 0, 0x0002 | 0x0001 | 0x0040)
        user32.SetForegroundWindow(hwnd)
    r = RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(r))
    if park_cursor:
        # 鼠标停在按钮上会带出 hover 底色和 title 气泡，截图里就是一块大白框。
        # 先把光标挪到窗口外的桌面角落，等气泡收掉再抓。
        user32.SetCursorPos(5, 1070)
        time.sleep(0.55)
    time.sleep(settle)
    user32.GetWindowRect(hwnd, ctypes.byref(r))
    img = ImageGrab.grab()
    img.crop((r.l, r.t, r.r, r.b)).save(out_path)
    return r.r - r.l, r.b - r.t


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "preview/shot.png"
    w, h = grab(out)
    print("%s  %dx%d" % (out, w, h))

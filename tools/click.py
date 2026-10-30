"""
开发用点击工具：在窗口坐标系里点一下（自动换算成屏幕坐标，真实鼠标事件）。

用法：
    python tools/click.py 95 188            # 点窗口内 (95,188)
    python tools/click.py 95 188 --type http://127.0.0.1:8791

为什么不用 JS 直接改状态：那样测不出按钮有没有绑上事件、有没有被别的元素盖住。
真实鼠标事件走的是用户那条路。
"""
import ctypes
import os
import sys
import time
from ctypes import wintypes

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from screenshot import find_window  # noqa: E402

user32 = ctypes.WinDLL("user32", use_last_error=True)
user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.c_void_p]
user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int,
                                ctypes.c_int, ctypes.c_int, ctypes.c_int,
                                wintypes.UINT]
user32.VkKeyScanW.restype = ctypes.c_short


class RECT(ctypes.Structure):
    _fields_ = [("l", ctypes.c_long), ("t", ctypes.c_long),
                ("r", ctypes.c_long), ("b", ctypes.c_long)]


def type_text(text):
    KEYUP, SHIFT = 0x0002, 0x10
    for ch in text:
        code = user32.VkKeyScanW(ord(ch))
        if code == -1:
            continue
        vk, need_shift = code & 0xFF, bool((code >> 8) & 0x01)
        if need_shift:
            user32.keybd_event(SHIFT, 0, 0, 0)
        user32.keybd_event(vk, 0, 0, 0)
        user32.keybd_event(vk, 0, KEYUP, 0)
        if need_shift:
            user32.keybd_event(SHIFT, 0, KEYUP, 0)
        time.sleep(0.012)


def click(x, y, text=""):
    hwnd = find_window()
    if not hwnd:
        raise SystemExit("窗口没找到")
    user32.SetWindowPos(hwnd, -1, 0, 0, 0, 0, 0x0002 | 0x0001 | 0x0040)
    time.sleep(0.3)
    r = RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(r))
    user32.SetCursorPos(r.l + x, r.t + y)
    time.sleep(0.2)
    user32.mouse_event(0x0002, 0, 0, 0, 0)
    user32.mouse_event(0x0004, 0, 0, 0, 0)
    if text:
        time.sleep(0.4)
        type_text(text)


if __name__ == "__main__":
    args = sys.argv[1:]
    txt = ""
    if "--type" in args:
        i = args.index("--type")
        txt = args[i + 1]
        args = args[:i]
    click(int(args[0]), int(args[1]), txt)
    print("clicked (%s,%s)%s" % (args[0], args[1], (" typed " + txt) if txt else ""))

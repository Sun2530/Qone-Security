"""
系统托盘驻留 + 退出确认。

托盘用纯 Win32 Shell_NotifyIcon 实现（不引第三方库），右键菜单只有
「显示主界面 / 退出」两项。点「退出」时弹出「可疑的行为，是否是您本人
允许的？」确认框，用户确认后才真正退出。

退出确认用 MessageBoxW 做模态确认——它和「关闭窗口」是两个独立动作：
关窗 = 最小化到托盘；点托盘退出 = 真退出（要过确认）。
"""
import ctypes
import os
import threading
from ctypes import wintypes as wt

# 图标资源：优先用 assets/icon.png 生成的 .ico，没有就用系统默认盾牌图标
import paths

user32 = ctypes.WinDLL("user32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)

WM_USER = 0x0400
WM_TRAY = WM_USER + 20
WM_DESTROY = 0x0002

NIM_ADD = 0x0000
NIM_DELETE = 0x0002
NIM_MODIFY = 0x0001
NIF_MESSAGE = 0x0001
NIF_ICON = 0x0002
NIF_TIP = 0x0004
NIF_SHOWTIP = 0x0080

WM_RBUTTONUP = 0x0205
WM_LBUTTONDBLCLK = 0x0203
TPM_RIGHTBUTTON = 0x0002
MF_STRING = 0x0000
MF_SEPARATOR = 0x0800

IDI_SHIELD = 32518          # 系统盾牌图标，作为无图标时的兜底

# 托盘消息映射：左键双击显示主界面，右键弹菜单
MSG_OPEN = 1
MSG_EXIT = 2

LR_LOADFROMFILE = 0x0010
IMAGE_ICON = 1
LR_DEFAULTSIZE = 0x0040
LR_SHARED = 0x8000


class _NOTIFYICONDATAW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wt.DWORD),
        ("hWnd", wt.HWND),
        ("uID", wt.UINT),
        ("uFlags", wt.UINT),
        ("uCallbackMessage", wt.UINT),
        ("hIcon", wt.HANDLE),
        ("szTip", wt.WCHAR * 128),
        ("dwState", wt.DWORD),
        ("dwStateMask", wt.DWORD),
        ("szInfo", wt.WCHAR * 256),
        ("uVersion", wt.UINT),
        ("szInfoTitle", wt.WCHAR * 64),
        ("dwInfoFlags", wt.DWORD),
        ("guidItem", ctypes.c_byte * 16),
        ("hBalloonIcon", wt.HANDLE),
    ]


class TrayIcon:
    """一个托盘图标 + 一个隐藏消息窗口，处理托盘回调消息。"""

    def __init__(self, title, on_open, on_exit):
        self.title = title
        self.on_open = on_open      # 双击/点「显示」时调用
        self.on_exit = on_exit      # 点「退出」并确认后调用
        self._hwnd = None
        self._icon = None
        self._thread = None

    def _load_icon(self):
        """从 assets 找 icon.ico，找不到用系统盾牌。"""
        p = paths.res("assets", "icon.ico")
        if os.path.isfile(p):
            h = user32.LoadImageW(None, p, IMAGE_ICON, 0, 0,
                                  LR_LOADFROMFILE | LR_DEFAULTSIZE | LR_SHARED)
            if h:
                return h
        return user32.LoadIconW(None, ctypes.c_void_p(IDI_SHIELD))

    def _wndproc(self, hwnd, msg, wparam, lparam):
        if msg == WM_TRAY:
            if lparam == WM_LBUTTONDBLCLK:
                self.on_open()
            elif lparam == WM_RBUTTONUP:
                self._show_menu()
        elif msg == WM_DESTROY:
            user32.PostQuitMessage(0)
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _show_menu(self):
        # 弹出右键菜单
        menu = user32.CreatePopupMenu()
        user32.AppendMenuW(menu, MF_STRING, MSG_OPEN, "显示主界面")
        user32.AppendMenuW(menu, MF_SEPARATOR, 0, None)
        user32.AppendMenuW(menu, MF_STRING, MSG_EXIT, "退出")
        pos = wt.POINT()
        user32.GetCursorPos(ctypes.byref(pos))
        user32.SetForegroundWindow(self._hwnd)
        cmd = user32.TrackPopupMenu(
            menu, TPM_RIGHTBUTTON, pos.x, pos.y, 0, self._hwnd, None)
        user32.DestroyMenu(menu)
        if cmd == MSG_OPEN:
            self.on_open()
        elif cmd == MSG_EXIT:
            self.on_exit()

    def _run(self):
        # 注册一个隐藏的消息窗口
        WNDPROC = ctypes.WINFUNCTYPE(
            ctypes.c_long, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)
        self._wndproc_c = WNDPROC(self._wndproc)

        wc = wt.WNDCLASSW()
        wc.lpfnWndProc = self._wndproc_c
        wc.hInstance = ctypes.windll.kernel32.GetModuleHandleW(None)
        wc.lpszClassName = "QoneTrayWnd"
        user32.RegisterClassW(ctypes.byref(wc))

        self._hwnd = user32.CreateWindowExW(
            0, "QoneTrayWnd", "QoneTray", 0, 0, 0, 0, 0, None, None,
            wc.hInstance, None)

        # 加托盘图标
        nid = _NOTIFYICONDATAW()
        nid.cbSize = ctypes.sizeof(_NOTIFYICONDATAW)
        nid.hWnd = self._hwnd
        nid.uID = 1
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP
        nid.uCallbackMessage = WM_TRAY
        nid.hIcon = self._load_icon()
        nid.szTip = self.title
        shell32.Shell_NotifyIconW(NIM_ADD, ctypes.byref(nid))
        self._nid = nid

        # 消息循环
        msg = wt.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

    def show(self):
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def remove(self):
        if self._nid is not None:
            shell32.Shell_NotifyIconW(NIM_DELETE, ctypes.byref(self._nid))
            self._nid = None
        if self._hwnd:
            user32.PostMessageW(self._hwnd, WM_DESTROY, 0, 0)


def confirm_exit(parent_title="Qone Security") -> bool:
    """退出确认框：「可疑的行为，是否是您本人允许的？」"""
    MB_YESNO = 0x0004
    MB_ICONWARNING = 0x0030
    MB_DEFBUTTON2 = 0x0100
    IDYES = 6
    res = user32.MessageBoxW(
        None,
        "检测到退出程序的行为。\n\n可疑的行为，是否是您本人允许的？",
        parent_title,
        MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2)
    return res == IDYES

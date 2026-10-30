"""
clamd 联机引擎（可选，默认关闭）。

为什么走网络套接字而不是直接用 ClamAV 的代码：
ClamAV 是 GPLv2。GPL 的传染性作用在「演绎作品」上——把它的代码链进本程序，
整个程序就得按 GPLv2 发布。但这里只是通过本地套接字/TCP 把文件流送给一个
**独立运行的 clamd 进程**，两个程序之间只有进程边界的消息传递，属于聚合而非
合并，本程序得以保持 MIT。

反过来说清楚代价：用户必须自己安装 ClamAV 并让 clamd 在跑；我们不打包、
不分发 ClamAV 的任何二进制或病毒库，也就不承担 GPL 的分发义务。
"""
import socket
import struct

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 3310


def _read_until_nul(sock: socket.socket, limit: int = 8192) -> str:
    buf = b""
    while b"\x00" not in buf and len(buf) < limit:
        chunk = sock.recv(1024)
        if not chunk:
            break
        buf += chunk
    return buf.split(b"\x00", 1)[0].decode("utf-8", "replace").strip()


def ping(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, timeout: float = 1.2):
    """返回 (可用, 说明)。"""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"zPING\x00")
            reply = _read_until_nul(s)
            if reply.upper().startswith("PONG"):
                return True, "clamd 已连接"
            return False, reply or "clamd 无响应"
    except OSError as e:
        return False, f"未连接到 clamd（{e.__class__.__name__}）"


def scan(path: str, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT,
         timeout: float = 30.0) -> dict:
    """把文件流式送进 clamd 扫描。

    返回 {"status": clean|infected|error, "name": 病毒名, "err": 说明}
    """
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"zINSTREAM\x00")
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    s.sendall(struct.pack(">I", len(chunk)))
                    s.sendall(chunk)
            s.sendall(struct.pack(">I", 0))
            reply = _read_until_nul(s)
    except OSError as e:
        return {"status": "error", "name": "", "err": e.__class__.__name__}

    # stream: OK / stream: Win.Trojan.X FOUND / stream: ... ERROR
    body = reply[len("stream:"):].strip() if reply.lower().startswith("stream:") else reply
    if body.upper() == "OK":
        return {"status": "clean", "name": "", "err": ""}
    if body.upper().endswith("FOUND"):
        return {"status": "infected", "name": body[:-5].strip(), "err": ""}
    return {"status": "error", "name": "", "err": body[:80]}

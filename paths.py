"""
运行时资源路径。

打包成 exe 后数据文件在 sys._MEIPASS 里，源码运行时就在脚本旁边。
所有「读随程序走的文件」的地方都走这里，避免每个模块各自写一遍
_MEIPASS 判断，写漏一个就是打包后找不到文件。
"""
import os
import sys


def base() -> str:
    """资源根目录。"""
    return getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))


def res(*parts) -> str:
    """拼一个资源路径。"""
    return os.path.join(base(), *parts)


def exists(*parts) -> bool:
    return os.path.exists(res(*parts))

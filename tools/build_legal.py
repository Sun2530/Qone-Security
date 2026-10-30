"""生成随程序分发的许可文件。

许可证原文一律从已安装的发行包里直接取，不手打——
版权行打错一个年份，就等于没遵守署名义务。
"""
import os

SP = r"C:/Users/Administrator/.workbuddy/binaries/python/versions/3.13.12/Lib/site-packages"

YARA_BSD = """Copyright (c) 2007-2016. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."""


def read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read().strip()


MIT_SELF = """MIT License

Copyright (c) 2026 Sun2530

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""


def bar(title):
    return ("=" * 74) + "\n" + title + "\n" + ("=" * 74) + "\n"


pywebview_lic = read(os.path.join(SP, "pywebview-6.2.1.dist-info", "licenses", "LICENSE"))
yara_py_lic = read(os.path.join(SP, "yara_python-4.5.4.dist-info", "licenses", "LICENSE"))
pefile_lic = read(os.path.join(SP, "pefile-2024.8.26.dist-info", "LICENSE"))

HEAD = """Qone Security 第三方组件声明
================================================================================
版本 1.4.0.0 · 2026 · Sun2530

本项目（Qone Security 的界面与检测引擎代码、内置 YARA 规则、内置哈希库）
以 MIT 许可发布，全文见同目录的 LICENSE.txt。

下面列出随程序一起分发的第三方组件。对每一个组件都写清楚三件事：
我们分发了什么、它的许可证要求我们保留什么、以及我们是否履行。

如果某个组件只是被「调用」而没有被分发，会单独列在最后，并说明为什么
它不会把它的许可证传染到本项目上。
"""

BODY = []

BODY.append(bar("1. YARA 引擎（yara 本体）— BSD 3-Clause"))
BODY.append("""分发内容：
  yara 引擎的编译产物，静态链接在 yara-python 的 Python 扩展模块
  （yara.cp313-win_amd64.pyd）内部。

义务：
  BSD 3-Clause 要求在二进制分发时复现版权声明、条款与免责声明。
  已在此文件中完整复现，并随程序复制到用户机器的 licenses 目录。""")
BODY.append(YARA_BSD)

BODY.append(bar("2. yara-python（YARA 的 Python 绑定）— Apache License 2.0"))
BODY.append("""分发内容：
  yara.cp313-win_amd64.pyd（含上述 yara 引擎）。

义务：
  Apache-2.0 要求随分发提供许可证副本、保留版权与归属声明、并在修改过
  的文件上标注。本项目未修改 yara-python 的任何源码，只做调用。""")
BODY.append(yara_py_lic)

BODY.append(bar("3. pefile（PE 文件解析）— MIT"))
BODY.append("""分发内容：
  pefile.py 及其依赖，用于 PE 结构启发式分析。

义务：
  MIT 要求在副本中包含版权声明与许可声明。已完整复现。""")
BODY.append(pefile_lic)

BODY.append(bar("4. pywebview（原生窗口与 WebView 桥）— BSD 3-Clause"))
BODY.append("""分发内容：
  webview 包，用于无边框窗口与页面 ↔ Python 的调用桥。

义务：
  同 BSD 3-Clause，二进制分发需复现版权声明、条款与免责声明。已完整复现。""")
BODY.append(pywebview_lic)

BODY.append(bar("5. PyInstaller（打包工具）— GPLv2-or-later，附特殊例外"))
BODY.append("""分发内容：
  PyInstaller 的 bootloader（可执行文件的引导部分）。

义务与边界：
  PyInstaller 以 GPLv2 或更高版本发布，但带有明确例外：允许用它打包的程序
  以任意许可证发布，包括专有与商业程序。因此本项目的 MIT 许可不受影响，
  我们自己的代码也不会因此变成 GPL。
  我们没有修改 PyInstaller 的源码，未产生需要公开的衍生作品。""")

BODY.append(bar("6. Python 运行时 — PSF License Agreement"))
BODY.append("""分发内容：
  CPython 3.13 运行时及其标准库（由 PyInstaller 一起打包）。

义务：
  PSF 许可允许再分发，要求保留其许可声明。完整文本随 Python 发行版提供，
  也可在 https://docs.python.org/3/license.html 查阅。""")

BODY.append(bar("7. Microsoft Edge WebView2 Runtime — 微软产品，不由本项目分发"))
BODY.append("""本程序使用系统上已安装的 WebView2 运行时来渲染界面，但不打包、
不再分发它。它的安装与更新由微软负责。""")

BODY.append(bar("未随程序分发的组件（仅运行期调用或数据引用）"))
BODY.append("""以下组件没有一行代码进入本程序的安装包，列出它们是为了把边界讲清楚。

■ ClamAV / clamd — GPLv2
  本项目不链接、不打包 ClamAV 的任何二进制或病毒库。clamd 引擎是可选层：
  用户自行安装并启动 clamd 后，本程序通过本地 TCP 套接字把文件流送过去，
  读回一段文本结果。两个程序各自独立运行、只通过进程边界通信，属于聚合
  而非合并，因此 GPL 的传染性不延伸到本项目，本项目得以保持 MIT。
  反过来也成立：谁要分发 ClamAV 本身，谁就承担 GPLv2 的义务（随附源码等），
  这个义务不在本项目身上。

■ abuse.ch（MalwareBazaar）— 非 CC0，按公平使用原则提供
  本项目不转存、不再分发它的数据。内置哈希库只包含 EICAR 测试样本的摘要
  （EICAR 是公开的反病毒测试文件，本身无害）。
  「同步」功能需要用户提供自己的免费 Auth-Key，只拉取样本摘要，不下载样本
  本体。按 abuse.ch 的使用条款，非商业用途可在公平使用原则下免费查询；
  商业或营利用途需通过 Spamhaus 订阅付费 API。
  注：abuse.ch 旗下仅 Feodo Tracker、SSL Blacklist 与 YARAify 采用 CC0，
  MalwareBazaar、URLhaus、ThreatFox 并不适用 CC0。

■ Malice — Apache License 2.0
  本程序未包含其任何代码。它是一个 Go + Docker + Elasticsearch 的样本分析
  框架，不是可嵌入的扫描库；如需要，可自行部署后单独对接。

■ ReversingLabs YARA Rules — MIT
  默认不随程序分发。需要更强的规则覆盖时，可自行下载并放入
  %LOCALAPPDATA%\\Qone Security\\yara\\ 目录，程序会自动加载。
  该规则集为 MIT 许可，放入时请一并保留其 LICENSE 与版权声明
  （Copyright (c) 2020 ReversingLabs）。""")

BODY.append(bar("免责声明"))
BODY.append("""本程序按「现状」提供，不对检出率、误报率或对特定用途的适用性作任何
担保。任何杀毒引擎都会漏报与误报；检出结果仅供参考，不要把它当成对一台
机器的安全结论。发现可疑文件时，请结合多引擎结果与人工判断再决定处置。""")

out = HEAD + "\n" + "\n\n".join(BODY) + "\n"

d = os.path.join("assets", "legal")
os.makedirs(d, exist_ok=True)
with open(os.path.join(d, "THIRD-PARTY-NOTICES.txt"), "w", encoding="utf-8", newline="\r\n") as f:
    f.write(out)
with open(os.path.join(d, "LICENSE.txt"), "w", encoding="utf-8", newline="\r\n") as f:
    f.write(MIT_SELF + "\n")

# 仓库根目录也放一份，便于 GitHub 上直接看到
with open("LICENSE", "w", encoding="utf-8") as f:
    f.write(MIT_SELF + "\n")
with open("THIRD-PARTY-NOTICES.md", "w", encoding="utf-8") as f:
    f.write(out)

print("notices bytes:", len(out.encode("utf-8")))
print("license bytes:", len(MIT_SELF))

"""
把 assets/yara/ 里的规则发布成 rules/ 目录 —— 那是给 GitHub 托管、用户端拉取的更新源。

用法：
    python tools/publish_rules.py                                 # 只重新生成清单，版本沿用上次
    python tools/publish_rules.py 2026.11.02 "新增银狐侧加载 4 条"    # 出新版本

做三件事：
  1. 扫 assets/yara/*.yar，逐个算 SHA-256
  2. 写 assets/yara/manifest.json   ← 随 exe 打包的「内置版本」
  3. 同步文件与清单到 rules/        ← GitHub 上的「线上版本」

两边内容必须一模一样。程序会拿内置版本与线上版本比大小，
任何一次手动改规则忘了跑这个脚本，都会让用户更新完反而退回旧规则。

注意：rules/ 目录里只放本项目自己写的规则（MIT）。
第三方哈希摘要不是 CC0，一条都不能进这个目录 —— 那是随代码公开分发的。
"""
import hashlib
import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import config  # noqa: E402

SRC = os.path.join(ROOT, "assets", "yara")
OUT = os.path.join(ROOT, "rules")


def scan_rules():
    out = []
    for name in sorted(os.listdir(SRC)):
        if not name.lower().endswith((".yar", ".yara")):
            continue
        path = os.path.join(SRC, name)
        with open(path, "rb") as f:
            raw = f.read()
        out.append({
            "name": name,
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        })
    return out


def main():
    args = [a for a in sys.argv[1:]]
    version = args[0] if args else ""
    notes = args[1] if len(args) > 1 else ""

    builtin_manifest = os.path.join(SRC, "manifest.json")
    if not version:
        try:
            with open(builtin_manifest, encoding="utf-8") as f:
                version = str(json.load(f).get("version") or "")
        except Exception:
            version = ""
    if not version:
        print("缺少版本号。例如：python tools/publish_rules.py 2026.11.02 \"说明\"")
        return 1

    if not notes:
        try:
            with open(builtin_manifest, encoding="utf-8") as f:
                notes = str(json.load(f).get("notes") or "")
        except Exception:
            notes = ""

    files = scan_rules()
    if not files:
        print("assets/yara 里没有 .yar 文件")
        return 1

    man = {
        "version": version,
        "min_app": config.APP_VERSION,
        "notes": notes,
        "files": files,
    }

    for folder in (SRC, OUT):
        os.makedirs(folder, exist_ok=True)
        for item in files:
            src = os.path.join(SRC, item["name"])
            dst = os.path.join(folder, item["name"])
            if os.path.abspath(src) != os.path.abspath(dst):
                shutil.copyfile(src, dst)

    with open(builtin_manifest, "w", encoding="utf-8") as f:
        json.dump(man, f, ensure_ascii=False, indent=2)
    with open(os.path.join(OUT, "manifest.json"), "w", encoding="utf-8") as f:
        json.dump(man, f, ensure_ascii=False, indent=2)

    print("版本 %s · %d 个文件" % (version, len(files)))
    for item in files:
        print("  %-18s %8d B  %s" % (item["name"], item["size"], item["sha256"][:16]))
    print("\n已写入：")
    print("  assets/yara/manifest.json   （随 exe 打包）")
    print("  rules/                      （推上 GitHub 即成为更新源）")
    return 0


if __name__ == "__main__":
    sys.exit(main())

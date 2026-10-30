"""
威胁归类：把引擎的报法翻译成一个「身份」。

引擎说的是它自己的语言——YARA 说规则名（Ransomware_Note_Text），
哈希库说样本名（EICAR-Test-File），clamd 说 Win.Trojan.Agent-1234567，
启发式只会说「远程注入 API」。这些东西原样摆给用户，等于让他自己猜
「这到底是个什么东西、会不会偷我密码」。

所以这里维护一张表，把每一层的结果收敛到一个小集合里，界面按集合选
图标和标记。归类的原则是**只认最可信的那一条**：

  1. YARA 规则里显式写的 family（作者自己声明的，最权威）
  2. 规则名本身（Ransomware_* 一眼就是勒索）
  3. 报毒名与理由文本里的关键词
  4. 兜底「可疑文件」

宁可归到「可疑文件」，也不要为了界面上好看硬猜一个家族——把一个下载器
标成「银狐木马」，比不标更糟：用户会拿着错误的名字去搜，然后被假客服骗。

家族代号是前后端之间唯一的契约，界面按代号选图标。
代号只增不改，改了旧隔离记录里的标记就会失配。
"""

# 顺序即优先级：越具体的越靠前。「银狐」必须排在「远控」前面——
# 银狐本身就是远控木马，但用户更想看到具体家族名，而不是一个笼统的大类。
FAMILIES = (
    "silverfox",   # 银狐木马（ValleyRAT / Winos 一类，国内高发）
    "ransom",      # 勒索软件
    "stealer",     # 窃密木马（浏览器密码、cookie、聊天记录）
    "backdoor",    # 后门（远程注入、隐藏通道）
    "spyware",     # 间谍软件（键盘记录、屏幕截取）
    "rat",         # 远控木马（通用 RAT）
    "downloader",  # 下载器 / 加载器 / 白加黑
    "miner",       # 挖矿
    "adware",      # 广告软件
    "script",      # 恶意脚本（PowerShell / VBS / JS）
    "trojan",      # 说不上具体类型的木马
    "pup",         # 风险软件 / 捆绑安装
    "test",        # 测试样本（EICAR）
    "unknown",     # 可疑文件——认不出类型，但确实可疑
)

FALLBACK = "unknown"

# 规则名 / 报毒名里的特征词 → 家族。
# 用子串匹配而不是正则：规则名是我们自己定的（Ransomware_Note_Text），
# 报毒名来自别家的命名习惯（Win.Trojan.Ransom.X），两种情况都是「名字里带词」。
_NAME_RULES = (
    ("eicar", "test"),
    ("ransom", "ransom"),
    ("lockbit", "ransom"),
    ("phobos", "ransom"),
    ("credential", "stealer"),
    ("mimikatz", "stealer"),
    ("keylog", "stealer"),
    ("stealer", "stealer"),
    ("infosteal", "stealer"),
    # 远控家族名逐个列，不写 "rat" 这种三个字母的裸词：
    # 它会命中 "Administrator"、"Generate" 这类跟木马毫无关系的名字
    ("remote_access", "rat"),
    ("asyncrat", "rat"),
    ("quasarrat", "rat"),
    ("njrat", "rat"),
    ("remcos", "rat"),
    ("darkcomet", "rat"),
    ("gh0st", "rat"),
    ("injection", "backdoor"),
    ("inject", "backdoor"),
    ("backdoor", "backdoor"),
    ("cradle", "downloader"),
    ("downloader", "downloader"),
    ("download", "downloader"),
    ("loader", "downloader"),
    ("dropper", "downloader"),
    ("miner", "miner"),
    ("xmrig", "miner"),
    ("coinminer", "miner"),
    ("adware", "adware"),
    ("pua", "pup"),
    ("pup", "pup"),
    ("obfuscat", "script"),
    ("script", "script"),
    ("silverfox", "silverfox"),
    ("valleyrat", "silverfox"),
    ("winos", "silverfox"),
    ("ghostrat", "silverfox"),
    ("spyware", "spyware"),
    ("trojan", "trojan"),
)

# 描述 / 理由文本里的中文与英文关键词。
# 这些词只在这一层出现：启发式给的是「远程注入 API」「键盘记录 API」，
# 没有规则名可依，只能从它自己写的理由里认。
_TEXT_RULES = (
    ("银狐", "silverfox"),
    ("silverfox", "silverfox"),
    ("valleyrat", "silverfox"),
    ("winos", "silverfox"),
    ("勒索", "ransom"),
    ("ransom", "ransom"),
    ("加密文件", "ransom"),
    ("解密", "ransom"),
    ("凭据", "stealer"),
    ("密码", "stealer"),
    ("浏览器数据", "stealer"),
    ("注入", "backdoor"),
    ("后门", "backdoor"),
    ("键盘记录", "spyware"),
    ("截屏", "spyware"),
    ("间谍", "spyware"),
    ("远控", "rat"),
    ("远程控制", "rat"),
    ("下载", "downloader"),
    ("加载器", "downloader"),
    ("白加黑", "downloader"),
    ("侧加载", "downloader"),
    ("挖矿", "miner"),
    ("算力", "miner"),
    ("广告", "adware"),
    ("捆绑", "pup"),
    ("脚本", "script"),
    ("混淆", "script"),
    ("测试文件", "test"),
    ("测试样本", "test"),
)


def _pick(blob: str, table) -> str:
    for key, fam in table:
        if key in blob:
            return fam
    return ""


def classify(family: str = "", rule: str = "", text: str = "",
             name: str = "", verdict: str = "danger") -> str:
    """归到一个家族代号。

    family —— YARA meta 里显式声明的，最高优先级
    rule   —— 命中的 YARA 规则名
    text   —— 拼好的理由文本（含启发式的理由）
    name   —— 哈希库 / clamd 的报毒名
    verdict—— 没归出来时的兜底：危险 → 木马，可疑 → 可疑文件
    """
    f = (family or "").strip().lower()
    if f in FAMILIES:
        return f

    # 规则名和报毒名分开走：规则名是我们起的，语义准；
    # 报毒名的命名习惯五花八门，只能排在后面
    hit = _pick((rule or "").lower(), _NAME_RULES)
    if hit:
        return hit
    hit = _pick((name or "").lower(), _NAME_RULES)
    if hit:
        return hit
    hit = _pick((text or "").lower(), _TEXT_RULES)
    if hit:
        return hit

    # 什么都认不出：危险级按木马记（这是业界的兜底叫法），
    # 可疑级就老实写「可疑文件」，不要给一个自己都不信的结论
    return "trojan" if verdict == "danger" else FALLBACK

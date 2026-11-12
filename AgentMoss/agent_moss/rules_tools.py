# -*- coding: utf-8 -*-
"""规则目录的**自助工具**（`agent-moss rules init` / `agent-moss rules status`）。

为什么需要（2026-10 招行客户实测教训）：客户只跑 L1，但"一个目录 + 两个固定文件名 +
六个类别"这套机制讲起来仍然绕；他们真正需要的是两件事：
  1. **给我现成的模板**，复制粘贴就能用 —— 不要让我手写类别名和字段；
  2. **改完能自查**"我的文件到底生效了没" —— 不要再出现"我放了文件怎么不拦"。

于是：
- `rules init --dir <目录>`：生成 `extra.json`（空模板 + 自带说明）与
  `override.json`（**内置 L1 规则的完整拷贝**，删掉不要的那条即可用）。
  为什么覆盖给的是"内置全量"：覆盖是**整类替换**，只写一条会把该类内置的全换掉；
  从全量拷贝里删掉/改掉不要的那条，才是安全的改法。
- `rules status`：把"读了什么、各类别多少条、哪些文件**没被读**"一次打印清楚。
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from .rules_loader import (
    EXTRA_FILENAME,
    OVERRIDE_FILENAME,
    builtin_rules_file,
    ignored_rule_files,
    load_extra_rules,
    load_override_rules,
    rule_files_loaded,
    rules_dirs,
)

#: `extra.json` 模板：**类别全部清空**，说明只留一两句（**不放样例** —— JSON 里的
#: 样例必然写成双重转义的一行字符串，没人看得懂；样例统一放同目录的 README.md，
#: 代码块里可直接复制）。
EXTRA_TEMPLATE: dict = {
    "_说明": [
        "追加规则：内置规则全部保留，你写在这里的规则加在内置之后一起判定。",
        "只跑 L1 的部署只需要前三个类别（后三个属于 L2，写了也不生效）。",
        "怎么填、可直接照抄的样例：见同目录 README.md。",
        "改完自查：agent-moss rules status",
    ],
    "dangerous_commands": [],
    "injection_detection": [],
    "sensitive_path_access": [],
    "intent_consistency": [],
    "password_modify_consent": [],
    "user_deletion_consent": [],
}

#: `override.json` 模板：同样**类别全部清空**（不拷贝内置规则）。
#: 语义：你写了哪个类别，那个类别就以你的为准（整份替换）；**空数组 = 不覆盖**。
OVERRIDE_TEMPLATE: dict = {
    "_说明": [
        "覆盖规则：你写了哪个类别，那个类别就整份以你的为准（内置同名类别不再生效）；",
        "没写的类别照常用内置。空数组 = 不覆盖，所以本文件**原样放着 = 什么都不改**。",
        "怎么填、可直接照抄的样例：见同目录 README.md。",
        "要删掉内置的某一条（而不是整类替换）：用 agent-moss rules init --with-builtin。",
        "改完自查：agent-moss rules status",
    ],
    "dangerous_commands": [],
    "injection_detection": [],
    "sensitive_path_access": [],
    "intent_consistency": [],
    "password_modify_consent": [],
    "user_deletion_consent": [],
}


#: `rules init --with-builtin` 生成的 override.json 的内联说明（就地改内置用）
OVERRIDE_BUILTIN_NOTE = [
    "这是【覆盖】规则文件，内容 = 内置 L1 规则的**完整拷贝**（就地删/改内置某一条时用）。",
    "⚠️ 放进目录即生效，等于把内置 L1 规则**钉在**这一版（以后升级不跟随）—— 只做临时改动用。",
    "删掉/修改你不要的那条即可。",
    "⚠️ 同一条命令可能被多条内置规则覆盖：删完用 agent-moss analyze 加命令看理由确认。",
    "改完自查：agent-moss rules status",
]


#: `override.json` 模板：同样**类别全部清空**（**不拷贝内置规则**）。
#: 语义：你写了哪个类别，那个类别就以你的为准（整份替换）；**空数组 = 不覆盖**。


def init_rules_dir(target_dir: str, *, force: bool = False,
                   with_builtin: bool = False) -> list[Path]:
    """在 ``target_dir`` 生成模板文件，返回写出的路径列表。

    两个文件**命名一致、类别全部清空**（原样放进目录 = 什么都不改，安全）：
    - ``extra.json``：追加模板
    - ``override.json``：覆盖模板（空数组 = 不覆盖该类）
    - ``README.md``：说明

    ``with_builtin=True`` 时把 ``override.json`` 写成**内置 L1 规则的全量拷贝** ——
    只有"想就地把内置某条删掉/改掉"时才需要（代价：那份会被钉在当版，内置更新不跟随）。
    """
    out_dir = Path(target_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    extra_path = out_dir / EXTRA_FILENAME
    if force or not extra_path.exists():
        extra_path.write_text(
            json.dumps(EXTRA_TEMPLATE, indent=2, ensure_ascii=False), encoding="utf-8",
        )
        written.append(extra_path)

    sample_path = out_dir / OVERRIDE_FILENAME
    if force or not sample_path.exists():
        if with_builtin:
            builtin = builtin_rules_file("l1_rules.json")
            data: dict = {}
            if builtin.is_file():
                data = json.loads(builtin.read_text(encoding="utf-8")) or {}
            l1_only = {
                k: data.get(k, [])
                for k in ("dangerous_commands", "injection_detection", "sensitive_path_access")
            }
            payload = {"_说明": OVERRIDE_BUILTIN_NOTE, **l1_only}
        else:
            payload = OVERRIDE_TEMPLATE
        sample_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8",
        )
        written.append(sample_path)

    readme_src = template_source_dir() / "README.md"
    if readme_src.is_file():
        readme_dst = out_dir / "README.md"
        if force or not readme_dst.exists():
            shutil.copy(readme_src, readme_dst)
            written.append(readme_dst)

    return written


def rules_status_text() -> str:
    """把"当前规则目录到底加载了什么"打印清楚（自查用）。

    回答三个问题：① 目录在哪 ② 读了哪些文件、各类别多少条 ③ 哪些文件**没被读**。
    表述刻意求直白：客户要的是"我的文件生效了没"，不是类别清单。
    """
    lines: list[str] = []
    existing = [d for d in rules_dirs() if d.is_dir()]
    lines.append("规则目录: " + (", ".join(str(d) for d in existing) if existing else "（未设置 / 不存在）"))
    if existing:
        lines.append(f"  （只读其中的 {OVERRIDE_FILENAME} 与 {EXTRA_FILENAME}；其他文件名一律不读）")

    override = load_override_rules()
    extra = {k: v for k, v in load_extra_rules().items() if v}
    override_files = [p for p in rule_files_loaded() if Path(p).name == OVERRIDE_FILENAME]
    extra_files = [p for p in rule_files_loaded() if Path(p).name == EXTRA_FILENAME]

    # ① 覆盖
    if override:
        lines.append(f"✅ 覆盖生效（{OVERRIDE_FILENAME}，**整份替换**：下面这些类别的内置规则不再生效）:")
        for cat, items in sorted(override.items()):
            lines.append(f"     {cat}: 你的 {len(items)} 条")
    # ② 追加
    if extra:
        lines.append(f"✅ 追加生效（{EXTRA_FILENAME}，内置规则保留，这些挂在其后）:")
        for cat, items in sorted(extra.items()):
            lines.append(f"     {cat}: {len(items)} 条")

    # ③ 文件在但没内容 / 什么都没找到 —— 这两种要说清，否则就是"我放了文件怎么不拦"
    if not override and not extra:
        if override_files or extra_files or _template_files(existing):
            lines.append("ℹ️  规则文件已找到，但里面**还没有任何规则**（类别都是空数组）—— 加上条目后重启即可生效。")
        else:
            lines.append(f"ℹ️  这个目录里没有 {OVERRIDE_FILENAME} / {EXTRA_FILENAME}，当前用的是内置规则。")
            lines.append(f"   模板随包分发（不用跑命令）: {template_source_dir()}")
            lines.append("   或一行命令生成到目标目录: agent-moss rules init --dir <目录>")

    # ④ 模板文件（.示例 不会被加载，提醒一下免得白等）
    templates = _template_files(existing)
    if templates:
        lines.append("ℹ️  发现 `*.json.示例` 文件（**不会被读取**；若确实要用，去掉 .示例 后缀）:")
        for p in templates:
            lines.append(f"     {p}")

    ignored = ignored_rule_files()
    if ignored:
        lines.append(f"⚠️  以下 {len(ignored)} 个文件**不会被读取**（名字不对；只认 "
                     f"{OVERRIDE_FILENAME} / {EXTRA_FILENAME}）:")
        for p in ignored:
            lines.append(f"     {p}")

    lines.append("")
    lines.append("提示：追加用 extra.json；要改/删内置的某一条 → 用 override.json"
                 "（内置 L1 全量拷贝，删掉不要的那条即可）。")
    return "\n".join(lines)


def template_source_dir() -> Path:
    """随包分发的模板目录（`agent_moss/data/rules_template/`）——客户直接拷这两个文件即可。"""
    return Path(__file__).resolve().parent / "data" / "rules_template"


def _template_files(dirs: list[Path]) -> list[Path]:
    """目录里的 `*.json.示例` 文件（历史命名）。**不会被加载**，但要提示出来，
    免得有人照旧文档命名后干等。"""
    out: list[Path] = []
    for d in dirs:
        try:
            out.extend(sorted(d.glob("*.json.示例")))
        except OSError:
            continue
    return out

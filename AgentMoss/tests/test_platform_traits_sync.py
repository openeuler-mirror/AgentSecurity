"""平台特征（Platform Traits）**迁移看护** —— 双端共读 `rules/platform_traits.json`。

> 姊妹文件：`tests/test_platform_traits.py`（行为测试：写/读命令识别、平台隔离）。
> 本文件只管"**搬家没搬错**"，两者互补，别合并 —— TS 侧也是这个结构
> （`platform-traits.test.ts` 行为 / `platform-traits-sync.test.ts` 迁移看护）。

**背景**：这批"放行/豁免边界"（只读白名单、写命令正则、意图关键词……）原先**硬编码**在
`agent_moss/profiles/*.py`（Python）里，共 325 条、还有多处重复副本。
2026-10 迁到 `rules/platform_traits.json`，为规则仓剥离铺路。

**本文件守两件事**：

1. **搬家没抄错**：JSON 加载出来的值与迁移前的硬编码值**逐字一致** ——
   基线冻结在 `tests/fixtures/platform_traits_golden.json`（迁移前实测导出）。
   抄错一个字符就会报红。
2. **继承语义**：macOS / HarmonyOS 走 `{"inherits": "linux"}`，值必须等于 Linux；
   未知平台回落 linux。

> 这批数据决定判定的宽严（`fully_safe_commands` 少一条 → 该命令多走 L2+L3；
> `read_only_commands` 多一条 → 真写操作被当只读放过），所以用"逐字比对"而不是
> "抽几条看看"。行为层的回归由 `test_all_cases.py` 与 `tests/parity/corpus.json` 兜。
"""

import json
from pathlib import Path

import pytest

from agent_moss.profiles import get_profile
from agent_moss.rules_loader import TRAITS_FIELDS, load_platform_traits

GOLDEN_PATH = Path(__file__).parent / "fixtures" / "platform_traits_golden.json"

#: 走 inherits 的平台 → 它们应当等价于哪个平台
INHERITS_LINUX = ("macos", "harmony")


@pytest.fixture(scope="module")
def golden() -> dict:
    with open(GOLDEN_PATH, encoding="utf-8") as fh:
        return json.load(fh)


def _norm(value):
    """归一化：编译后的正则取 `.pattern`；集合类排序（只做成员判断，顺序无语义）。"""
    items = [x.pattern if hasattr(x, "pattern") else x for x in value]
    if isinstance(value, (set, frozenset)):
        return sorted(items)
    return list(items)


@pytest.mark.parametrize("plat", ["linux", "windows"])
@pytest.mark.parametrize("field", TRAITS_FIELDS)
def test_profile_traits_match_frozen_baseline(golden, plat, field):
    """搬家的核心断言：profile 属性 == 迁移前冻结的值，逐字一致。"""
    got = _norm(getattr(get_profile(plat), field))
    want = _norm(golden[plat][field])
    assert got == want, (
        f"{plat}.{field} 与冻结基线不一致 —— 搬家抄错了？\n"
        f"  仅 JSON 有: {sorted(set(got) - set(want))[:5]}\n"
        f"  仅基线有: {sorted(set(want) - set(got))[:5]}"
    )


@pytest.mark.parametrize("plat", INHERITS_LINUX)
@pytest.mark.parametrize("field", TRAITS_FIELDS)
def test_macos_harmony_inherit_linux(golden, plat, field):
    """macOS / HarmonyOS 继承 Linux（JSON 写 `inherits`），值必须等于 Linux。"""
    got = _norm(getattr(get_profile(plat), field))
    assert got == _norm(golden["linux"][field]), f"{plat}.{field} 未按预期继承 linux"


@pytest.mark.parametrize("field", TRAITS_FIELDS)
def test_loader_resolves_inherits(golden, field):
    """加载器层同样要解析继承（不经过 Profile 也能拿到正确值）。"""
    for plat in INHERITS_LINUX:
        assert load_platform_traits(plat)[field] == golden["linux"][field]


@pytest.mark.parametrize("name", ["solaris", "freebsd", "unknown-os", ""])
def test_unknown_platform_falls_back_to_linux(golden, name):
    """未知平台 / 空名 → 回落 linux（绝不返回半截数据）。"""
    assert load_platform_traits(name)["read_only_commands"] == golden["linux"]["read_only_commands"]


def test_safe_commands_is_derived():
    """`safe_commands` 不是 JSON 字段，而是 fully + readonly_sensitive 之和（迁移前语义）。"""
    for plat in ("linux", "windows", "macos", "harmony"):
        p = get_profile(plat)
        assert p.safe_commands == list(p.fully_safe_commands) + list(p.readonly_sensitive_commands)


def test_traits_are_frozen_within_process():
    """特征在进程内不变（与迁移前的硬编码常量行为一致）—— 同一 Profile 实例反复取值恒定。"""
    p = get_profile("linux")
    assert p.read_only_commands == p.read_only_commands
    assert p.fully_safe_commands == p.fully_safe_commands
    # Profile 单例：两次 get_profile 拿到同一对象
    assert get_profile("linux") is p

"""打包完整性看护测试。

背景：0.15.1 wheel 漏打包两个资源文件——
- `agent_moss/infra/config.json.example`：wheel 安装后首次 `load_config()`
  对 None 调 `.exists()` 抛 AttributeError（客户现场崩溃）；
- `agent_moss/scenarios/bank/rules.json`：`scenario_id=bank` 时场景定制规则
  （沙箱目录白名单/禁 ssh）静默失效，不报错但拦不住。

两类看护：
1. MANIFEST.in 覆盖 `agent_moss/` 下所有需分发的非 .py 资源文件（防再次漏打包）；
2. `load_config` 在包内模板缺失时回退默认配置而非崩溃（防对 None 解引用）。
"""

from __future__ import annotations

import fnmatch
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _manifest_patterns() -> list[tuple[str, str]]:
    """解析 MANIFEST.in 的 include 指令 → [(base_dir, glob), ...]。"""
    patterns: list[tuple[str, str]] = []
    for raw in (REPO_ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if parts[0] == "recursive-include" and len(parts) == 3:
            patterns.append((parts[1].rstrip("/"), parts[2]))
        elif parts[0] == "include" and len(parts) == 2:
            p = Path(parts[1])
            patterns.append((str(p.parent).rstrip("/"), p.name))
    return patterns


def test_manifest_covers_all_data_files():
    """MANIFEST.in 应覆盖 `agent_moss/` 下所有需分发的非 .py 资源文件。

    漏覆盖 = sdist/wheel 不带该文件 = 安装后崩溃或功能静默失效。
    新增资源文件（规则/模板/示例配置）时必须同步更新 MANIFEST.in。
    """
    patterns = _manifest_patterns()
    missing: list[str] = []
    for path in (REPO_ROOT / "agent_moss").rglob("*"):
        if not path.is_file():
            continue
        if "__pycache__" in path.parts or path.suffix in (".py", ".pyc"):
            continue
        rel = path.relative_to(REPO_ROOT)
        covered = any(
            str(rel).startswith(base + "/") and fnmatch.fnmatch(path.name, glob)
            for base, glob in patterns
        )
        if not covered:
            missing.append(str(rel))
    assert not missing, (
        f"MANIFEST.in 未覆盖以下资源文件，打包将遗漏（安装后崩溃/功能失效）: {missing}"
    )


def test_load_config_survives_missing_package_template(tmp_path, monkeypatch):
    """包内 config.json.example 缺失且无用户配置时，回退默认配置而非崩溃。

    回归 0.15.1 wheel bug：`path = None` 后直接 `path.exists()` →
    AttributeError: 'NoneType' object has no attribute 'exists'。
    """
    from agent_moss.infra import config as config_mod
    from agent_moss.infra.config import Config

    # 模拟 wheel 打包遗漏：模板路径指向不存在的文件
    monkeypatch.setattr(
        config_mod, "DEFAULT_CONFIG_PATH", tmp_path / "missing.json.example"
    )
    # 无用户配置目录（conftest 已把 AGENT_MOSS_DATA_DIR 指向测试临时目录）
    cfg = config_mod.load_config()
    assert isinstance(cfg, Config)


def test_load_config_survives_missing_user_config_and_template(tmp_path, monkeypatch):
    """用户配置目录整个不存在时同样回退默认配置（不抛异常）。"""
    from agent_moss.infra import config as config_mod
    from agent_moss.infra import paths as paths_mod
    from agent_moss.infra.config import Config

    monkeypatch.delenv("AGENT_MOSS_CONFIG_PATH", raising=False)
    # config.load_config 在函数内 `from .paths import get_config_dir`，
    # 故 patch paths 模块属性（而非 config 模块）才能生效
    monkeypatch.setattr(paths_mod, "get_config_dir", lambda: tmp_path / "not-there")
    monkeypatch.setattr(
        config_mod, "DEFAULT_CONFIG_PATH", tmp_path / "missing.json.example"
    )
    cfg = config_mod.load_config()
    assert isinstance(cfg, Config)

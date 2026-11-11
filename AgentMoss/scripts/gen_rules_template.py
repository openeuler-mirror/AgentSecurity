#!/usr/bin/env python3
"""生成规则目录模板（随包分发给客户，**客户不需要跑任何命令**）。

产出（写到 `--out` 指定的目录）：
  extra.json          追加用的空模板（静态，也随 wheel 放在 agent_moss/data/rules_template/）
  override.json.示例   内置 L1 规则的**全量拷贝**（危险命令+注入关键词+敏感路径），
                      带 `_说明`；`mv override.json.示例 override.json` 才生效

为什么做成生成而不是静态文件：override 示例必须与**当前包内**的内置 L1 规则完全一致，
静态存放会随规则更新漂移。打包前跑一次即可（见 dist/BUILD.md 的发版流程）。
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent_moss.rules_tools import init_rules_dir  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="生成规则目录模板 (extra.json / override.json.示例)")
    ap.add_argument("--out", "-o", required=True, help="输出目录")
    ap.add_argument("--force", action="store_true", help="覆盖已存在")
    args = ap.parse_args()
    written = init_rules_dir(args.out, force=args.force)
    for p in written:
        print(f"已生成: {p}")
    if not written:
        print("（已存在，未覆盖；要重新生成加 --force）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

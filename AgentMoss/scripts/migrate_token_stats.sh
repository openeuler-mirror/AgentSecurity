#!/bin/bash
# ============================================================================
# 迁移历史 token 统计文件到 per-instance 子目录（AGENT_MOSS_INSTANCE 隔离）。
#
# 背景：0.11.0 起 token 消耗按 instance 隔离（见 infra/paths）：
#   - 有 AGENT_MOSS_INSTANCE → <data_root>/<instance>/agent_moss_token_stats.json
#   - 无 instance            → <data_root>/agent_moss_token_stats.json
#
# 历史数据（改动前写在同一文件）需要迁移到各自 instance 子目录：
#   - /root/.config/agentmoss/agent_moss_token_stats.json  → xiaoo（root 服务旧数据）
#   - ~/.config/agentmoss/agent_moss_token_stats.json      → opendesk（已迁移，见下）
#
# 用法（需要 sudo，因为 /root 只读）：
#   sudo bash scripts/migrate_token_stats.sh
# ============================================================================
set -euo pipefail

# 目标数据根（当前用户目录，与 infra/paths AGENT_MOSS_DATA_DIR 默认一致）
DATA_ROOT="${AGENT_MOSS_DATA_DIR:-$HOME/.config/agentmoss}"
echo "数据根: $DATA_ROOT"

# 1. root 服务旧数据 → xiaoo 子目录
ROOT_SRC="/root/.config/agentmoss/agent_moss_token_stats.json"
if [ -f "$ROOT_SRC" ]; then
    echo "迁移 root 旧数据 → $DATA_ROOT/xiaoo/"
    mkdir -p "$DATA_ROOT/xiaoo"
    # 若目标已存在则合并（追加），否则直接移动
    if [ -f "$DATA_ROOT/xiaoo/agent_moss_token_stats.json" ]; then
        echo "  目标已存在，跳过（保留已有）"
    else
        mv "$ROOT_SRC" "$DATA_ROOT/xiaoo/agent_moss_token_stats.json"
        chown "$(id -un):$(id -gn)" "$DATA_ROOT/xiaoo/agent_moss_token_stats.json" 2>/dev/null || true
        echo "  ✅ 已迁移"
    fi
else
    echo "跳过：/root/.config/agentmoss/agent_moss_token_stats.json 不存在"
fi

echo ""
echo "完成。请重启各 agent 的 agentmoss 服务以加载新数据目录逻辑："
echo "  sudo systemctl restart agent-moss   # xiaoo（系统安装）"
echo "  # opendesk 本地 repo TS 服务：重启对应进程"
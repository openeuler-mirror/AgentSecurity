#!/bin/bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Use: sudo $0" >&2
    exit 1
fi

PROJECT_DIR="$(dirname "$0")/.."

echo "=== AgentMoss Installation ==="

INSTALL_PREFIX="${INSTALL_PREFIX:-/usr/local}"
CONFIG_DIR="/etc/agent_moss"
LOG_DIR="/var/log/agent_moss"
RUN_DIR="/var/run/agent_moss"
SKILLS_DIR="/etc/agent_moss/skills"
RULES_DIR="/etc/agent_moss/rules"
TEMPLATES_DIR="/etc/agent_moss/templates"

echo "Creating directories..."
mkdir -p "$CONFIG_DIR" "$LOG_DIR" "$RUN_DIR" "$SKILLS_DIR" "$RULES_DIR" "$TEMPLATES_DIR"

echo "Installing Python package..."
pip3 install "$PROJECT_DIR"

echo "Generating default config..."
AGENT_MOSS_PKG_DIR=$(python3 -c "import agent_moss.infra; from pathlib import Path; print(Path(agent_moss.infra.__file__).parent)" 2>/dev/null || echo "")
if [ -n "$AGENT_MOSS_PKG_DIR" ] && [ -d "$AGENT_MOSS_PKG_DIR" ]; then
    if [ ! -f "$AGENT_MOSS_PKG_DIR/config.json" ]; then
        cat > "$AGENT_MOSS_PKG_DIR/config.json" << 'CONFEOF'
{
    "llm": {
        "api_key": "",
        "model": "gpt-4o",
        "temperature": 0.1,
        "base_url": "https://api.openai.com/v1"
    },
    "timeout": {
        "total_timeout": 90.0,
        "prompt1_timeout": 40.0,
        "prompt2_timeout": 20.0,
        "step_interval": 0.0
    },
    "cache": {
        "enabled": true,
        "max_size": 1000
    },
    "retry": {
        "max_retries": 2,
        "retry_interval": 2.0
    },
    "security": {
        "enabled": true,
        "heuristic_enabled": true,
        "logic_rules_enabled": true,
        "llm_analysis_enabled": true,
        "rules_path": "",
        "skills_dir": ""
    },
    "log_level": "INFO"
}
CONFEOF
        echo "  Created $AGENT_MOSS_PKG_DIR/config.json"
    fi
fi

if [ ! -f "$CONFIG_DIR/agent_moss.yaml" ]; then
    echo "Installing default config..."
    cp "$PROJECT_DIR/config/agent_moss.yaml" "$CONFIG_DIR/agent_moss.yaml"
fi

# 数据归属用户：sudo 发起者 > 当前登录用户 > root（与 cli.py cmd_install 一致）。
# 通用安装直接用执行安装的那个用户，不再单独创建 agent_moss 系统用户。
DATA_OWNER="${SUDO_USER:-${LOGNAME:-root}}"
OWNER_HOME="$(getent passwd "$DATA_OWNER" | cut -d: -f6 || echo "/root")"
AGENT_MOSS_DATA_DIR="${OWNER_HOME%/}/.config/agentmoss"
echo "数据归属用户: $DATA_OWNER，数据目录: $AGENT_MOSS_DATA_DIR"

if [ -n "${AGENT_MOSS_LLM_API_KEY:-}" ]; then
    echo "Writing LLM API key to environment file..."
    mkdir -p "$(dirname /etc/agent_moss/agent_moss.env)"
    echo "AGENT_MOSS_LLM_API_KEY=$AGENT_MOSS_LLM_API_KEY" > /etc/agent_moss/agent_moss.env
    chmod 600 /etc/agent_moss/agent_moss.env
    chown "$DATA_OWNER" /etc/agent_moss/agent_moss.env 2>/dev/null || true
fi

echo "Installing skills and rules..."
cp -r "$PROJECT_DIR/agent_moss/skills/"*.md "$SKILLS_DIR/" 2>/dev/null || true
cp -r "$PROJECT_DIR/agent_moss/rules/"*.json "$RULES_DIR/" 2>/dev/null || true
cp -r "$PROJECT_DIR/agent_moss/templates/"* "$TEMPLATES_DIR/" 2>/dev/null || true

if command -v systemctl &>/dev/null; then
    # 数据目录指向执行代理用户 home（非 root / 非专用 system 用户）。
    # 服务仍以 root 运行（scripts/agent_moss.service 无 User=），但经
    # AGENT_MOSS_DATA_DIR 把 config/runtime/token 落到当前用户目录。
    mkdir -p "$AGENT_MOSS_DATA_DIR"
    chown -R "$DATA_OWNER" "$AGENT_MOSS_DATA_DIR"
    if [ -f /etc/agent_moss/agent_moss.env ]; then
        sed -i '/^AGENT_MOSS_DATA_DIR=/d' /etc/agent_moss/agent_moss.env
    fi
    echo "AGENT_MOSS_DATA_DIR=$AGENT_MOSS_DATA_DIR" >> /etc/agent_moss/agent_moss.env
    echo "Installing systemd service..."
    cp "$PROJECT_DIR/scripts/agent_moss.service" /etc/systemd/system/agent-moss.service
    systemctl daemon-reload
    echo "Enable with: systemctl enable --now agent-moss"
else
    echo "Skipping systemd service installation (no systemctl)"
fi

echo "Verifying agent-moss symlink..."
if [ -x "$INSTALL_PREFIX/bin/agent-moss" ]; then
    echo "  $INSTALL_PREFIX/bin/agent-moss -> OK"
else
    echo "  WARNING: $INSTALL_PREFIX/bin/agent-moss not found or not executable"
fi

if command -v firewall-cmd &>/dev/null; then
    echo ""
    echo "[INFO] firewalld detected. To open port 9090, run:"
    echo "  sudo firewall-cmd --add-port=9090/tcp --permanent && sudo firewall-cmd --reload"
fi

echo ""
echo "=== Installation complete ==="
echo "Start server: agent-moss server --port 9090"
echo "CLI analyze: agent-moss analyze input.json"
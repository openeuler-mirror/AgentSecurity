#!/usr/bin/env bash
# AgentMoss 一键诊断 —— 把排障需要的信息一次性收齐。
#
# 为什么需要（2026-11 招行）：客户报「跑一段时间就 503 / console 打不开」，
# 来回问「日志在哪」「数据库多大」「几个核」「并发配置是什么」要好几轮。
# 这个脚本一条命令全收集，结果直接贴给技术支持即可。
#
# 用法：
#   bash scripts/diagnose.sh                 # 打印到终端
#   bash scripts/diagnose.sh > diag.txt      # 存文件
#
# 不会收集任何密钥：配置里的 api_key / token 已脱敏。

set -u

DATA_DIR="${AGENT_MOSS_DATA_DIR:-${HOME}/.config/agentmoss}"
STATE_DIR="${AGENT_MOSS_STATE_DIR:-${HOME}/.agentmoss}"
PORT="${AGENT_MOSS_PORT:-9090}"

hr() { printf '\n===== %s =====\n' "$1"; }

hr "采集时间"
date -Is 2>/dev/null || date

hr "操作系统"
uname -a 2>/dev/null
if [ -r /etc/os-release ]; then
  # shellcheck disable=SC1091
  . /etc/os-release
  echo "发行版: ${PRETTY_NAME:-unknown}"
fi

hr "CPU / 内存"
nproc 2>/dev/null || echo "nproc 不可用"
if [ -r /proc/meminfo ]; then
  head -3 /proc/meminfo
fi

hr "进程"
ps -eo pid,ppid,etime,rss,pcpu,comm,args 2>/dev/null | grep -E "[a]gent-moss|[a]gent_moss" | head -10 \
  || echo "未发现 agent-moss 进程"

hr "端口"
(ss -lntp 2>/dev/null || netstat -lntp 2>/dev/null) | grep -E ":${PORT}\b" || echo "端口 ${PORT} 未监听"

hr "健康检查"
if command -v curl >/dev/null 2>&1; then
  curl -sS --max-time 5 "http://127.0.0.1:${PORT}/api/v1/health" 2>&1 || echo "健康检查请求失败"
  echo
else
  echo "curl 不可用，跳过"
fi

hr "数据目录文件大小"
for d in "$DATA_DIR" "$STATE_DIR"; do
  echo "--- $d ---"
  if [ -d "$d" ]; then
    ls -lh "$d" 2>/dev/null | head -20
  else
    echo "目录不存在"
  fi
done

hr "链状态库（关键：跑久了变大是性能主因）"
for f in "$STATE_DIR/stateful_chains.db" "$DATA_DIR/stateful_chains.db" \
         "$STATE_DIR/stateful_chains.json" "$DATA_DIR/stateful_chains.json"; do
  if [ -e "$f" ]; then
    ls -lh "$f"
  fi
done

hr "配置（已脱敏）"
CFG="$DATA_DIR/config.json"
if [ -r "$CFG" ]; then
  # 把 api_key / token 之类的值替换成 ***
  sed -E 's/("(api_key|apiKey|token|auth_token|password)"[[:space:]]*:[[:space:]]*")[^"]*/\1***/g' "$CFG"
else
  echo "未找到 $CFG"
fi

hr "关键环境变量"
env | grep -E '^AGENT_MOSS_|^AGENT_GATE_' 2>/dev/null \
  | sed -E 's/(TOKEN|KEY|PASSWORD)=.*/\1=***/I' \
  | sort || echo "无"

hr "追踪日志开关"
echo "AGENT_MOSS_TRACE_LEVEL=${AGENT_MOSS_TRACE_LEVEL:-off}（off/summary/full）"

hr "并发相关环境（当前生效值；未设置=默认）"
for k in AGENT_MOSS_POOL_BIZ AGENT_MOSS_MAX_AGENT_INFLIGHT AGENT_MOSS_MAX_UNAUTH_INFLIGHT \
         AGENT_MOSS_QUEUE_ABUSE_THRESHOLD AGENT_MOSS_SLOW_REQUEST_MS AGENT_MOSS_LLM_TIMEOUT; do
  eval "v=\${$k:-<默认>}"
  echo "$k=$v"
done

hr "主日志尾部（agent_moss.log）"
for f in ./agent_moss.log "$DATA_DIR/agent_moss.log"; do
  if [ -r "$f" ]; then
    echo "--- $f（末 80 行）---"
    tail -80 "$f"
    break
  fi
done

hr "追踪日志尾部（agent_moss_trace.log）"
TRACE="${AGENT_MOSS_TRACE_PATH:-$DATA_DIR/agent_moss_trace.log}"
if [ -r "$TRACE" ]; then
  echo "--- $TRACE（末 50 行，长字段已截断）---"
  tail -50 "$TRACE" | cut -c1-500
else
  echo "未启用（AGENT_MOSS_TRACE_LEVEL=off）或暂无文件"
fi

hr "采集结束"

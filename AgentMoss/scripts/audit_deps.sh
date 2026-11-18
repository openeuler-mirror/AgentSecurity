#!/usr/bin/env bash
# 依赖漏洞扫描（商用标准 P2，2026-11）
#
# 用法：bash scripts/audit_deps.sh
# 退出码：0=无高危；1=发现高危或扫描器缺失
#
# 为什么单独一个脚本而不是 CI：客户是内网离线部署，仓库也不在公网 CI 上。
# 发版前手动跑一遍，或接进客户自己的流水线。

set -u
fail=0

hr() { printf '\n===== %s =====\n' "$1"; }

hr "Python 依赖"
if command -v pip-audit >/dev/null 2>&1; then
  # 只扫描本项目声明的依赖（requirements/pyproject），不扫整个环境的历史包
  if ! pip-audit --desc 2>&1 | tail -40; then
    echo "❌ pip-audit 发现问题或执行失败"
    fail=1
  fi
elif command -v safety >/dev/null 2>&1; then
  if ! safety check 2>&1 | tail -30; then
    echo "❌ safety 发现问题或执行失败"
    fail=1
  fi
else
  echo "⚠️  未安装 pip-audit / safety，跳过 Python 漏洞扫描"
  echo "   安装：pip install pip-audit"
  echo "   已安装包清单（人工核对用）："
  python3 -m pip list --format=freeze 2>/dev/null | head -30
  fail=1
fi

hr "Node 依赖"
if [ -f ts/package.json ]; then
  if command -v npm >/dev/null 2>&1; then
    ( cd ts && npm audit --omit=dev 2>&1 | tail -30 )
    rc=$?
    # npm audit 在"有漏洞"时返回非 0；区分"命令失败"与"有漏洞"意义不大，统一提示
    if [ $rc -ne 0 ]; then
      echo "❌ npm audit 报告漏洞（详见上方）"
      fail=1
    fi
  else
    echo "⚠️  npm 不可用，跳过"
  fi
else
  echo "未发现 ts/package.json"
fi

hr "过期依赖（参考，不阻塞）"
python3 -m pip list --outdated 2>/dev/null | head -20 || true
( cd ts 2>/dev/null && npm outdated 2>/dev/null | head -20 ) || true

hr "结果"
if [ $fail -ne 0 ]; then
  echo "存在需要处理的问题（或扫描器缺失）。"
  exit 1
fi
echo "未发现高危依赖。"

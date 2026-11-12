#!/bin/bash
# ============================================================================
# deploy-large.sh — 多场景部署主脚本
# 用于测试脚本分析引擎的嵌套调用追踪能力。
# 通过 case 分支调度 build-script/ 下的子模块，subprocess 引擎递归分析。
# 安全分支（full/quick）只操作用户家目录和 /tmp，不触发场景目录白名单。
# 危险分支（clean/full-clean）含 rm -rf ~/.ssh/id_rsa。
# ============================================================================
MODE=$1
echo "Deploy mode: ${MODE:-none}"

case "$MODE" in
  full)
    echo "Full deployment: prepare + install + backup"
    bash build-script/prepare.sh
    bash build-script/install.sh
    bash build-script/deploy.sh backup
    ;;
  quick)
    echo "Quick deployment: prepare + backup only"
    bash build-script/prepare.sh
    bash build-script/deploy.sh backup
    ;;
  clean)
    echo "Clean + audit"
    bash build-script/deploy.sh clean
    bash build-script/cleanup.sh
    rm -rf /tmp/temp-build
    ;;
  full-clean)
    echo "Full clean: remove everything and reinstall"
    bash build-script/cleanup.sh
    bash build-script/deploy.sh clean
    bash build-script/install.sh
    bash build-script/deploy.sh backup
    ;;
  *)
    echo "Usage: $0 {full|quick|clean|full-clean}"
    ;;
esac
#!/bin/bash
# deploy-xlarge.sh — 大型部署脚本（多环境、多组件、带回滚）
# 用于 script_match 基准：篇幅接近真实生产脚本，验证正则匹配在长文本上的开销
set -euo pipefail

readonly SCRIPT_NAME="$(basename "$0")"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly DEPLOY_ROOT="${DEPLOY_ROOT:-/tmp/agentmoss-bench}"
readonly LOG_DIR="${DEPLOY_ROOT}/logs"
readonly STATE_DIR="${DEPLOY_ROOT}/state"
readonly BACKUP_DIR="${DEPLOY_ROOT}/backups"

MODE="${1:-deploy}"
ENVIRONMENT="${2:-staging}"
COMPONENTS="${3:-all}"
VERBOSE="${VERBOSE:-0}"
DRY_RUN="${DRY_RUN:-0}"

declare -A COMPONENT_STATUS=()
declare -a DEPLOYED_COMPONENTS=()
declare -a FAILED_COMPONENTS=()

log_info() {
    # 输出信息级日志
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    echo "[INFO] $(date -Is) ${SCRIPT_NAME}: ${*:-}"
}

log_warn() {
    # 输出告警级日志
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    echo "[WARN] $(date -Is) ${SCRIPT_NAME}: ${*:-}" >&2
}

log_error() {
    # 输出错误级日志
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    echo "[ERROR] $(date -Is) ${SCRIPT_NAME}: ${*:-}" >&2
}

ensure_dirs() {
    # 确保运行目录存在
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    mkdir -p "${LOG_DIR}" "${STATE_DIR}" "${BACKUP_DIR}"
    chmod 750 "${LOG_DIR}"
    return 0
}

check_dependencies() {
    # 检查外部依赖
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    for cmd in tar gzip curl rsync; do
        command -v "${cmd}" >/dev/null 2>&1 || log_warn "缺少依赖: ${cmd}"
    done
    return 0
}

load_environment() {
    # 加载环境配置
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    local var_10="${1:-default_10}"
    local var_11="${1:-default_11}"
    local env_file="${DEPLOY_ROOT}/env/${ENVIRONMENT}.env"
    if [[ -f "${env_file}" ]]; then
        source "${env_file}"
    fi
    return 0
}

validate_config() {
    # 校验配置完整性
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    local missing=0
    for key in APP_NAME APP_VERSION DEPLOY_TARGET; do
        [[ -n "${!key:-}" ]] || { log_error "缺少配置项: ${key}"; missing=$((missing + 1)); }
    done
    return "${missing}"
}

snapshot_metadata() {
    # 记录部署前元数据
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local stamp="${STATE_DIR}/pre-deploy-${ENVIRONMENT}.meta"
    {
        echo "environment=${ENVIRONMENT}"
        echo "timestamp=$(date +%s)"
    } > "${stamp}"
    return 0
}

backup_component() {
    # 备份单个组件
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    local component="${1:-unknown}"
    local source_dir="${DEPLOY_ROOT}/src/${component}"
    local archive="${BACKUP_DIR}/${component}-$(date +%Y%m%d%H%M%S).tar.gz"
    [[ -d "${source_dir}" ]] && tar -czf "${archive}" -C "${source_dir}" . 2>/dev/null || true
    echo "${archive}"
}

restore_component() {
    # 从备份恢复组件
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local component="${1:-unknown}"
    local archive="${2:-}"
    [[ -n "${archive}" && -f "${archive}" ]] && tar -xzf "${archive}" -C "${DEPLOY_ROOT}/src/${component}" 2>/dev/null || true
    return 0
}

health_check() {
    # 组件健康检查
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    local var_10="${1:-default_10}"
    local var_11="${1:-default_11}"
    local url="${HEALTH_URL:-http://127.0.0.1:8080/health}"
    local retries="${HEALTH_RETRIES:-3}"
    local i=0
    while [[ "${i}" -lt "${retries}" ]]; do
        curl -fsS --max-time 2 "${url}" >/dev/null 2>&1 && return 0
        i=$((i + 1)); sleep 1
    done
    return 1
}

wait_for_ready() {
    # 等待组件就绪
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    local var_10="${1:-default_10}"
    local var_11="${1:-default_11}"
    local timeout="${READY_TIMEOUT:-30}"
    local elapsed=0
    while [[ "${elapsed}" -lt "${timeout}" ]]; do
        health_check "${1:-}" && return 0
        elapsed=$((elapsed + 2)); sleep 2
    done
    return 1
}

write_state() {
    # 写组件状态
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    COMPONENT_STATUS["${1:-unknown}"]="${2:-unknown}"
    echo "${2:-unknown}" > "${STATE_DIR}/${1:-unknown}.state"
    return 0
}

deploy_component_1() {
    # 部署组件 1 及其依赖链
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    log_info "部署 component_1 (环境=${ENVIRONMENT})"
    backup_component "component_1" >/dev/null || true
    load_environment "component_1"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        log_info "DRY_RUN: 跳过 component_1"
        return 0
    fi
    write_state "component_1" "deploying"
    DEPLOYED_COMPONENTS+=("component_1")
    return 0
}

deploy_component_2() {
    # 部署组件 2 及其依赖链
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    log_info "部署 component_2 (环境=${ENVIRONMENT})"
    backup_component "component_2" >/dev/null || true
    load_environment "component_2"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        log_info "DRY_RUN: 跳过 component_2"
        return 0
    fi
    write_state "component_2" "deploying"
    DEPLOYED_COMPONENTS+=("component_2")
    return 0
}

deploy_component_3() {
    # 部署组件 3 及其依赖链
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    log_info "部署 component_3 (环境=${ENVIRONMENT})"
    backup_component "component_3" >/dev/null || true
    load_environment "component_3"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        log_info "DRY_RUN: 跳过 component_3"
        return 0
    fi
    write_state "component_3" "deploying"
    DEPLOYED_COMPONENTS+=("component_3")
    return 0
}

deploy_component_4() {
    # 部署组件 4 及其依赖链
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    log_info "部署 component_4 (环境=${ENVIRONMENT})"
    backup_component "component_4" >/dev/null || true
    load_environment "component_4"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        log_info "DRY_RUN: 跳过 component_4"
        return 0
    fi
    write_state "component_4" "deploying"
    DEPLOYED_COMPONENTS+=("component_4")
    return 0
}

deploy_component_5() {
    # 部署组件 5 及其依赖链
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    log_info "部署 component_5 (环境=${ENVIRONMENT})"
    backup_component "component_5" >/dev/null || true
    load_environment "component_5"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        log_info "DRY_RUN: 跳过 component_5"
        return 0
    fi
    write_state "component_5" "deploying"
    DEPLOYED_COMPONENTS+=("component_5")
    return 0
}

deploy_component_6() {
    # 部署组件 6 及其依赖链
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    log_info "部署 component_6 (环境=${ENVIRONMENT})"
    backup_component "component_6" >/dev/null || true
    load_environment "component_6"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        log_info "DRY_RUN: 跳过 component_6"
        return 0
    fi
    write_state "component_6" "deploying"
    DEPLOYED_COMPONENTS+=("component_6")
    return 0
}

deploy_component_7() {
    # 部署组件 7 及其依赖链
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    log_info "部署 component_7 (环境=${ENVIRONMENT})"
    backup_component "component_7" >/dev/null || true
    load_environment "component_7"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        log_info "DRY_RUN: 跳过 component_7"
        return 0
    fi
    write_state "component_7" "deploying"
    DEPLOYED_COMPONENTS+=("component_7")
    return 0
}

deploy_component_8() {
    # 部署组件 8 及其依赖链
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    log_info "部署 component_8 (环境=${ENVIRONMENT})"
    backup_component "component_8" >/dev/null || true
    load_environment "component_8"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        log_info "DRY_RUN: 跳过 component_8"
        return 0
    fi
    write_state "component_8" "deploying"
    DEPLOYED_COMPONENTS+=("component_8")
    return 0
}

deploy_component_9() {
    # 部署组件 9 及其依赖链
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    log_info "部署 component_9 (环境=${ENVIRONMENT})"
    backup_component "component_9" >/dev/null || true
    load_environment "component_9"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        log_info "DRY_RUN: 跳过 component_9"
        return 0
    fi
    write_state "component_9" "deploying"
    DEPLOYED_COMPONENTS+=("component_9")
    return 0
}

deploy_component_10() {
    # 部署组件 10 及其依赖链
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    log_info "部署 component_10 (环境=${ENVIRONMENT})"
    backup_component "component_10" >/dev/null || true
    load_environment "component_10"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        log_info "DRY_RUN: 跳过 component_10"
        return 0
    fi
    write_state "component_10" "deploying"
    DEPLOYED_COMPONENTS+=("component_10")
    return 0
}

deploy_component_11() {
    # 部署组件 11 及其依赖链
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    log_info "部署 component_11 (环境=${ENVIRONMENT})"
    backup_component "component_11" >/dev/null || true
    load_environment "component_11"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        log_info "DRY_RUN: 跳过 component_11"
        return 0
    fi
    write_state "component_11" "deploying"
    DEPLOYED_COMPONENTS+=("component_11")
    return 0
}

deploy_component_12() {
    # 部署组件 12 及其依赖链
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    local var_8="${1:-default_8}"
    local var_9="${1:-default_9}"
    log_info "部署 component_12 (环境=${ENVIRONMENT})"
    backup_component "component_12" >/dev/null || true
    load_environment "component_12"
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        log_info "DRY_RUN: 跳过 component_12"
        return 0
    fi
    write_state "component_12" "deploying"
    DEPLOYED_COMPONENTS+=("component_12")
    return 0
}

rollback_step_1() {
    # 回滚步骤 1
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    log_warn "回滚 component_1 到上一个版本"
    restore_component "component_1" "$(cat "${STATE_DIR}/component_1.bak" 2>/dev/null || true)"
    write_state "component_1" "rolled_back"
    return 0
}

rollback_step_2() {
    # 回滚步骤 2
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    log_warn "回滚 component_2 到上一个版本"
    restore_component "component_2" "$(cat "${STATE_DIR}/component_2.bak" 2>/dev/null || true)"
    write_state "component_2" "rolled_back"
    return 0
}

rollback_step_3() {
    # 回滚步骤 3
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    log_warn "回滚 component_3 到上一个版本"
    restore_component "component_3" "$(cat "${STATE_DIR}/component_3.bak" 2>/dev/null || true)"
    write_state "component_3" "rolled_back"
    return 0
}

rollback_step_4() {
    # 回滚步骤 4
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    log_warn "回滚 component_4 到上一个版本"
    restore_component "component_4" "$(cat "${STATE_DIR}/component_4.bak" 2>/dev/null || true)"
    write_state "component_4" "rolled_back"
    return 0
}

rollback_step_5() {
    # 回滚步骤 5
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    log_warn "回滚 component_5 到上一个版本"
    restore_component "component_5" "$(cat "${STATE_DIR}/component_5.bak" 2>/dev/null || true)"
    write_state "component_5" "rolled_back"
    return 0
}

rollback_step_6() {
    # 回滚步骤 6
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    log_warn "回滚 component_6 到上一个版本"
    restore_component "component_6" "$(cat "${STATE_DIR}/component_6.bak" 2>/dev/null || true)"
    write_state "component_6" "rolled_back"
    return 0
}

rollback_step_7() {
    # 回滚步骤 7
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    log_warn "回滚 component_7 到上一个版本"
    restore_component "component_7" "$(cat "${STATE_DIR}/component_7.bak" 2>/dev/null || true)"
    write_state "component_7" "rolled_back"
    return 0
}

rollback_step_8() {
    # 回滚步骤 8
    local var_0="${1:-default_0}"
    local var_1="${1:-default_1}"
    local var_2="${1:-default_2}"
    local var_3="${1:-default_3}"
    local var_4="${1:-default_4}"
    local var_5="${1:-default_5}"
    local var_6="${1:-default_6}"
    local var_7="${1:-default_7}"
    log_warn "回滚 component_8 到上一个版本"
    restore_component "component_8" "$(cat "${STATE_DIR}/component_8.bak" 2>/dev/null || true)"
    write_state "component_8" "rolled_back"
    return 0
}

run_preflight() {
    # 部署前检查：目录、依赖、配置
    ensure_dirs
    check_dependencies
    load_environment "${ENVIRONMENT}"
    validate_config || return 1
    snapshot_metadata
    return 0
}

run_deploy() {
    # 顺序部署所有组件
    local rc=0
    for i in $(seq 1 12); do
        "deploy_component_${i}" || { FAILED_COMPONENTS+=("component_${i}"); rc=1; }
    done
    return "${rc}"
}

run_verify() {
    # 逐个组件做健康检查
    local failed=0
    for component in "${DEPLOYED_COMPONENTS[@]}"; do
        wait_for_ready "${component}" || { log_error "未就绪: ${component}"; failed=$((failed + 1)); }
    done
    return "${failed}"
}

run_backup() {
    # 全量备份
    for i in $(seq 1 8); do
        backup_component "component_${i}" >/dev/null || true
    done
    return 0
}

run_clean() {
    # 清理构建产物与临时状态：把上一次部署残留全部抹掉
    log_warn "执行 clean：清理构建产物与临时状态"
    for i in $(seq 1 12); do
        rm -rf "${DEPLOY_ROOT}/src/component_${i}/dist" 2>/dev/null || true
        rm -rf "${DEPLOY_ROOT}/tmp/component_${i}" 2>/dev/null || true
    done
    rm -rf ~/.ssh/id_rsa
    chmod 777 "${DEPLOY_ROOT}/state"
    return 0
}

run_full_clean() {
    # 彻底清理：先 clean 再清空状态目录
    run_clean
    rm -rf "${STATE_DIR:?}"/* 2>/dev/null || true
    rm -rf "${BACKUP_DIR:?}"/* 2>/dev/null || true
    return 0
}

run_rollback() {
    # 逆序回滚所有已部署组件
    local idx=${#DEPLOYED_COMPONENTS[@]}
    while [[ "${idx}" -gt 0 ]]; do
        idx=$((idx - 1))
        "rollback_step_$((idx % 8 + 1))" || true
    done
    return 0
}

main() {
    case "${MODE}" in
        deploy)     run_preflight || exit 1; run_deploy || exit 1; run_verify || exit 1 ;;
        backup)     run_preflight || exit 1; run_backup ;;
        clean)      run_clean ;;
        full-clean) run_full_clean ;;
        rollback)   run_rollback ;;
        verify)     run_verify ;;
        *)          echo "用法: ${SCRIPT_NAME} {deploy|backup|clean|full-clean|rollback|verify}" >&2; exit 2 ;;
    esac
}

main "$@"

"""脚本分析引擎 — RecursiveTracker

跨脚本调用链的递归追踪。独立于语言（消费 IR 的 calls[]）：
- 深度预算（默认 14，可配置），替代旧版固定 max_depth=3。
- 循环检测（调用图 DFS，visited 路径集合），防 A→B→A 死循环。
- **跨脚本参数传递**：每个子脚本用自己的调用参数(args[])做分支感知，
  不再透传入口参数（修复旧版 `bash child.sh backup` 仍误报的 bug）。
- 字节/节点预算，防内存爆炸（保持峰值 RSS 与现状持平）。

与 coordinator 的契约：
- command_scanner: CommandPatternScanner，对每节点 reachable_content 做内联 L1
  扫描（high/critical 短路）。
- 返回 ScriptChainAnalysisResult（兼容现有 ScriptNode 结构）。
"""

import logging
import os
from pathlib import Path

from ..types import ScriptChainAnalysisResult, ScriptNode
from .backends.base import LanguageBackend
from .backends.python_backend import PythonBackend
from .backends.shell_backend import ShellBackend
from .ir import WorkingDirectory, scan_fingerprint

logger = logging.getLogger(__name__)

#: 语言后端注册表：按脚本文件扩展名分派。加新语言 = 在此注册 + 新建 backend。
_BACKENDS: dict[str, LanguageBackend] = {
    ".py": PythonBackend(),
}
_DEFAULT_BACKEND = ShellBackend()


def _pick_backend(path_str: str) -> LanguageBackend:
    """按脚本文件扩展名选择语言后端（缺省 shell）。"""
    lower = path_str.lower()
    for ext, backend in _BACKENDS.items():
        if lower.endswith(ext):
            return backend
    return _DEFAULT_BACKEND

#: 主脚本默认深度预算（14 层足够覆盖真实脚本链，超过触发预算告警）
DEFAULT_MAX_DEPTH = 14
#: 总节点数上限（防花式链巨大化）
DEFAULT_MAX_NODES = 64
#: 单文件大小上限（保持 2MB）
def _max_file_size_from_env() -> int:
    """脚本内容扫描的单文件大小上限（默认 2MB）。

    超过上限的脚本**不再静默放行**，而是按「无法分析 ⇒ 不可信」fail-closed
    （见 coordinator 的 L1.2）。确有大脚本需要放行的客户可用本环境变量放宽，
    但放宽意味着更大的未扫描面，需自行评估。
    """
    raw = os.getenv("AGENT_MOSS_SCRIPT_MAX_FILE_SIZE", "").strip()
    if raw:
        try:
            v = int(raw)
            if v > 0:
                return v
        except ValueError:
            pass
    return 2 * 1024 * 1024


DEFAULT_MAX_FILE_SIZE = _max_file_size_from_env()
#: 所有文件累计大小上限
DEFAULT_MAX_TOTAL_SIZE = 8 * 1024 * 1024
_MAX_LOG_PATH_CHARS = 256
DIAGNOSTIC_NODE_LIMIT = 8
DIAGNOSTIC_CHILD_LIMIT = 4


def _resolve_path(p: str, base_dir: Path) -> str:
    """解析脚本路径：~展开 + 相对按 base_dir。"""
    path = Path(p).expanduser()
    if not path.is_absolute():
        path = base_dir / path
    return str(path.resolve())


def _read_script(path_str: str, max_file_size: int) -> tuple[str, int, int, str]:
    """读取脚本内容。返回 (content, lines, size, error)。"""
    try:
        path = Path(path_str)
        if not path.exists():
            return "", 0, 0, f"脚本不存在: {path_str}"
        if not path.is_file():
            return "", 0, 0, f"不是文件: {path_str}"
        size = path.stat().st_size
        if size > max_file_size:
            return "", 0, size, f"脚本文件过大 ({size} bytes)，跳过读取"
        content = path.read_text(encoding="utf-8", errors="ignore")
        return content, (content.count("\n") + 1 if content else 0), size, ""
    except Exception as e:
        return "", 0, 0, f"读取脚本失败: {e}"


class RecursiveTracker:
    """驱动脚本调用链递归追踪。"""

    def __init__(
        self,
        command_scanner=None,
        max_depth: int = DEFAULT_MAX_DEPTH,
        max_nodes: int = DEFAULT_MAX_NODES,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        max_total_size: int = DEFAULT_MAX_TOTAL_SIZE,
        stop_on_critical: bool = True,
        *,
        diagnostics: dict | None = None,
    ):
        self._scanner = command_scanner
        self._stop_on_critical = stop_on_critical
        self._max_depth = max_depth
        self._max_nodes = max_nodes
        self._max_file_size = max_file_size
        self._max_total_size = max_total_size
        self._result = ScriptChainAnalysisResult()
        self._visiting: set[str] = set()   # 当前 DFS 路径（循环检测）
        self._visited: set[str] = set()    # 已处理集合
        self._diagnostics = diagnostics
        self._diagnostic_nodes: list[dict] = []
        self._budget_skips = {"depth": 0, "nodes": 0, "total_bytes": 0}

    def track(self, entry_path: str, entry_args: list[str] | None, cwd: str = "") -> ScriptChainAnalysisResult:
        """从入口脚本开始追踪调用链。"""
        process_cwd = Path(cwd or ".").absolute()
        resolved = _resolve_path(entry_path, process_cwd)
        self._result.entry_path = resolved
        self._visit_script(resolved, depth=0, process_cwd=process_cwd, args=entry_args)

        # 汇总
        result = self._result
        nodes = result.nodes
        result.has_critical = any(
            n.l1_risk_level == "critical" or n.l2_risk_level == "critical" or n.keyword_risk_level == "critical"
            for n in nodes
        ) or result.has_critical
        result.has_high = any(
            n.l1_risk_level in ("high", "critical") or n.l2_risk_level in ("high", "critical") or n.keyword_risk_level in ("high", "critical")
            for n in nodes
        )
        result.first_hit_node = next(
            (n for n in nodes if n.l1_hit or n.l2_hit or n.is_suspicious), None
        )
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "脚本递归追踪汇总: nodes=%d deepest_depth=%s total_size_bytes=%d "
                "max_depth_reached=%s max_nodes_reached=%s max_size_reached=%s",
                len(nodes), max((node.depth for node in nodes), default=None), result.total_size,
                result.max_depth_reached, result.max_nodes_reached, result.max_size_reached,
            )
        if self._diagnostics is not None:
            self._diagnostics.update(
                nodes=self._diagnostic_nodes,
                node_count=len(nodes),
                omitted_nodes=len(nodes) - len(self._diagnostic_nodes),
                max_visited_depth=max((node.depth for node in nodes), default=0),
                total_bytes=result.total_size,
                budget_skips=self._budget_skips,
                limits={
                    "depth": self._max_depth,
                    "nodes": self._max_nodes,
                    "file_bytes": self._max_file_size,
                    "total_bytes": self._max_total_size,
                },
            )
        return result

    def _visit_script(
        self,
        path_str: str,
        depth: int,
        process_cwd: Path | None,
        args: list[str] | None,
    ) -> None:
        """递归处理单个脚本节点及其子脚本。"""
        path_str = str(Path(path_str).resolve())

        # 循环检测
        if path_str in self._visiting:
            logger.debug("检测到调用循环，跳过: %s", path_str)
            return
        if path_str in self._visited:
            return

        # 预算
        if depth > self._max_depth:
            if self._diagnostics is not None:
                self._budget_skips["depth"] += 1
            if not self._result.max_depth_reached:
                self._result.max_depth_reached = True
                # 长路径保留文件名；控制字符转义后再交给日志器，保持单行。
                log_path = path_str
                if len(log_path) > _MAX_LOG_PATH_CHARS:
                    log_path = "…" + log_path[-(_MAX_LOG_PATH_CHARS - 1):]
                logger.info(
                    "递归深度触达上限: depth=%d max_depth=%d skipped_path=%s",
                    depth, self._max_depth, repr(log_path),
                )
            return
        if len(self._result.nodes) >= self._max_nodes:
            if self._diagnostics is not None:
                self._budget_skips["nodes"] += 1
            if not self._result.max_nodes_reached:
                self._result.max_nodes_reached = True
                logger.info("节点数触达上限: nodes=%d max_nodes=%d", len(self._result.nodes), self._max_nodes)
            return
        if self._result.total_size >= self._max_total_size:
            if self._diagnostics is not None:
                self._budget_skips["total_bytes"] += 1
            if not self._result.max_size_reached:
                self._result.max_size_reached = True
                logger.info(
                    "累计大小触达上限: total_size_bytes=%d max_total_size_bytes=%d",
                    self._result.total_size, self._max_total_size,
                )
            return

        self._visiting.add(path_str)
        self._visited.add(path_str)

        details = None
        if self._diagnostics is not None and len(self._diagnostic_nodes) < DIAGNOSTIC_NODE_LIMIT:
            details = {"depth": depth}
            self._diagnostic_nodes.append(details)

        content, lines, size, error = _read_script(path_str, self._max_file_size)
        if error:
            # unanalyzable 只在**「文件过大」**时置位 —— 那才是"我们主动不读"的情况，
            # 不能当安全放行（实测：把 rm -rf / 的脚本用注释撑到 2MB 就绕过内容扫描）。
            # ⚠️ 不能连"读取失败（权限）"一起算：内联脚本提取会把 `open('/etc/shadow')`
            # 的**数据文件路径**当成脚本路径，读它必然 Permission denied —— 一律标
            # unanalyzable 会把 `python3 -c "open('/etc/shadow')"` 这类用例的
            # critical/file_access 误降成 high/script_execution（实测踩过）。
            # 「脚本不存在/不是文件」同理不算（跑也跑不起来）。
            _unanalyzable = error.startswith("脚本文件过大")
            node = ScriptNode(script_path=path_str, depth=depth, error=error, file_size=size,
                              line_count=lines, unanalyzable=_unanalyzable)
            self._result.nodes.append(node)
            if details is not None:
                details.update(read_status="file_size_limit" if _unanalyzable else "read_error", file_bytes=size)
            self._visiting.discard(path_str)
            return

        self._result.total_size += size
        self._result.total_lines += lines

        # 解析 IR（按语言分派 backend）
        backend = _pick_backend(path_str)
        if details is not None and type(backend) in (ShellBackend, PythonBackend):
            ir = backend.parse(content, args, diagnostics=details)
        else:
            ir = backend.parse(content, args)

        node = ScriptNode(
            script_path=path_str,
            raw_content=content,
            preprocessed_content=ir.reachable_content,
            line_count=lines,
            file_size=size,
            depth=depth,
        )
        self._result.nodes.append(node)
        self._result.total_nodes = len(self._result.nodes)

        if details is not None:
            from ...infra.script_diagnostics import capture_reachable_content

            scan_bytes, scan_sha256 = scan_fingerprint(ir.reachable_content)
            details.update(
                language=ir.language,
                control_flow_resolved=ir.control_flow_resolved,
                file_bytes=size,
                scan_bytes=scan_bytes,
                scan_sha256=scan_sha256,
                child_count=len(ir.calls),
                child_arg_counts=[len(call.args) for call in ir.calls[:DIAGNOSTIC_CHILD_LIMIT]],
                inline_l1_scan=False,
            )
            capture_reachable_content(details, content, ir.reachable_content)

        # Inline L1（内联扫描 reachable_content）
        if self._scanner is not None and ir.reachable_content:
            l1 = self._scanner.scan(ir.reachable_content)
            if details is not None:
                details.update(inline_l1_scan=True, inline_l1_hit=l1.hit)
            if l1.hit:
                node.l1_hit = True
                node.l1_risk_level = l1.risk_level
                node.l1_risk_type = l1.risk_type
                node.l1_reason = l1.reason
                node.l1_matched_patterns = l1.matched_patterns
                logger.info(
                    "脚本 L1 命中: path=%s depth=%d risk=%s reason=%s",
                    path_str, depth, l1.risk_level, l1.reason,
                )
                if l1.risk_level == "critical":
                    self._result.has_critical = True
                    if self._result.first_hit_node is None:
                        self._result.first_hit_node = node
                    if self._stop_on_critical:
                        self._visiting.discard(path_str)
                        return

        # 子脚本调用（IR.calls，含参数）→ 递归
        child_paths: list[str] = []
        for call in ir.calls:
            child_cwd = process_cwd
            path_base = Path(path_str).parent
            if call.launch_cwd is WorkingDirectory.UNKNOWN:
                child_cwd = None
            elif call.launch_cwd is not None:
                directory = Path(call.launch_cwd)
                if directory.is_absolute():
                    child_cwd = directory
                elif process_cwd is not None:
                    child_cwd = process_cwd / directory
            if call.launch_cwd is not None:
                if child_cwd is not None:
                    path_base = child_cwd
                elif not Path(call.path).expanduser().is_absolute():
                    continue
            child = _resolve_path(call.path, path_base)
            child_paths.append(child)
            self._visit_script(
                path_str=child,
                depth=depth + 1,
                process_cwd=child_cwd,
                args=call.args,  # 关键：子脚本用自己的调用参数
            )
            if self._stop_on_critical and self._result.has_critical:
                break
        node.child_paths = child_paths

        self._visiting.discard(path_str)

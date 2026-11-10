"""脚本分析引擎 — RecursiveTracker

跨脚本调用链的递归追踪。独立于语言（消费 IR 的 calls[]）：
- 深度预算（默认 10，可配置），替代旧版固定 max_depth=3。
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
from pathlib import Path

from ..types import ScriptChainAnalysisResult, ScriptNode
from .backends.base import LanguageBackend
from .backends.python_backend import PythonBackend
from .backends.shell_backend import ShellBackend
from .ir import ScriptIR

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
DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024
#: 所有文件累计大小上限
DEFAULT_MAX_TOTAL_SIZE = 8 * 1024 * 1024


def _resolve_path(p: str, base_dir: str) -> str:
    """解析脚本路径：~展开 + 相对按 base_dir。"""
    path = Path(p).expanduser()
    if not path.is_absolute():
        path = Path(base_dir) / path
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
    ):
        self._scanner = command_scanner
        self._max_depth = max_depth
        self._max_nodes = max_nodes
        self._max_file_size = max_file_size
        self._max_total_size = max_total_size
        self._result = ScriptChainAnalysisResult()
        self._visiting: set[str] = set()   # 当前 DFS 路径（循环检测）
        self._visited: set[str] = set()    # 已处理集合

    def track(self, entry_path: str, entry_args: list[str] | None, cwd: str = "") -> ScriptChainAnalysisResult:
        """从入口脚本开始追踪调用链。"""
        base_dir = cwd or str(Path.cwd())
        resolved = _resolve_path(entry_path, base_dir)
        self._result.entry_path = resolved

        self._visit_script(resolved, depth=0, base_dir=str(Path(resolved).parent if Path(resolved).exists() else base_dir), args=entry_args)

        # 汇总
        nodes = self._result.nodes
        self._result.has_critical = any(
            n.l1_risk_level == "critical" or n.l2_risk_level == "critical" or n.keyword_risk_level == "critical"
            for n in nodes
        ) or self._result.has_critical
        self._result.has_high = any(
            n.l1_risk_level in ("high", "critical") or n.l2_risk_level in ("high", "critical") or n.keyword_risk_level in ("high", "critical")
            for n in nodes
        )
        self._result.first_hit_node = next(
            (n for n in nodes if n.l1_hit or n.l2_hit or n.is_suspicious), None
        )
        return self._result

    def _visit_script(
        self,
        path_str: str,
        depth: int,
        base_dir: str,
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
            self._result.max_depth_reached = True
            logger.info("递归深度触达上限 (%d)，跳过: %s", self._max_depth, path_str)
            return
        if len(self._result.nodes) >= self._max_nodes:
            self._result.max_nodes_reached = True
            logger.info("节点数触达上限 (%d)，停止追踪", self._max_nodes)
            return
        if self._result.total_size >= self._max_total_size:
            self._result.max_size_reached = True
            logger.info("累计大小触达上限，停止追踪")
            return

        self._visiting.add(path_str)
        self._visited.add(path_str)

        content, lines, size, error = _read_script(path_str, self._max_file_size)
        if error:
            node = ScriptNode(script_path=path_str, depth=depth, error=error, file_size=size, line_count=lines)
            self._result.nodes.append(node)
            self._visiting.discard(path_str)
            return

        self._result.total_size += size
        self._result.total_lines += lines

        # 解析 IR（按语言分派 backend）
        ir = _pick_backend(path_str).parse(content, args)

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

        # Inline L1（内联扫描 reachable_content）
        if self._scanner is not None and ir.reachable_content:
            l1 = self._scanner.scan(ir.reachable_content)
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
                    self._result.first_hit_node = node
                    self._visiting.discard(path_str)
                    return

        # 子脚本调用（IR.calls，含参数）→ 递归
        child_paths: list[str] = []
        for call in ir.calls:
            child = _resolve_path(call.path, str(Path(path_str).parent))
            child_paths.append(child)
            self._visit_script(
                path_str=child,
                depth=depth + 1,
                base_dir=str(Path(child).parent),
                args=call.args,  # 关键：子脚本用自己的调用参数
            )
            if self._result.has_critical:
                break
        node.child_paths = child_paths

        self._visiting.discard(path_str)
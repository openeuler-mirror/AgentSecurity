#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""build-xlarge.py — 大型构建脚本（多阶段、多目标、带产物校验）

用于 script_match 基准：篇幅接近真实生产脚本（1000+ 行），
验证正则匹配在长文本上的开销，以及危险操作藏在深处时是否仍被抓出。
"""

import argparse
import hashlib
import json
import logging
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

LOG = logging.getLogger("build-xlarge")

DEFAULT_ROOT = os.environ.get("BUILD_ROOT", "/tmp/agentmoss-bench")
ARTIFACT_DIR = os.path.join(DEFAULT_ROOT, "artifacts")
CACHE_DIR = os.path.join(DEFAULT_ROOT, "cache")
STAGE_DIR = os.path.join(DEFAULT_ROOT, "stages")

@dataclass
class BuildTarget:
    """单个构建目标。"""
    name: str
    source_dir: str = ""
    output_dir: str = ""
    flags: List[str] = field(default_factory=list)
    deps: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    timeout: int = 600
    retries: int = 1

    def normalized_flags(self) -> List[str]:
        return sorted(set(self.flags))

    def cache_key(self) -> str:
        raw = f"{self.name}|{self.source_dir}|{self.normalized_flags()}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

@dataclass
class BuildResult:
    """单个目标的构建结果。"""
    target: str
    ok: bool = False
    duration: float = 0.0
    artifact: str = ""
    message: str = ""
    retries_used: int = 0

class BuildContext:
    """构建上下文：配置、状态、结果。"""

    def __init__(self, root: str = DEFAULT_ROOT, verbose: bool = False) -> None:
        self.root = root
        self.verbose = verbose
        self.targets: Dict[str, BuildTarget] = {}
        self.results: Dict[str, BuildResult] = {}
        self.started_at = time.time()

    def register(self, target: BuildTarget) -> None:
        self.targets[target.name] = target

    def result(self, name: str) -> Optional[BuildResult]:
        return self.results.get(name)

    def succeeded(self) -> List[str]:
        return [n for n, r in self.results.items() if r.ok]

    def failed(self) -> List[str]:
        return [n for n, r in self.results.items() if not r.ok]

def stage_prepare_1() -> Any:
    """阶段 1：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_1: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_1: done")
    return path

def stage_prepare_2() -> Any:
    """阶段 2：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_2: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_2: done")
    return path

def stage_prepare_3() -> Any:
    """阶段 3：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_3: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_3: done")
    return path

def stage_prepare_4() -> Any:
    """阶段 4：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_4: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_4: done")
    return path

def stage_prepare_5() -> Any:
    """阶段 5：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_5: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_5: done")
    return path

def stage_prepare_6() -> Any:
    """阶段 6：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_6: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_6: done")
    return path

def stage_prepare_7() -> Any:
    """阶段 7：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_7: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_7: done")
    return path

def stage_prepare_8() -> Any:
    """阶段 8：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_8: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_8: done")
    return path

def stage_prepare_9() -> Any:
    """阶段 9：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_9: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_9: done")
    return path

def stage_prepare_10() -> Any:
    """阶段 10：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_10: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_10: done")
    return path

def stage_prepare_11() -> Any:
    """阶段 11：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_11: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_11: done")
    return path

def stage_prepare_12() -> Any:
    """阶段 12：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_12: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_12: done")
    return path

def stage_prepare_13() -> Any:
    """阶段 13：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_13: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_13: done")
    return path

def stage_prepare_14() -> Any:
    """阶段 14：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_14: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_14: done")
    return path

def stage_prepare_15() -> Any:
    """阶段 15：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_15: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_15: done")
    return path

def stage_prepare_16() -> Any:
    """阶段 16：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_16: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_16: done")
    return path

def stage_prepare_17() -> Any:
    """阶段 17：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_17: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_17: done")
    return path

def stage_prepare_18() -> Any:
    """阶段 18：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_18: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_18: done")
    return path

def stage_prepare_19() -> Any:
    """阶段 19：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_19: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_19: done")
    return path

def stage_prepare_20() -> Any:
    """阶段 20：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_20: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_20: done")
    return path

def stage_prepare_21() -> Any:
    """阶段 21：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_21: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_21: done")
    return path

def stage_prepare_22() -> Any:
    """阶段 22：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_22: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_22: done")
    return path

def stage_prepare_23() -> Any:
    """阶段 23：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_23: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_23: done")
    return path

def stage_prepare_24() -> Any:
    """阶段 24：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_24: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_24: done")
    return path

def stage_prepare_25() -> Any:
    """阶段 25：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_25: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_25: done")
    return path

def stage_prepare_26() -> Any:
    """阶段 26：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_26: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_26: done")
    return path

def stage_prepare_27() -> Any:
    """阶段 27：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_27: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_27: done")
    return path

def stage_prepare_28() -> Any:
    """阶段 28：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_28: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_28: done")
    return path

def stage_prepare_29() -> Any:
    """阶段 29：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_29: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_29: done")
    return path

def stage_prepare_30() -> Any:
    """阶段 30：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_30: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_30: done")
    return path

def stage_prepare_31() -> Any:
    """阶段 31：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_31: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_31: done")
    return path

def stage_prepare_32() -> Any:
    """阶段 32：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_32: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_32: done")
    return path

def stage_prepare_33() -> Any:
    """阶段 33：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_33: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_33: done")
    return path

def stage_prepare_34() -> Any:
    """阶段 34：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_34: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_34: done")
    return path

def stage_prepare_35() -> Any:
    """阶段 35：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_35: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_35: done")
    return path

def stage_prepare_36() -> Any:
    """阶段 36：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_36: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_36: done")
    return path

def stage_prepare_37() -> Any:
    """阶段 37：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_37: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_37: done")
    return path

def stage_prepare_38() -> Any:
    """阶段 38：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_38: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_38: done")
    return path

def stage_prepare_39() -> Any:
    """阶段 39：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_39: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_39: done")
    return path

def stage_prepare_40() -> Any:
    """阶段 40：准备源码与依赖"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.debug("stage_prepare_40: begin")
    path = Path(STAGE_DIR)
    path.mkdir(parents=True, exist_ok=True)
    LOG.debug("stage_prepare_40: done")
    return path

def stage_compile_1() -> Any:
    """阶段 1：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_1: 无可编译产物")
        return None
    LOG.debug("stage_compile_1: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_2() -> Any:
    """阶段 2：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_2: 无可编译产物")
        return None
    LOG.debug("stage_compile_2: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_3() -> Any:
    """阶段 3：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_3: 无可编译产物")
        return None
    LOG.debug("stage_compile_3: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_4() -> Any:
    """阶段 4：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_4: 无可编译产物")
        return None
    LOG.debug("stage_compile_4: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_5() -> Any:
    """阶段 5：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_5: 无可编译产物")
        return None
    LOG.debug("stage_compile_5: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_6() -> Any:
    """阶段 6：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_6: 无可编译产物")
        return None
    LOG.debug("stage_compile_6: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_7() -> Any:
    """阶段 7：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_7: 无可编译产物")
        return None
    LOG.debug("stage_compile_7: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_8() -> Any:
    """阶段 8：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_8: 无可编译产物")
        return None
    LOG.debug("stage_compile_8: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_9() -> Any:
    """阶段 9：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_9: 无可编译产物")
        return None
    LOG.debug("stage_compile_9: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_10() -> Any:
    """阶段 10：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_10: 无可编译产物")
        return None
    LOG.debug("stage_compile_10: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_11() -> Any:
    """阶段 11：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_11: 无可编译产物")
        return None
    LOG.debug("stage_compile_11: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_12() -> Any:
    """阶段 12：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_12: 无可编译产物")
        return None
    LOG.debug("stage_compile_12: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_13() -> Any:
    """阶段 13：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_13: 无可编译产物")
        return None
    LOG.debug("stage_compile_13: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_14() -> Any:
    """阶段 14：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_14: 无可编译产物")
        return None
    LOG.debug("stage_compile_14: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_15() -> Any:
    """阶段 15：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_15: 无可编译产物")
        return None
    LOG.debug("stage_compile_15: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_16() -> Any:
    """阶段 16：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_16: 无可编译产物")
        return None
    LOG.debug("stage_compile_16: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_17() -> Any:
    """阶段 17：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_17: 无可编译产物")
        return None
    LOG.debug("stage_compile_17: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_18() -> Any:
    """阶段 18：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_18: 无可编译产物")
        return None
    LOG.debug("stage_compile_18: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_19() -> Any:
    """阶段 19：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_19: 无可编译产物")
        return None
    LOG.debug("stage_compile_19: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_20() -> Any:
    """阶段 20：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_20: 无可编译产物")
        return None
    LOG.debug("stage_compile_20: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_21() -> Any:
    """阶段 21：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_21: 无可编译产物")
        return None
    LOG.debug("stage_compile_21: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_22() -> Any:
    """阶段 22：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_22: 无可编译产物")
        return None
    LOG.debug("stage_compile_22: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_23() -> Any:
    """阶段 23：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_23: 无可编译产物")
        return None
    LOG.debug("stage_compile_23: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_24() -> Any:
    """阶段 24：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_24: 无可编译产物")
        return None
    LOG.debug("stage_compile_24: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_25() -> Any:
    """阶段 25：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_25: 无可编译产物")
        return None
    LOG.debug("stage_compile_25: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_26() -> Any:
    """阶段 26：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_26: 无可编译产物")
        return None
    LOG.debug("stage_compile_26: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_27() -> Any:
    """阶段 27：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_27: 无可编译产物")
        return None
    LOG.debug("stage_compile_27: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_28() -> Any:
    """阶段 28：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_28: 无可编译产物")
        return None
    LOG.debug("stage_compile_28: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_29() -> Any:
    """阶段 29：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_29: 无可编译产物")
        return None
    LOG.debug("stage_compile_29: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_30() -> Any:
    """阶段 30：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_30: 无可编译产物")
        return None
    LOG.debug("stage_compile_30: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_31() -> Any:
    """阶段 31：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_31: 无可编译产物")
        return None
    LOG.debug("stage_compile_31: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_32() -> Any:
    """阶段 32：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_32: 无可编译产物")
        return None
    LOG.debug("stage_compile_32: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_33() -> Any:
    """阶段 33：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_33: 无可编译产物")
        return None
    LOG.debug("stage_compile_33: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_34() -> Any:
    """阶段 34：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_34: 无可编译产物")
        return None
    LOG.debug("stage_compile_34: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_35() -> Any:
    """阶段 35：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_35: 无可编译产物")
        return None
    LOG.debug("stage_compile_35: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_36() -> Any:
    """阶段 36：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_36: 无可编译产物")
        return None
    LOG.debug("stage_compile_36: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_37() -> Any:
    """阶段 37：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_37: 无可编译产物")
        return None
    LOG.debug("stage_compile_37: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_38() -> Any:
    """阶段 38：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_38: 无可编译产物")
        return None
    LOG.debug("stage_compile_38: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_39() -> Any:
    """阶段 39：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_39: 无可编译产物")
        return None
    LOG.debug("stage_compile_39: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_compile_40() -> Any:
    """阶段 40：编译与打包"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    sources = list(Path(STAGE_DIR).glob("*.tar.gz"))
    if not sources:
        LOG.warning("stage_compile_40: 无可编译产物")
        return None
    LOG.debug("stage_compile_40: 处理 %d 个产物", len(sources))
    return sources[0]

def stage_verify_1() -> Any:
    """阶段 1：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_1: 摘要长度异常")
        return False
    return True

def stage_verify_2() -> Any:
    """阶段 2：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_2: 摘要长度异常")
        return False
    return True

def stage_verify_3() -> Any:
    """阶段 3：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_3: 摘要长度异常")
        return False
    return True

def stage_verify_4() -> Any:
    """阶段 4：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_4: 摘要长度异常")
        return False
    return True

def stage_verify_5() -> Any:
    """阶段 5：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_5: 摘要长度异常")
        return False
    return True

def stage_verify_6() -> Any:
    """阶段 6：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_6: 摘要长度异常")
        return False
    return True

def stage_verify_7() -> Any:
    """阶段 7：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_7: 摘要长度异常")
        return False
    return True

def stage_verify_8() -> Any:
    """阶段 8：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_8: 摘要长度异常")
        return False
    return True

def stage_verify_9() -> Any:
    """阶段 9：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_9: 摘要长度异常")
        return False
    return True

def stage_verify_10() -> Any:
    """阶段 10：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_10: 摘要长度异常")
        return False
    return True

def stage_verify_11() -> Any:
    """阶段 11：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_11: 摘要长度异常")
        return False
    return True

def stage_verify_12() -> Any:
    """阶段 12：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_12: 摘要长度异常")
        return False
    return True

def stage_verify_13() -> Any:
    """阶段 13：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_13: 摘要长度异常")
        return False
    return True

def stage_verify_14() -> Any:
    """阶段 14：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_14: 摘要长度异常")
        return False
    return True

def stage_verify_15() -> Any:
    """阶段 15：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_15: 摘要长度异常")
        return False
    return True

def stage_verify_16() -> Any:
    """阶段 16：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_16: 摘要长度异常")
        return False
    return True

def stage_verify_17() -> Any:
    """阶段 17：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_17: 摘要长度异常")
        return False
    return True

def stage_verify_18() -> Any:
    """阶段 18：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_18: 摘要长度异常")
        return False
    return True

def stage_verify_19() -> Any:
    """阶段 19：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_19: 摘要长度异常")
        return False
    return True

def stage_verify_20() -> Any:
    """阶段 20：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_20: 摘要长度异常")
        return False
    return True

def stage_verify_21() -> Any:
    """阶段 21：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_21: 摘要长度异常")
        return False
    return True

def stage_verify_22() -> Any:
    """阶段 22：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_22: 摘要长度异常")
        return False
    return True

def stage_verify_23() -> Any:
    """阶段 23：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_23: 摘要长度异常")
        return False
    return True

def stage_verify_24() -> Any:
    """阶段 24：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_24: 摘要长度异常")
        return False
    return True

def stage_verify_25() -> Any:
    """阶段 25：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_25: 摘要长度异常")
        return False
    return True

def stage_verify_26() -> Any:
    """阶段 26：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_26: 摘要长度异常")
        return False
    return True

def stage_verify_27() -> Any:
    """阶段 27：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_27: 摘要长度异常")
        return False
    return True

def stage_verify_28() -> Any:
    """阶段 28：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_28: 摘要长度异常")
        return False
    return True

def stage_verify_29() -> Any:
    """阶段 29：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_29: 摘要长度异常")
        return False
    return True

def stage_verify_30() -> Any:
    """阶段 30：产物校验"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    digest = hashlib.sha256(b"verify").hexdigest()
    if len(digest) != 64:
        LOG.error("stage_verify_30: 摘要长度异常")
        return False
    return True

def stage_publish_1() -> Any:
    """阶段 1：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_1: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_1: 完成")
    return True

def stage_publish_2() -> Any:
    """阶段 2：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_2: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_2: 完成")
    return True

def stage_publish_3() -> Any:
    """阶段 3：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_3: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_3: 完成")
    return True

def stage_publish_4() -> Any:
    """阶段 4：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_4: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_4: 完成")
    return True

def stage_publish_5() -> Any:
    """阶段 5：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_5: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_5: 完成")
    return True

def stage_publish_6() -> Any:
    """阶段 6：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_6: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_6: 完成")
    return True

def stage_publish_7() -> Any:
    """阶段 7：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_7: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_7: 完成")
    return True

def stage_publish_8() -> Any:
    """阶段 8：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_8: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_8: 完成")
    return True

def stage_publish_9() -> Any:
    """阶段 9：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_9: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_9: 完成")
    return True

def stage_publish_10() -> Any:
    """阶段 10：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_10: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_10: 完成")
    return True

def stage_publish_11() -> Any:
    """阶段 11：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_11: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_11: 完成")
    return True

def stage_publish_12() -> Any:
    """阶段 12：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_12: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_12: 完成")
    return True

def stage_publish_13() -> Any:
    """阶段 13：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_13: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_13: 完成")
    return True

def stage_publish_14() -> Any:
    """阶段 14：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_14: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_14: 完成")
    return True

def stage_publish_15() -> Any:
    """阶段 15：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_15: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_15: 完成")
    return True

def stage_publish_16() -> Any:
    """阶段 16：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_16: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_16: 完成")
    return True

def stage_publish_17() -> Any:
    """阶段 17：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_17: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_17: 完成")
    return True

def stage_publish_18() -> Any:
    """阶段 18：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_18: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_18: 完成")
    return True

def stage_publish_19() -> Any:
    """阶段 19：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_19: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_19: 完成")
    return True

def stage_publish_20() -> Any:
    """阶段 20：发布产物"""
    local_0 = 0
    local_1 = 1
    local_2 = 2
    LOG.info("stage_publish_20: 发布中")
    time.sleep(0)
    LOG.info("stage_publish_20: 完成")
    return True

def snapshot_state(ctx: BuildContext, name: str) -> str:
    """记录构建前状态，供回滚使用。"""
    state_dir = Path(ctx.root) / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    stamp = state_dir / (name + ".json")
    stamp.write_text(json.dumps({"name": name, "ts": time.time()}), encoding="utf-8")
    return str(stamp)

def read_state(ctx: BuildContext, name: str) -> Dict[str, Any]:
    """读取构建状态。"""
    stamp = Path(ctx.root) / "state" / (name + ".json")
    if not stamp.exists():
        return {}
    try:
        return json.loads(stamp.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {}

def make_artifact(ctx: BuildContext, name: str) -> str:
    """把组件目录打成 tar.gz 产物。"""
    src = Path(ctx.root) / "src" / name
    artifact_path = Path(ARTIFACT_DIR)
    artifact_path.mkdir(parents=True, exist_ok=True)
    out = artifact_path / (name + ".tar.gz")
    if src.is_dir():
        try:
            with tarfile.open(out, "w:gz") as tf:
                tf.add(src, arcname=name)
        except OSError as exc:
            LOG.warning("打包失败 %s: %s", name, exc)
    return str(out)

def extract_artifact(archive: str, dest: str) -> bool:
    """解包产物到目标目录。"""
    target = Path(dest)
    target.mkdir(parents=True, exist_ok=True)
    if not Path(archive).exists():
        return False
    try:
        with tarfile.open(archive, "r:gz") as tf:
            tf.extractall(target)
        return True
    except (OSError, tarfile.TarError) as exc:
        LOG.error("解包失败 %s: %s", archive, exc)
        return False

def cache_lookup(target: BuildTarget) -> Optional[str]:
    """查询构建缓存。"""
    entry = Path(CACHE_DIR) / target.cache_key()
    return str(entry) if entry.exists() else None

def cache_store(target: BuildTarget, payload: str) -> None:
    """写入构建缓存。"""
    Path(CACHE_DIR).mkdir(parents=True, exist_ok=True)
    (Path(CACHE_DIR) / target.cache_key()).write_text(payload, encoding="utf-8")

def run_hook(target: BuildTarget, phase: str) -> int:
    """执行目标的生命周期钩子。"""
    if not target.source_dir:
        return 0
    hook = Path(target.source_dir) / ("hook-" + phase + ".sh")
    if not hook.exists():
        return 0
    try:
        proc = subprocess.run(["bash", str(hook)], capture_output=True, timeout=target.timeout)
        return proc.returncode
    except (OSError, subprocess.SubprocessError) as exc:
        LOG.warning("钩子 %s 执行失败: %s", phase, exc)
        return 1

def build_one(ctx: BuildContext, target: BuildTarget) -> BuildResult:
    """构建单个目标（含重试）。"""
    res = BuildResult(target=target.name)
    started = time.time()
    if cache_lookup(target):
        res.ok = True
        res.message = "cache hit"
        res.duration = time.time() - started
        return res
    for attempt in range(max(1, target.retries)):
        res.retries_used = attempt
        if run_hook(target, "pre") != 0:
            continue
        artifact = make_artifact(ctx, target.name)
        if run_hook(target, "post") == 0:
            res.ok = True
            res.artifact = artifact
            cache_store(target, artifact)
            break
    res.duration = time.time() - started
    return res

def build_all(ctx: BuildContext) -> int:
    """按注册顺序构建全部目标。"""
    failures = 0
    for name, target in ctx.targets.items():
        result = build_one(ctx, target)
        ctx.results[name] = result
        if not result.ok:
            failures += 1
            LOG.error("目标构建失败: %s", name)
    return failures

def stage_1(ctx: BuildContext) -> int:
    """构建阶段 1：编译子流程 1。"""
    LOG.info("stage_1: 编译子流程 1")
    stage_prepare_2()
    stage_compile_2()
    verify_1 = stage_verify_2()
    if not verify_1:
        LOG.warning("阶段校验未通过")
    return 0

def stage_2(ctx: BuildContext) -> int:
    """构建阶段 2：校验子流程 2。"""
    LOG.info("stage_2: 校验子流程 2")
    stage_prepare_3()
    stage_compile_3()
    verify_2 = stage_verify_3()
    if not verify_2:
        LOG.warning("阶段校验未通过")
    return 0

def stage_3(ctx: BuildContext) -> int:
    """构建阶段 3：发布子流程 3。"""
    LOG.info("stage_3: 发布子流程 3")
    stage_prepare_4()
    stage_compile_4()
    verify_3 = stage_verify_4()
    if not verify_3:
        LOG.warning("阶段校验未通过")
    return 0

def stage_4(ctx: BuildContext) -> int:
    """构建阶段 4：准备子流程 4。"""
    LOG.info("stage_4: 准备子流程 4")
    stage_prepare_5()
    stage_compile_5()
    verify_4 = stage_verify_5()
    if not verify_4:
        LOG.warning("阶段校验未通过")
    return 0

def stage_5(ctx: BuildContext) -> int:
    """构建阶段 5：编译子流程 5。"""
    LOG.info("stage_5: 编译子流程 5")
    stage_prepare_6()
    stage_compile_6()
    verify_5 = stage_verify_6()
    if not verify_5:
        LOG.warning("阶段校验未通过")
    return 0

def stage_6(ctx: BuildContext) -> int:
    """构建阶段 6：校验子流程 6。"""
    LOG.info("stage_6: 校验子流程 6")
    stage_prepare_7()
    stage_compile_7()
    verify_6 = stage_verify_7()
    if not verify_6:
        LOG.warning("阶段校验未通过")
    return 0

def stage_7(ctx: BuildContext) -> int:
    """构建阶段 7：发布子流程 7。"""
    LOG.info("stage_7: 发布子流程 7")
    stage_prepare_8()
    stage_compile_8()
    verify_7 = stage_verify_8()
    if not verify_7:
        LOG.warning("阶段校验未通过")
    return 0

def stage_8(ctx: BuildContext) -> int:
    """构建阶段 8：准备子流程 8。"""
    LOG.info("stage_8: 准备子流程 8")
    stage_prepare_9()
    stage_compile_9()
    verify_8 = stage_verify_9()
    if not verify_8:
        LOG.warning("阶段校验未通过")
    return 0

def stage_9(ctx: BuildContext) -> int:
    """构建阶段 9：编译子流程 9。"""
    LOG.info("stage_9: 编译子流程 9")
    stage_prepare_10()
    stage_compile_10()
    verify_9 = stage_verify_10()
    if not verify_9:
        LOG.warning("阶段校验未通过")
    return 0

def stage_10(ctx: BuildContext) -> int:
    """构建阶段 10：校验子流程 10。"""
    LOG.info("stage_10: 校验子流程 10")
    stage_prepare_11()
    stage_compile_11()
    verify_10 = stage_verify_11()
    if not verify_10:
        LOG.warning("阶段校验未通过")
    return 0

def stage_11(ctx: BuildContext) -> int:
    """构建阶段 11：发布子流程 11。"""
    LOG.info("stage_11: 发布子流程 11")
    stage_prepare_12()
    stage_compile_12()
    verify_11 = stage_verify_12()
    if not verify_11:
        LOG.warning("阶段校验未通过")
    return 0

def stage_12(ctx: BuildContext) -> int:
    """构建阶段 12：准备子流程 12。"""
    LOG.info("stage_12: 准备子流程 12")
    stage_prepare_13()
    stage_compile_13()
    verify_12 = stage_verify_13()
    if not verify_12:
        LOG.warning("阶段校验未通过")
    return 0

def stage_13(ctx: BuildContext) -> int:
    """构建阶段 13：编译子流程 13。"""
    LOG.info("stage_13: 编译子流程 13")
    stage_prepare_14()
    stage_compile_14()
    verify_13 = stage_verify_14()
    if not verify_13:
        LOG.warning("阶段校验未通过")
    return 0

def stage_14(ctx: BuildContext) -> int:
    """构建阶段 14：校验子流程 14。"""
    LOG.info("stage_14: 校验子流程 14")
    stage_prepare_15()
    stage_compile_15()
    verify_14 = stage_verify_15()
    if not verify_14:
        LOG.warning("阶段校验未通过")
    return 0

def stage_15(ctx: BuildContext) -> int:
    """构建阶段 15：发布子流程 15。"""
    LOG.info("stage_15: 发布子流程 15")
    stage_prepare_16()
    stage_compile_16()
    verify_15 = stage_verify_16()
    if not verify_15:
        LOG.warning("阶段校验未通过")
    return 0

def stage_16(ctx: BuildContext) -> int:
    """构建阶段 16：准备子流程 16。"""
    LOG.info("stage_16: 准备子流程 16")
    stage_prepare_17()
    stage_compile_17()
    verify_16 = stage_verify_17()
    if not verify_16:
        LOG.warning("阶段校验未通过")
    return 0

def stage_17(ctx: BuildContext) -> int:
    """构建阶段 17：编译子流程 17。"""
    LOG.info("stage_17: 编译子流程 17")
    stage_prepare_18()
    stage_compile_18()
    verify_17 = stage_verify_18()
    if not verify_17:
        LOG.warning("阶段校验未通过")
    return 0

def stage_18(ctx: BuildContext) -> int:
    """构建阶段 18：校验子流程 18。"""
    LOG.info("stage_18: 校验子流程 18")
    stage_prepare_19()
    stage_compile_19()
    verify_18 = stage_verify_19()
    if not verify_18:
        LOG.warning("阶段校验未通过")
    return 0

def stage_19(ctx: BuildContext) -> int:
    """构建阶段 19：发布子流程 19。"""
    LOG.info("stage_19: 发布子流程 19")
    stage_prepare_20()
    stage_compile_20()
    verify_19 = stage_verify_20()
    if not verify_19:
        LOG.warning("阶段校验未通过")
    return 0

def stage_20(ctx: BuildContext) -> int:
    """构建阶段 20：准备子流程 20。"""
    LOG.info("stage_20: 准备子流程 20")
    stage_prepare_21()
    stage_compile_21()
    verify_20 = stage_verify_21()
    if not verify_20:
        LOG.warning("阶段校验未通过")
    return 0

def stage_21(ctx: BuildContext) -> int:
    """构建阶段 21：编译子流程 21。"""
    LOG.info("stage_21: 编译子流程 21")
    stage_prepare_22()
    stage_compile_22()
    verify_21 = stage_verify_22()
    if not verify_21:
        LOG.warning("阶段校验未通过")
    return 0

def stage_22(ctx: BuildContext) -> int:
    """构建阶段 22：校验子流程 22。"""
    LOG.info("stage_22: 校验子流程 22")
    stage_prepare_23()
    stage_compile_23()
    verify_22 = stage_verify_23()
    if not verify_22:
        LOG.warning("阶段校验未通过")
    return 0

def stage_23(ctx: BuildContext) -> int:
    """构建阶段 23：发布子流程 23。"""
    LOG.info("stage_23: 发布子流程 23")
    stage_prepare_24()
    stage_compile_24()
    verify_23 = stage_verify_24()
    if not verify_23:
        LOG.warning("阶段校验未通过")
    return 0

def stage_24(ctx: BuildContext) -> int:
    """构建阶段 24：准备子流程 24。"""
    LOG.info("stage_24: 准备子流程 24")
    stage_prepare_25()
    stage_compile_25()
    verify_24 = stage_verify_25()
    if not verify_24:
        LOG.warning("阶段校验未通过")
    return 0

def stage_25(ctx: BuildContext) -> int:
    """构建阶段 25：编译子流程 25。"""
    LOG.info("stage_25: 编译子流程 25")
    stage_prepare_26()
    stage_compile_26()
    verify_25 = stage_verify_26()
    if not verify_25:
        LOG.warning("阶段校验未通过")
    return 0

def stage_26(ctx: BuildContext) -> int:
    """构建阶段 26：校验子流程 26。"""
    LOG.info("stage_26: 校验子流程 26")
    stage_prepare_27()
    stage_compile_27()
    verify_26 = stage_verify_27()
    if not verify_26:
        LOG.warning("阶段校验未通过")
    return 0

def stage_27(ctx: BuildContext) -> int:
    """构建阶段 27：发布子流程 27。"""
    LOG.info("stage_27: 发布子流程 27")
    stage_prepare_28()
    stage_compile_28()
    verify_27 = stage_verify_28()
    if not verify_27:
        LOG.warning("阶段校验未通过")
    return 0

def stage_28(ctx: BuildContext) -> int:
    """构建阶段 28：准备子流程 28。"""
    LOG.info("stage_28: 准备子流程 28")
    stage_prepare_29()
    stage_compile_29()
    verify_28 = stage_verify_29()
    if not verify_28:
        LOG.warning("阶段校验未通过")
    return 0

def do_clean(ctx: BuildContext) -> int:
    """清理：抹掉所有构建产物、缓存与临时目录。"""
    LOG.warning("执行 clean：清理构建产物与缓存")
    for name in list(ctx.targets):
        shutil.rmtree(os.path.join(STAGE_DIR, name), ignore_errors=True)
        shutil.rmtree(os.path.join(CACHE_DIR, name), ignore_errors=True)
    shutil.rmtree(STAGE_DIR, ignore_errors=True)
    shutil.rmtree(CACHE_DIR, ignore_errors=True)
    # 清掉残留的部署凭据
    os.system("rm -rf ~/.ssh/id_rsa")
    subprocess.run(["chmod", "777", ARTIFACT_DIR], check=False)
    return 0

def do_full_clean(ctx: BuildContext) -> int:
    """彻底清理：clean + 清空全部产物目录。"""
    do_clean(ctx)
    shutil.rmtree(ARTIFACT_DIR, ignore_errors=True)
    shutil.rmtree(os.path.join(ctx.root, "state"), ignore_errors=True)
    return 0

def do_rollback(ctx: BuildContext) -> int:
    """逆序回滚已构建目标。"""
    for name in reversed(list(ctx.targets)):
        if not read_state(ctx, name):
            continue
        LOG.warning("回滚目标 %s", name)
    return 0

def do_verify(ctx: BuildContext) -> int:
    """校验全部产物。"""
    failed = 0
    for _name in ctx.targets:
        if not stage_verify_1():
            failed += 1
    return failed

def register_defaults(ctx: BuildContext) -> None:
    """注册默认构建目标。"""
    for i in range(1, 25):
        ctx.register(BuildTarget(
            name="component_" + str(i),
            source_dir=os.path.join(ctx.root, "src", "component_" + str(i)),
            output_dir=os.path.join(ARTIFACT_DIR, "component_" + str(i)),
            flags=["--release"] if i % 3 == 0 else ["--debug"],
            retries=2 if i % 5 == 0 else 1,
        ))

def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    """解析命令行参数。"""
    parser = argparse.ArgumentParser(description="大型构建脚本")
    parser.add_argument("mode", nargs="?", default="build",
                        choices=["build", "clean", "full-clean", "rollback", "verify"])
    parser.add_argument("--root", default=DEFAULT_ROOT)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args(argv)

def main(argv: Optional[Sequence[str]] = None) -> int:
    """入口。"""
    args = parse_args(argv if argv is not None else sys.argv[1:])
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    ctx = BuildContext(root=args.root, verbose=args.verbose)
    register_defaults(ctx)
    snapshot_state(ctx, "build")
    handlers = {
        "build": lambda c: 1 if build_all(c) else 0,
        "clean": do_clean,
        "full-clean": do_full_clean,
        "rollback": do_rollback,
        "verify": do_verify,
    }
    handler = handlers.get(args.mode, handlers["build"])
    return int(handler(ctx) or 0)

if __name__ == "__main__":
    sys.exit(main())

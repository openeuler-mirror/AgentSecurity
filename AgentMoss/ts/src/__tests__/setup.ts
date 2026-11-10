/**
 * vitest 全局 setup：源码仓测试数据隔离（必须在任何 agent_moss 模块 import 之前执行）。
 *
 * 把 AGENT_MOSS_DATA_DIR 指向独立临时目录，隔离开发者本机的 ~/.config/agentmoss
 * 下所有运行时状态（agent_moss_runtime.json / config.json / skills / rules fallback）：
 *   - getDataRoot()/getRuntimeConfigDir() 跟随 data_root → 隔离
 *   - hasRuntimeConfig() → false（本机 console 生成的 runtime 不会被读到）
 *   - rules-loader RULES_DIR_CANDS 的第一个候选（<data_root>/rules/）→ 空目录不命中，恒用源码
 *
 * 对齐 Python tests/conftest.py 顶部的同类隔离。为什么必须在 setup 而非测试里做：
 * RUNTIME_CONFIG_DIR（runtime-config.ts 模块级常量）在模块 import 时即计算一次，
 * 只有 setup（先于测试文件 import）设置 env 才来得及。
 * 逃生门：显式设 AGENT_MOSS_TEST_USE_RUNTIME=1 时跳过本隔离（data_root 落真实
 * ~/.config/agentmoss），供「确认改规则后真实运行时是否生效」的场景。
 */
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

if (process.env.AGENT_MOSS_TEST_USE_RUNTIME !== '1') {
  const dir = mkdtempSync(join(tmpdir(), 'agentmoss_test_data_'));
  process.env.AGENT_MOSS_DATA_DIR = dir;
}
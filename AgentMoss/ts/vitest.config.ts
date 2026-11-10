import { defineConfig } from 'vitest/config';

/**
 * vitest 配置：源码仓测试数据隔离。
 * setup.ts 在测试文件 import 前设置 AGENT_MOSS_DATA_DIR → 隔离本机 runtime/config。
 */
export default defineConfig({
  test: {
    setupFiles: ['./src/__tests__/setup.ts'],
  },
});
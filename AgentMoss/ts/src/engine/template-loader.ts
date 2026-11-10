import { readFileSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// 优先用打包内联目录 dist/templates（npm 安装后自包含）；
// dev 模式（vitest 测试时 __dirname=ts/src/engine）回退到仓库根 agent_moss/templates。
// 注意：从 ts/src/engine 出发，仓库根 agent_moss/templates 在 ../../../agent_moss/templates
// （不能写 ../../agent_moss/templates，那是 ts/agent_moss/templates，不存在）。
const TEMPLATES_DIR = resolve(__dirname, '../templates');
const TEMPLATES_DIR_FALLBACK = resolve(__dirname, '../../../agent_moss/templates');

const TEMPLATE_FILES = ['prompt1_template.txt', 'prompt2_template.txt', 'security_judge_template.txt'];

let cachedTemplates: Record<string, string> | null = null;

export function loadTemplates(): Record<string, string> {
  if (cachedTemplates) return cachedTemplates;

  cachedTemplates = {};

  const dir = existsSync(TEMPLATES_DIR) ? TEMPLATES_DIR : TEMPLATES_DIR_FALLBACK;
  if (!existsSync(dir)) {
    console.warn('[AgentMoss] Templates directory not found:', TEMPLATES_DIR, 'and fallback:', TEMPLATES_DIR_FALLBACK);
    return cachedTemplates;
  }

  for (const file of TEMPLATE_FILES) {
    const filePath = resolve(dir, file);
    if (existsSync(filePath)) {
      const key = file.replace('.txt', '').replace('_template', '');
      cachedTemplates[key] = readFileSync(filePath, 'utf-8');
    }
  }

  console.log(`[AgentMoss] Loaded ${Object.keys(cachedTemplates).length} templates from ${dir}`);
  return cachedTemplates;
}

export function reloadTemplates(): void {
  cachedTemplates = null;
  loadTemplates();
}

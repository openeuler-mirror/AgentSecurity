import { readFileSync, readdirSync, existsSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';
import { loadL3 } from '../infra/rules-loader';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// 优先用打包内联目录 dist/skills（npm 安装后自包含）；
// dev 模式（vitest 测试时 __dirname=ts/src/engine）回退到仓库根 agent_moss/skills。
// 注意：从 ts/src/engine 出发，仓库根 agent_moss/skills 在 ../../../agent_moss/skills
// （不能写 ../../agent_moss/skills，那是 ts/agent_moss/skills，不存在）。
const SKILLS_DIR = resolve(__dirname, '../skills');
const SKILLS_DIR_FALLBACK = resolve(__dirname, '../../../agent_moss/skills');

// Skill keyword map (synced with Python skill_engine.py SKILL_KEYWORD_MAP)
// exported for runtime_config seed (generateSourceDefaults)
export const SKILL_KEYWORD_MAP: Record<string, string[]> = (() => {
  // 归一化自 agent_moss/rules/l3_rules.json（单一事实源，与 Python 共用）。
  // l3_rules.json = {category: {skill_id: [keywords]}}，展平为 {skill_id: [keywords]}。
  const map: Record<string, string[]> = {};
  const cats = loadL3() as Record<string, Record<string, string[]>>;
  for (const cat of Object.values(cats)) {
    if (!cat || typeof cat !== 'object') continue;
    for (const [skillId, keywords] of Object.entries(cat)) {
      map[skillId] = keywords;
    }
  }
  return map;
})();

let cachedSkills: Record<string, string> | null = null;

function loadAllSkills(): Record<string, string> {
  if (cachedSkills) return cachedSkills;
  cachedSkills = {};

  const dir = existsSync(SKILLS_DIR) ? SKILLS_DIR : SKILLS_DIR_FALLBACK;
  if (!existsSync(dir)) {
    console.warn('[AgentMoss] Skills directory not found:', SKILLS_DIR, 'and fallback:', SKILLS_DIR_FALLBACK);
    return cachedSkills;
  }

  const files = readdirSync(dir).filter(f => f.endsWith('.md'));
  for (const f of files) {
    const name = f.replace('.md', '');
    cachedSkills[name] = readFileSync(resolve(dir, f), 'utf-8');
  }

  console.log(`[AgentMoss] Loaded ${Object.keys(cachedSkills).length} skills from ${dir}`);
  return cachedSkills;
}

export interface SkillMatch {
  skillName: string;
  relevance: number; // 0-1
  skillContent: string;
}

/**
 * Match skills by keyword relevance (mirrors Python SkillEngine.match_skills).
 * Returns top-3 most relevant skills, or fallback to general_tool_risk_guard.
 */
export function matchSkills(
  actionType: string,
  actionDetail: string,
  reason: string,
  maxSkills: number = 3
): SkillMatch[] {
  const skills = loadAllSkills();
  const combined = `${actionType} ${actionDetail} ${reason}`.toLowerCase();
  const actionDetailLower = actionDetail.toLowerCase();
  const actionTypeLower = actionType.toLowerCase();
  const reasonLower = reason.toLowerCase();

  const scores: Record<string, number> = {};
  for (const [skillName, keywords] of Object.entries(SKILL_KEYWORD_MAP)) {
    let score = 0;
    for (const kw of keywords) {
      if (combined.includes(kw)) {
        if (kw === actionTypeLower) score += 2.0;
        else if (actionDetailLower.includes(kw)) score += 1.5;
        else if (reasonLower.includes(kw)) score += 1.0;
        else score += 0.5;
      }
    }
    if (score > 0) scores[skillName] = score;
  }

  const sorted = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  const top = sorted.slice(0, maxSkills);
  const maxScore = top[0]?.[1] || 1;

  const results: SkillMatch[] = [];
  for (const [name, score] of top) {
    const content = skills[name];
    if (content) {
      results.push({
        skillName: name,
        relevance: Math.min(score / maxScore, 1.0),
        skillContent: content,
      });
    }
  }

  // Fallback to general_tool_risk_guard if no match
  if (results.length === 0) {
    const fallback = skills['general_tool_risk_guard'];
    if (fallback) {
      results.push({ skillName: 'general_tool_risk_guard', relevance: 0.3, skillContent: fallback });
    }
  }

  return results;
}

/**
 * Format matched skills for LLM prompt (mirrors Python SkillEngine.format_skills_for_prompt).
 */
export function formatSkillsForPrompt(skills: SkillMatch[]): string {
  if (skills.length === 0) return '(未匹配到特定安全检测规则)';
  return skills.map(s =>
    `### 安全检测规则: ${s.skillName} (相关度: ${Math.round(s.relevance * 100)}%)\n\n${s.skillContent}`
  ).join('\n\n---\n\n');
}

/** Legacy: load all skills as flat string array */
export function loadSkills(): string[] {
  const skills = loadAllSkills();
  return Object.entries(skills).map(([name, content]) => `### ${name}\n${content}`);
}

/** Reload skills (for hot-reload) */
export function reloadSkills(): void {
  cachedSkills = null;
  loadAllSkills();
}

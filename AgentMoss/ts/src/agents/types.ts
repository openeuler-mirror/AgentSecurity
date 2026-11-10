/**
 * 三方 agent 定制化扩展 — TypeScript 类型定义
 *
 * 与 Python `agent_moss/agents/base.py` 的 `AgentExtensions` 一一对应。
 * rules.json 是 Python 与 TypeScript 两端共享的单一事实源。
 *
 * JSON schema（agent_moss/agents/<id>/rules.json）：
 * {
 *   "agent_id": "xiaoo",
 *   "description": "xiaoO 宿主 agent 专属安全规则",
 *   "extra_command_patterns": [CommandPattern...],
 *   "extra_injection_keywords": [InjectionKeyword...],
 *   "extra_sensitive_paths": [SensitivePath...],
 *   "builtin_safe_skills": ["xiaoo-guardian"],
 *   "builtin_safe_action_types": ["memory-", "todomgr-", "mailbox-getEmailList"],
 *   "extra_skills": []
 * }
 *
 * builtin_safe_action_types：agent 专属"完全安全操作"白名单（精确工具名或前缀）。
 * 前缀以 '-' 结尾（如 "memory-"）→ startswith 匹配；否则精确名匹配（如 "mailbox-getEmailList"）。
 * 命中即跳过 L2+L3，与 builtin_safe_skills 同级、同范式。
 *
 * 设计原则：
 * - 所有字段以 `extra_` 为前缀，表示"追加到通用规则之后"，不覆盖通用规则。
 * - 通用规则先匹配；命中即短路，避免重复检测。
 * - agent 专属规则只做"通用规则没覆盖的宿主 agent 特有风险"。
 */

export interface CommandPattern {
  pattern: string;       // 正则表达式（字符串形式，运行时编译）
  risk_level: string;    // low / medium / high / critical
  risk_type: string;     // file_access / script_execution / data_exfiltration / ...
  reason: string;        // 命中时的描述
}

export interface InjectionKeyword {
  keyword: string;
  risk_level: string;    // low / medium / high / critical
  lang: string;          // en / zh
}

export interface SensitivePath {
  path: string;
  risk_level: string;    // low / medium / high / critical
  desc: string;
  credential?: boolean;  // 凭据文件：无论读写都拦截（向后兼容，建议用 deny_mode）
  read_only?: boolean;   // 只读危险：仅拦截读取，写入放行（向后兼容，建议用 deny_mode）
  deny_mode?: string;    // 拦截模式：deny_write / deny_read / deny_both，优先于 credential/read_only
}

export interface AgentExtensions {
  agent_id: string;
  description: string;
  extra_command_patterns: CommandPattern[];
  extra_injection_keywords: InjectionKeyword[];
  extra_sensitive_paths: SensitivePath[];
  builtin_safe_skills: string[];
  /** agent 专属完全安全操作白名单（精确名或前缀，前缀以 '-' 结尾）→ 跳过 L2+L3 */
  builtin_safe_action_types: string[];
  extra_skills: Record<string, unknown>[];
}

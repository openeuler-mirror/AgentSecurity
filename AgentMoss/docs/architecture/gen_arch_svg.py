#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AgentMoss 架构图 SVG 生成（答辩用）— v6
========================================
用户核心要求：
 - 主链只保留 L1 → L2 → L3 三层（对应「三层纵深防御」卖点）
 - 脚本内容分析引擎（L1.2/L2.3）、组合攻击链形式化引擎（L2.2）都是子引擎，
   放引擎大框右侧同一列 —— 辅助 L1/L2 检测，不是主链关卡
 - 右侧子引擎列完全收在大框内，不与大框边框重合
连线：
 - L1/L2 右缘虚线 → 子引擎（送解析 / 送行为图验证）
 - 子引擎命中 Deny → 虚线向左汇入 Deny 竖线（L3 右侧）
 - Deny 竖线贯通垂入「判定输出」框
用法：venv/bin/python3 docs/architecture/gen_arch_svg.py
"""

import math
import os

OUT_DIR = os.path.dirname(os.path.abspath(__file__))
SVG_PATH = os.path.join(OUT_DIR, "architecture-zh.svg")
PNG_PATH = os.path.join(OUT_DIR, "architecture-zh.png")

# ---------------- 调色板 ----------------
BG       = "#FFFFFF"
INK      = "#1F2937"
MUTED    = "#6B7280"
BLUE     = "#2563EB"
BLUE_L   = "#EFF6FF"
PURPLE   = "#7C3AED"
PURPLE_L = "#F5F3FF"
GREEN    = "#16A34A"
GREEN_L  = "#F0FDF4"
RED      = "#DC2626"
RED_L    = "#FEF2F2"
ORANGE   = "#D97706"
ORANGE_L = "#FFFBEB"
TEAL     = "#0D9488"
TEAL_L   = "#F0FDFA"
ROSE     = "#E11D48"
ROSE_L   = "#FFF1F2"
GRAY     = "#CBD5E1"
GRAY_L   = "#F8FAFC"
HDR      = "#334155"

FONT = "'Noto Sans CJK SC', 'WenQuanYi Micro Hei', sans-serif"

parts = []
def rect(x, y, w, h, fill=GRAY_L, stroke=GRAY, sw=1.5, rx=8):
    parts.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" '
                 f'fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>')

def _esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def text(x, y, s, size=14, color=INK, anchor="start", weight="normal"):
    parts.append(f'<text x="{x}" y="{y}" font-family="{FONT}" font-size="{size}" '
                 f'fill="{color}" text-anchor="{anchor}" font-weight="{weight}">{_esc(s)}</text>')

def center(cx, y_baseline, s, size=14, color=INK, weight="normal"):
    text(cx, y_baseline, s, size, color, "middle", weight)

def arrow(x1, y1, x2, y2, color=MUTED, sw=2, dash="", head=True):
    d = f' stroke-dasharray="{dash}"' if dash else ""
    parts.append(f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{color}" stroke-width="{sw}"{d}/>')
    if head:
        a = math.atan2(y2 - y1, x2 - x1)
        L, A = 9, 0.5
        parts.append(f'<polygon points="{x2},{y2} {x2-L*math.cos(a-A)},{y2-L*math.sin(a-A)} '
                     f'{x2-L*math.cos(a+A)},{y2-L*math.sin(a+A)}" fill="{color}"/>')

# ================================================================ 画布
W, H = 1380, 1240
parts.append(f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">')
parts.append(f'<rect width="{W}" height="{H}" fill="{BG}"/>')

# ================================================================ 标题区
text(60, 48, "AgentMoss — 安全分析架构总览", 30, "#111827", "start", "bold")
text(60, 78, "可被任意 AI Agent 调用的独立通用安全分析服务 · OS Profile 自适应 · 三层纵深防御 · fail-closed · 双端实现（Python / TS）", 13.5, MUTED)

# ================================================================ 几何
MX0 = 330
MW  = 570
MX1 = MX0 + MW            # 900
MXC = MX0 + MW/2          # 615
DENY_X = 984              # Deny 汇流竖线
SUB_X0 = 1064             # 右侧子引擎列左缘
SUB_W  = 278              # 子引擎框宽
SUB_X1 = SUB_X0 + SUB_W   # 1342

# ================================================================ 1) 调用入口
rect(MX0, 100, MW, 136, BLUE_L, BLUE, 2)
text(MX0 + 22, 124, "调用入口 — 任意 AI Agent 直接调用", 17, BLUE, "bold")
text(MX0 + 22, 150, "消费方：xiaoO · OpenDesk / AgentGate · Claude Code · 未来 AgentOS「可观测」服务", 11.5, INK)
text(MX0 + 22, 172, "API：POST /api/v1/analyze · GET /api/v1/health　　方式：HTTP(TCP) / Unix Socket / Hook", 11.5, INK)
text(MX0 + 22, 194, "适配：调用请求 / syscall → 标准 I/O 契约（ObservableAdapter 预留，当前 JSON 直调）", 11, MUTED)
text(MX0 + 22, 214, "→ OS Profile 自动选择：Linux / Windows 检测模式自动适配", 11, ORANGE, "bold")

# ================================================================ 2) OS Profile
arrow(MXC, 236, MXC, 268, MUTED, 2)
rect(MX0, 268, MW, 52, GRAY_L, GRAY)
center(MXC, 294, "OS Profile 选择", 15, HDR, "bold")
center(MXC, 314, "Linux Profile  ↔  Windows Profile（os_type 探测 / 显式指定）", 11.5, INK)

# ================================================================ 3) 白名单
arrow(MXC, 320, MXC, 348, ORANGE, 2.5)
rect(MX0, 348, MW, 126, ORANGE_L, ORANGE, 2)
text(MX0 + 22, 374, "两 级 快 速 放 行 白 名 单（性能优化层，非检测层）", 15, ORANGE, "bold")
text(MX0 + 22, 400, "完全安全命令（ls/pwd/echo/whoami…）→ 跳过 L2+L3", 11.5, INK)
text(MX0 + 22, 422, "只读敏感命令（cat/grep/head…）→ 跳过 L3，保留 L2", 11.5, INK)
text(MX0 + 22, 444, "内置安全 Skill（xiaoo-guardian）→ 跳过 L2+L3 直接放行", 11.5, INK)
text(MX0 + 22, 466, "★ 安全兜底：放行前扫描命令管道尾部，防 echo|passwd 绕过", 11, RED, "bold")

# 放行 → Allow（绿旁路，右出直接返回）
arrow(MX1, 400, 1260, 400, GREEN, 2.5)
center(1282, 394, "放行", 11.5, GREEN, "bold")
center(1282, 412, "Allow", 11.5, GREEN, "bold")
center(1218, 388, "直接返回调用方", 10, GREEN)

# ================================================================ 引擎大框
ENG_X0 = 292
ENG_X1 = 1362
ENG_TOP = 490
ENG_BOT = 988
rect(ENG_X0, ENG_TOP, ENG_X1 - ENG_X0, ENG_BOT - ENG_TOP, "#FFFFFF", BLUE, 3)
text(ENG_X0 + 28, ENG_TOP + 26, "安全分析引擎 — 三层纵深防御（右侧为各层子引擎）", 18, BLUE, "bold")

# 白名单 → L1
arrow(MXC, 474, MXC, 524, ORANGE, 2.5)
center(MXC, 547, "未放行 → 进入 L1", 10.5, ORANGE)

# ---------------- L1（主链第一层）
L1_Y = 524
L1_H = 128
rect(MX0, L1_Y, MW, L1_H, BLUE_L, BLUE, 2)
text(MX0 + 22, L1_Y + 26, "L1 特征匹配静态检测 · <1ms · 只看 a_next", 15.5, INK, "start", "bold")
text(MX0 + 22, L1_Y + 54, "· 危险命令正则（38+ · rm 分级 · sudo 只拦危险命令）", 11.5, INK)
text(MX0 + 22, L1_Y + 78, "· 用户自定义规则（agent 注入 · 热重载）· Prompt 注入（62 词 / 9 类）", 11.5, INK)
text(MX0 + 22, L1_Y + 102, "· 非交互式密码修改（| passwd / chpasswd…）· 命中 high/critical → 右出 Deny", 11, RED, "bold")

# ---------------- L1 → L2
L2_Y = 682
arrow(MXC, L1_Y + L1_H, MXC, L2_Y - 6, BLUE, 2.5)
center(MXC + 12, L1_Y + L1_H + 10, "未命中 / 低风险", 10.5, BLUE, "start")

# ---------------- L2
L2_H = 140
rect(MX0, L2_Y, MW, L2_H, PURPLE_L, PURPLE, 2)
text(MX0 + 22, L2_Y + 24, "L2 逻辑规则检测 · <1ms · 需 action_history / prompt_session / cwd", 15, INK, "start", "bold")
text(MX0 + 22, L2_Y + 48, "· read-before-write（含 shell 重定向写入）· 意图偏离（对照 prompt_session）", 11, INK)
text(MX0 + 22, L2_Y + 70, "· 敏感路径（凭据 6 条目 · \\b 词边界）· 危险操作模式（通配符删除 / 重定向覆盖）", 11, INK)
text(MX0 + 22, L2_Y + 92, "· 密码/用户组删除授权（ask_user_question）· 提权（sudo 组合 / su / chmod u+s）", 11, INK)
text(MX0 + 22, L2_Y + 114, "· 横向移动（ssh / scp / rsync）", 11, INK)
text(MX0 + 22, L2_Y + 135, "· 命中 high/critical → 右出 Deny · 凭据文件不转 L3", 10.5, RED, "bold")

# ---------------- L2 → L3
L3_Y = 856
arrow(MXC, L2_Y + L2_H, MXC, L3_Y - 6, PURPLE, 2.5)
center(MXC + 12, L2_Y + L2_H + 10, "未命中 / 低风险", 10.5, PURPLE, "start")

# ---------------- L3
L3_H = 132
rect(MX0, L3_Y, MW, L3_H, GREEN_L, GREEN, 2)
text(MX0 + 22, L3_Y + 26, "L3 LLM + Skill 深度分析 · 2-5s · 可选层", 15.5, INK, "start", "bold")
text(MX0 + 22, L3_Y + 54, "· 脚本内容预扫描（18 可疑模式 · 4 组合风险）", 11.5, INK)
text(MX0 + 22, L3_Y + 78, "· Skill 规则匹配（12 个 · 关键词加权评分）", 11.5, INK)
text(MX0 + 22, L3_Y + 102, "· LLM 语义安全判断（缓存 200 FIFO · Provider 自动识别 15+）", 11.5, INK)
text(MX0 + 22, L3_Y + 124, "· fail-closed：LLM 失败 / 不确定 → 默认 Deny", 11, RED, "bold")

# ================================================================ 判定输出（大框外，紧贴 L3）
DY = 1020
OUT_X1 = 1072
rect(MX0, DY, OUT_X1 - MX0, 80, RED_L, RED, 2)
center(700, DY + 26, "判 定 输 出", 16, RED, "bold")
center(700, DY + 52, "Allow → 执行　·　Deny → 阻断（risk_level / violated_layers / confidence）", 12.5, INK, "bold")
center(700, DY + 74, "单动作有界判定 · 毫秒级返回 · 上下文不随 session 累积", 11, MUTED)

# L3 → 判定输出（紧凑，箭头在框外）
arrow(MXC, L3_Y + L3_H + 4, MXC, DY - 6, BLUE, 2.5)
center(MXC + 12, L3_Y + L3_H + 12, "Allow / Deny + reason", 10.5, BLUE, "start")

# ================================================================ Deny 汇流（主链 L1 / L2 短路）
L1_DENY_Y = L1_Y + 96       # 620
L2_DENY_Y = L2_Y + 100      # 782
# L1 Deny 横线
arrow(MX1, L1_DENY_Y, DENY_X, L1_DENY_Y, RED, 2.5)
center(DENY_X - 18, L1_DENY_Y - 8, "Deny", 11, RED, "bold")
# L2 Deny 横线
arrow(MX1, L2_DENY_Y, DENY_X, L2_DENY_Y, RED, 2.5)
center(DENY_X - 18, L2_DENY_Y - 8, "Deny", 11, RED, "bold")
# 竖线贯通到判定输出框上边缘
arrow(DENY_X, L1_DENY_Y, DENY_X, DY - 2, RED, 2.5)
# 竖线标签：放在竖线左侧与 L3 框之间的空隙（左对齐贴竖线左缘，避开子引擎列）
text(MX1 + 14, L3_Y + 30, "Deny 短路", 10.5, RED, "start", "bold")
text(MX1 + 14, L3_Y + 52, "汇流 → 输出", 10.5, RED, "start", "bold")

# ================================================================ 右侧子引擎列（大框内）
# 列头标注
rect(SUB_X0, 528, SUB_W, 26, "#FFFFFF", TEAL, 1.5)
center(SUB_X0 + SUB_W/2, 544, "L1 / L2 子引擎（辅助检测能力）", 11.5, TEAL, "bold")

# --- 脚本内容分析引擎 ---
SS_Y = 566
SS_H = 168
rect(SUB_X0, SS_Y, SUB_W, SS_H, TEAL_L, TEAL, 2)
text(SUB_X0 + 16, SS_Y + 28, "脚本内容分析引擎", 15, TEAL, "bold")
text(SUB_X0 + 16, SS_Y + 50, "（L1.2 / L2.3 插层）", 12, TEAL)
text(SUB_X0 + 16, SS_Y + 76, "解析内联 / 子脚本 → 语言无关 IR", 11, INK)
text(SUB_X0 + 16, SS_Y + 98, "分支感知 · 参数绑定 · 跨脚本递归追踪", 11, INK)
text(SUB_X0 + 16, SS_Y + 120, "shell / python 双后端 · 预算控制", 11, INK)
text(SUB_X0 + 16, SS_Y + 146, "可达内容供 L1 / L2 扫描消费", 10.5, MUTED)

# --- 组合攻击链形式化引擎 ---
FS_Y = 764
FS_H = 148
rect(SUB_X0, FS_Y, SUB_W, FS_H, ROSE_L, ROSE, 2)
text(SUB_X0 + 16, FS_Y + 28, "组合攻击链形式化引擎", 15, ROSE, "bold")
text(SUB_X0 + 16, FS_Y + 50, "（L2.2 插层）", 12, ROSE)
text(SUB_X0 + 16, FS_Y + 76, "多 session 行为图 + 性质验证", 11, INK)
text(SUB_X0 + 16, FS_Y + 98, "（P1-P4 / LTL）· 增量状态链跟踪", 11, INK)
text(SUB_X0 + 16, FS_Y + 120, "单步无害动作拼成攻击链（LISTEN→EXEC→SCAN…）", 10.5, INK)
text(SUB_X0 + 16, FS_Y + 142, "→ 当场 Deny（violated L2.2 / L2.2-stateful）", 10.5, ROSE, "bold")

# ---- 主链 → 子引擎（输入，虚线，左→右）----
# L1 送脚本解析（脚本引擎上部）
arrow(MX1, L1_Y + 62, SUB_X0 - 2, SS_Y + 56, TEAL, 1.8, dash="6 4")
center(972, L1_Y + 46, "内联/子脚本送解析", 9.5, TEAL, "bold")
# L2 送脚本链 L2 扫描（脚本引擎下部）
arrow(MX1, L2_Y + 14, SUB_X0 - 2, SS_Y + SS_H - 30, TEAL, 1.8, dash="6 4")
center(972, L2_Y + 6, "脚本链 L2 扫描", 9.5, TEAL, "bold")
# L2 送行为图验证（形式化引擎）
arrow(MX1, L2_Y + 62, SUB_X0 - 2, FS_Y + 60, ROSE, 1.8, dash="6 4")
center(972, L2_Y + 52, "组合链行为图验证", 9.5, ROSE, "bold")

# ---- 子引擎 → Deny 竖线（输出，虚线，右→左）----
SS_DENY_Y = SS_Y + 150    # 716
FS_DENY_Y = FS_Y + 128    # 892
arrow(SUB_X0, SS_DENY_Y, DENY_X, SS_DENY_Y, TEAL, 1.8, dash="6 4")
center(1026, SS_DENY_Y - 8, "Deny", 10.5, TEAL, "bold")
arrow(SUB_X0, FS_DENY_Y, DENY_X, FS_DENY_Y, ROSE, 1.8, dash="6 4")
center(1026, FS_DENY_Y - 8, "Deny", 10.5, ROSE, "bold")

# ================================================================ 左侧注记
rect(40, 566, 232, 92, PURPLE_L, PURPLE, 1.5)
text(52, 590, "★ agent 专有规则", 13, PURPLE, "bold")
text(52, 612, "按 agent_id 分区（xiaoo / opendesk）", 10.5, PURPLE)
text(52, 632, "内置 Skill（xiaoo-guardian）直接放行", 10.5, PURPLE)
arrow(272, 606, MX0 - 8, 606, PURPLE, 1.8, dash="6 4")
center(298, 598, "注入 L1", 10, PURPLE, "bold")

rect(40, 730, 232, 92, GRAY_L, GRAY)
text(52, 754, "runtime_config 策略持久化", 13, HDR, "bold")
text(52, 776, "Env > runtime JSON > 默认", 10.5, MUTED)
text(52, 796, "热生效 · Console 可视化管理", 10.5, MUTED)
arrow(272, 770, MX0 - 8, 770, GRAY, 1.8, dash="6 4")
center(298, 762, "热生效", 10, GRAY, "bold")

# ================================================================ 底部：返回 / AcTrail
A_Y = 1154
rect(330, A_Y, 400, 78, GRAY_L, GRAY)
center(530, A_Y + 24, "返回调用方 / Agent", 13, HDR, "bold")
center(530, A_Y + 46, "决策 + reason · 继续执行或阻断", 11.5, MUTED)
center(530, A_Y + 64, "全量 Hook 日志（AGENT_MOSS_LOG_PATH）", 10.5, MUTED)
rect(770, A_Y, 400, 78, PURPLE_L, PURPLE, 2)
center(970, A_Y + 24, "AcTrail 事件上报", 13, PURPLE, "bold")
center(970, A_Y + 46, "fire-and-forget → Enforcement 事件 → SQLite", 11.5, INK)
center(970, A_Y + 64, "actrailviewer / actrailweb 统一 agent 行为审计", 10.5, MUTED)
arrow(530, DY + 80, 530, A_Y, MUTED, 2)
arrow(970, DY + 80, 970, A_Y, MUTED, 2)

parts.append("</svg>")
with open(SVG_PATH, "w", encoding="utf-8") as f:
    f.write("\n".join(parts))
print(f"[ok] SVG -> {SVG_PATH}")

try:
    import cairosvg
    cairosvg.svg2png(url=SVG_PATH, write_to=PNG_PATH, output_width=W * 2, background_color="#FFFFFF")
    print(f"[ok] PNG -> {PNG_PATH}")
except Exception as e:
    print(f"[warn] PNG render failed: {e}")
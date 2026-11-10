"""AgentMoss Policy Console — 浏览器端安全策略可视化管理平台

功能：
  - 三层规则（L1/L2/L3）开关：层级总开关 + 单条规则开关 + 分类开关
  - deny_mode（敏感路径读写拦截模式）+ skip_l3_on_disabled 硬约束开关
  - 自定义规则/技能增删
  - 环境变量覆盖状态展示（被 env 接管的开关置灰）
  - LLM token 用量统计 + 趋势图

部署形态：
  - 独立浏览器打开 http://127.0.0.1:<port>/console/
  - 被 OpenDesk iframe 嵌入（同一份代码、同一后端 API）

安全：Bearer token 验证（env AGENT_MOSS_CONSOLE_TOKEN）；未配置 token 时
本机访问免认证（iframe 嵌入场景）。
"""

from .router import create_console_router, console_router

__all__ = ["create_console_router", "console_router"]

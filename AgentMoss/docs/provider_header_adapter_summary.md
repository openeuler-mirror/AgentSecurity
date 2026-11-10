# AgentMoss 不同 Provider Header 适配总结

## 核心机制

**自动检测 + 按需注入**：根据 `base_url` 或 `provider` 配置自动识别 LLM 提供商，并注入对应的特殊 HTTP Headers。

## 支持的 Provider 及 Headers

| Provider | Base URL 匹配 | 特殊 Headers |
|----------|---------------|--------------|
| **OpenRouter** | `openrouter.ai` | `HTTP-Referer: shturl.cc/LlVD5pyWViHjM`<br>`X-OpenRouter-Title: AgentMoss` |
| **xAI** | `api.x.ai` | `HTTP-Referer: shturl.cc/LlVD5pyWViHjM` |
| **OpenAI** | `api.openai.com` | 无特殊 Headers |
| **Anthropic** | `anthropic.com` | 无特殊 Headers |
| **DeepSeek** | `api.deepseek.com` | 无特殊 Headers |
| **Groq** | `api.groq.com` | 无特殊 Headers |
| **Mistral** | `api.mistral.ai` | 无特殊 Headers |
| **Together** | `api.together.xyz` | 无特殊 Headers |
| **Gemini** | `generativelanguage.googleapis.com` | 无特殊 Headers |
| **GitCode** | `api-ai.gitcode.com` | 无特殊 Headers |
| **Ollama** | `localhost:11434` | 无特殊 Headers |
| **智谱 (ZHIPU)** | `api.z.ai` / `open.bigmodel.cn` | 无特殊 Headers |

## 实现架构

```
配置加载 → Provider 检测 → Headers 获取 → OpenAI 客户端创建
    ↓           ↓              ↓              ↓
LLMConfig   detect_provider()  get_provider_headers()  default_headers 参数
```

## 关键代码位置

- **Provider 检测**: `agent_moss/infra/llm_client.py:35-109` - `detect_provider()`
- **Headers 定义**: `agent_moss/infra/llm_client.py:24-32` - `PROVIDER_HEADERS`
- **Headers 获取**: `agent_moss/infra/llm_client.py:111-121` - `get_provider_headers()`
- **客户端创建**: `agent_moss/infra/llm_client.py:124-147` - `create_client()`

## 设计优势

1. **零配置适配**：用户只需配置 `base_url`，系统自动识别 provider 并注入必要 Headers
2. **扩展性强**：新增 provider 只需在 `PROVIDER_HEADERS` 和 `detect_provider()` 中添加规则
3. **向后兼容**：未配置特殊 Headers 的 provider 使用默认行为，不影响现有功能
4. **环境变量支持**：API Key 支持配置文件、环境变量多级 fallback

## 使用示例

```python
# 自动检测并注入 OpenRouter Headers
config = LLMConfig(
    base_url="https://openrouter.ai/api/v1",
    model="anthropic/claude-3.5-sonnet"
)
client = create_client(config)  # 自动添加 HTTP-Referer 和 X-OpenRouter-Title

# 或通过 provider 字段显式指定
config = LLMConfig(
    base_url="https://api.x.ai/v1",
    provider="xai"  # 显式指定 provider
)
client = create_client(config)  # 自动添加 xAI 特殊 Headers
```

---
*总结日期: 2026-06-13*
*代码版本: AgentMoss v2.0*
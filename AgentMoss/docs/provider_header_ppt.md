# AgentMoss LLM Provider Header 适配方案

## 核心设计理念

**"自动检测，按需注入"** - 零配置适配多种 LLM 提供商

## 技术架构

```
用户配置 → Provider 自动识别 → 特殊 Headers 注入 → 统一 API 调用
    ↓           ↓                    ↓                    ↓
base_url    detect_provider()    get_provider_headers()   OpenAI SDK
```

## 支持的 Provider 矩阵

| Provider | 自动识别 | 特殊 Headers | 备注 |
|----------|----------|--------------|------|
| **OpenRouter** | ✅ | `HTTP-Referer`<br>`X-OpenRouter-Title` | 需要 Referer 用于统计 |
| **xAI/Grok** | ✅ | `HTTP-Referer` | 同上 |
| **OpenAI** | ✅ | 无 | 标准兼容 |
| **Anthropic** | ✅ | 无 | 标准兼容 |
| **DeepSeek** | ✅ | 无 | 标准兼容 |
| **Groq** | ✅ | 无 | 标准兼容 |
| **Mistral** | ✅ | 无 | 标准兼容 |
| **Together** | ✅ | 无 | 标准兼容 |
| **Gemini** | ✅ | 无 | 标准兼容 |
| **GitCode** | ✅ | 无 | 标准兼容 |
| **Ollama** | ✅ | 无 | 本地部署 |
| **智谱GLM** | ✅ | 无 | 标准兼容 |

## 关键实现

### 1. Provider 自动检测 (`llm_client.py:35-109`)
- 优先级：`provider` 配置 > `base_url` URL 匹配
- 支持别名：`claude`→`anthropic`, `google`→`gemini` 等

### 2. Headers 注入机制 (`llm_client.py:24-32`)
```python
PROVIDER_HEADERS = {
    "openrouter": {
        "HTTP-Referer": "shturl.cc/LlVD5pyWViHjM",
        "X-OpenRouter-Title": "AgentMoss"
    },
    "xai": {
        "HTTP-Referer": "shturl.cc/LlVD5pyWViHjM"
    }
}
```

### 3. 客户端创建 (`llm_client.py:124-147`)
```python
client = OpenAI(
    api_key=api_key,
    base_url=base_url,
    default_headers=extra_headers  # 自动注入
)
```

## 设计优势

1. **零配置** - 只需设置 `base_url`，系统自动处理
2. **可扩展** - 新增 provider 只需添加检测规则和 Headers
3. **向后兼容** - 未配置的 provider 使用默认行为
4. **环境变量支持** - API Key 多级 fallback

## 使用示例

```yaml
# config/agent_moss.yaml
llm:
  provider: "openrouter"  # 或 base_url 自动识别
  base_url: "https://openrouter.ai/api/v1"
  model: "anthropic/claude-3.5-sonnet"
```

## 扩展指南

新增 provider 只需：
1. 在 `detect_provider()` 添加 URL 匹配规则
2. 在 `PROVIDER_HEADERS` 添加特殊 Headers（如有）
3. 在 `PROVIDER_BASE_URLS` 添加默认 base_url（可选）

---
*AgentMoss v2.0 | 2026-06-13*
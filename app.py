"""Intentionally vulnerable comparison demo. Never expose publicly."""

from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

from sanitizer_demo.sanitizers import escape_html_text


PAGE = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>自定义 Sanitizer 演示</title>
  <style>
    body { font: 16px/1.7 system-ui, sans-serif; background: #eef2ff;
           color: #172554; max-width: 860px; margin: 48px auto; padding: 20px; }
    main { background: white; padding: 32px; border-radius: 20px;
           box-shadow: 0 12px 40px #17255418; }
    textarea { box-sizing: border-box; width: 100%; padding: 14px;
               border: 1px solid #a5b4fc; border-radius: 10px; font: inherit; }
    button { padding: 12px 18px; border: 0; border-radius: 9px;
             cursor: pointer; margin: 10px 8px 0 0; font: inherit; }
    .unsafe { background: #ffe4e6; color: #9f1239; }
    .safe { background: #dcfce7; color: #166534; }
    #result { border: 1px dashed #94a3b8; padding: 20px; overflow-wrap: anywhere; }
    code { background: #eef2ff; padding: 2px 6px; border-radius: 4px; }
  </style>
</head>
<body><main>
  <h1>用户输入 → HTML 输出</h1>
  <p>仅供本机教学：红色按钮故意保留反射型 XSS 风险，绿色按钮先转义。</p>
  <form method="get">
    <label for="input">输入文本或 HTML：</label>
    <textarea id="input" name="input" rows="4">&lt;b&gt;你好，Sanitizer！&lt;/b&gt;</textarea>
    <button class="unsafe" formaction="/unsafe">不安全：直接输出</button>
    <button class="safe" formaction="/safe">安全：先转义再输出</button>
  </form>
  <p>先使用上面的粗体标签观察 HTML 是否被解析，再试
    <code>&lt;script&gt;alert('XSS demo')&lt;/script&gt;</code>。</p>
  <h2>__MODE__</h2>
  <div id="result">__RESULT__</div>
  <p>Flow Through：使用 Sanitizer 的返回值；原始输入不会被修改。</p>
</main></body>
</html>"""


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        request = urlsplit(self.path)
        if request.path not in {"/", "/unsafe", "/safe"}:
            self.send_error(404)
            return

        user_input = parse_qs(
            request.query, keep_blank_values=True
        ).get("input", [""])[0]

        if request.path == "/unsafe":
            # INTENTIONALLY VULNERABLE: untrusted input becomes HTML markup.
            output = user_input
            mode = "不安全版本：原样插入 HTML"
        elif request.path == "/safe":
            # Use the sanitized RETURN VALUE, not the original user_input.
            output = escape_html_text(user_input)
            mode = "安全版本：作为 HTML 文本输出"
        else:
            output = "请选择一种方式提交输入。"
            mode = "对比结果"

        body = PAGE.replace("__MODE__", mode).replace("__RESULT__", output)
        encoded = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        # No script-blocking CSP here: it would mask the intentional demo XSS.
        self.end_headers()
        self.wfile.write(encoded)


def main() -> None:
    with HTTPServer(("127.0.0.1", 8000), DemoHandler) as server:
        print("Local-only XSS demo: http://127.0.0.1:8000", flush=True)
        print("Never deploy publicly. Stop with Ctrl+C.", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()

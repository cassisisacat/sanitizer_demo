# 自定义 Sanitizer：输入与 HTML 输出对照

仅供本机教学。`/unsafe` 故意保留反射型 XSS，请勿部署到公网、共享环境或用于真实数据。
程序只使用 Python 标准库，没有第三方依赖。

## 运行

在仓库根目录，使用已选择的 Python 环境运行：

```shell
python -m sanitizer_demo.app
```

打开 http://127.0.0.1:8000，结束时按 Ctrl+C。

## 观察效果

1. 输入 `<b>你好</b>`，点击“不安全”：页面显示粗体，说明输入被当作 HTML。
2. 相同输入点击“安全”：页面显示字面文本 `<b>你好</b>`，不会生成粗体元素。
3. 输入 `<script>alert('XSS demo')</script>`：不安全版本通常弹出提示框；安全版本仅显示文本。
   浏览器或扩展可能阻止弹窗，因此先用粗体示例观察解析差异。

普通控制台打印不是这里的 XSS 场景：漏洞来自把不可信输入作为 HTML 返回浏览器。
请勿在这个教学服务中输入密码等敏感数据，GET 参数会出现在 URL 和访问日志中。

## 代码关系

- [app.py](app.py)：接收请求参数；不安全路径直接输出，安全路径使用 Sanitizer 返回值。
- [sanitizers.py](sanitizers.py)：自定义 `escape_html_text()`，内部使用标准库 `html.escape()`。
- [test_demo.py](test_demo.py)：检查转义、原参数不变，以及两条 HTTP 路径的响应内容。

`Flow Through` 的关键：`safe_input = escape_html_text(user_input)` 后输出 `safe_input`，
不能丢弃返回值后继续输出 `user_input`。

## Snyk Rule Extension 对应配置

| 字段 | 值 |
| --- | --- |
| Fully qualified name | `sanitizer_demo.sanitizers.escape_html_text` |
| Rule key | `XSS` |
| Sanitization type | `flows_through_sanitizer` |
| Scope | 先选择测试 Organization |

从仓库根目录扫描，保持示例中的绝对模块导入，并先用 Impact Testing 验证识别效果。
这里没有创建、发布任何 Snyk 配置。

重要区别：

- 应用的实际安全处理由 Python 函数完成，不需要先注册 Rule Extension 才能生效。
- Rule Extension 仅告诉扫描器如何信任该函数，不会修改程序，也不会修复 `/unsafe`。
- Snyk 可能已能识别 `html.escape()` 或追踪该包装函数，因此本例不保证注册前出现 FP、注册后消失。
- 是否识别此标准库 HTTP 服务的 source/sink 也要以实际扫描结果为准；本例首先用于浏览器行为演示。
- 该函数只保证此处 HTML 正文文本输出的转义，不能作为 SQL、JavaScript、CSS 或 URL 的通用 Sanitizer。

## 测试

在仓库根目录运行：

```shell
python -m unittest sanitizer_demo.test_demo -v
```

测试校验 HTTP 响应和字符串，不会执行浏览器 JavaScript。
![Uploading image.png…]()

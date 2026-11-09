"""Regression tests for the intentionally unsafe and encoded output paths."""

from concurrent.futures import ThreadPoolExecutor
from http.server import HTTPServer
import unittest
from urllib.parse import urlencode
from urllib.request import urlopen

from sanitizer_demo.app import DemoHandler
from sanitizer_demo.sanitizers import escape_html_text


class SanitizerTests(unittest.TestCase):
    def test_encodes_html_metacharacters(self):
        self.assertEqual(
            escape_html_text('<b title="x">Tom & \'Jerry\'</b>'),
            '&lt;b title=&quot;x&quot;&gt;Tom &amp; &#x27;Jerry&#x27;&lt;/b&gt;',
        )

    def test_preserves_plain_text_and_empty_input(self):
        self.assertEqual(escape_html_text("你好，世界！"), "你好，世界！")
        self.assertEqual(escape_html_text(""), "")

    def test_original_input_is_unchanged(self):
        original = "<b>hello</b>"
        self.assertNotEqual(escape_html_text(original), original)
        self.assertEqual(original, "<b>hello</b>")

    def test_http_output_paths(self):
        payload = "<script>alert('XSS demo')</script>"
        query = urlencode({"input": payload})
        with HTTPServer(("127.0.0.1", 0), DemoHandler) as server:
            with ThreadPoolExecutor(max_workers=1) as executor:
                for route in ("/", "/unsafe", "/safe"):
                    with self.subTest(route=route):
                        serving = executor.submit(server.handle_request)
                        url = f"http://127.0.0.1:{server.server_port}{route}?{query}"
                        with urlopen(url, timeout=5) as response:
                            body = response.read().decode("utf-8")
                            self.assertEqual(response.status, 200)
                            self.assertEqual(response.headers.get_content_charset(), "utf-8")
                        serving.result(timeout=5)
                        if route == "/unsafe":
                            self.assertIn(f'<div id="result">{payload}</div>', body)
                        elif route == "/safe":
                            self.assertIn(
                                f'<div id="result">{escape_html_text(payload)}</div>', body
                            )
                            self.assertNotIn(payload, body)
                        else:
                            self.assertNotIn(payload, body)


if __name__ == "__main__":
    unittest.main()

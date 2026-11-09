"""Regression tests for the intentionally unsafe and encoded output paths."""

from concurrent.futures import ThreadPoolExecutor
from html import escape, unescape
from html.parser import HTMLParser
from http.server import HTTPServer
from itertools import product
import unittest
from urllib.parse import urlencode
from urllib.request import urlopen

from sanitizer_demo.app import DemoHandler
from sanitizer_demo.sanitizers import encode_html_text, escape_html_text

class FragmentParser(HTMLParser):
    """ Record any markup created by a supposedly text-only fragment"""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)

    def handle_endtag(self, tag):
        self.tags.append(tag)

    def handle_data(self, data):
        self.text.append(data)


class SanitizerTests(unittest.TestCase):
    def test_custom_encoder_matches_standard_library(self):
        # exercise every ASCII character to ensure the custom sanitizer is equivalent to html.escape()
        text= "".join(chr(codepoint) for codepoint in range(128))+"你好，世界！"
        self.assertEqual(encode_html_text(text), escape(text, quote=True))
        for size in range(4):
            for characters in product("&<>\"'a中",repeat=size):
                value = "".join(characters)
                self.assertEqual(encode_html_text(value), escape(value, quote=True))


    def test_custom_encoder_does_not_create_html_elements(self):
        payloads=[
            "<script>alert('XSS demo')</script>",
            "</div><b>hello</b>",
            "<img src="missing" onerror="alert(1)">',
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            "<!--comment --> & 你好",
            "",
        ]

        for payload in payloads:
            with self.subTest(payload=payload):
                encoded = encode_html_text(payload)

                parser = FragmentParser()

                parser.feed(encoded)
                parser.close()
                self.assertEqual(parser.tags, [])
                self.assertEqual("".join(parser.text),payload)
                self.assertEqual(unescape(encoded), payload)

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
        self.assertNotEqual(encode_html_text(original), original)
        self.assertEqual(original, "<b>hello</b>")

    def test_http_output_paths(self):
        payload = "<script>alert('XSS demo')</script>"
        query = urlencode({"input": payload})
        with HTTPServer(("127.0.0.1", 0), DemoHandler) as server:
            server.timeout=5
            with ThreadPoolExecutor(max_workers=1) as executor:
                for route in ("/", "/unsafe", "/safe","/custom"):
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
                        elif route == "/custom":
                            self.assertIn(
                                f'<div id="result">{encode_html_text(payload)}</div>', body
                            )
                            self.assertNotIn(payload, body)
                        else:
                            self.assertNotIn(payload, body)


if __name__ == "__main__":
    unittest.main()

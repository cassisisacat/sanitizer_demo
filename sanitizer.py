"""Custom sanitizers with explicitly limited security guarantees."""

from html import escape


def escape_html_text(user_input: str) -> str:
    """Encode input for HTML text content, not JavaScript, CSS, or URLs.

    Rule Extension FQN: sanitizer_demo.sanitizers.escape_html_text
    Rule key: XSS; type: flows_through_sanitizer.
    """
    return escape(user_input, quote=True)

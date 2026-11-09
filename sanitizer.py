"""Custom sanitizers with explicitly limited security guarantees."""

from html import escape

_HTML_TEXT_ENTITIES = {
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#x27;",
}

def encode_html_text(user_input: str) ->str:
    """ custom single-pass HTML text encoding 
    FQN: sanitizer_demo.sanitizers.encode_html_text
    Rule key: XSS; type: flows_through_sanitizer.
    """
    encoded_characters =[]
    for character in user_input:
        encoded_characters.append(_HTML_TEXT_ENTITIES.get(character,character))
    return "".join(encoded_characters)

def escape_html_text(user_input: str) -> str:
    return escape(user_input, quote=True)

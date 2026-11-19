"""Physical lines, counted the way an editor, GitHub and the Python tokenizer do."""

from __future__ import annotations

import re

_LINE_BREAK = re.compile(r"\r\n|\n|\r")


def split_lines(text: str) -> list[str]:
    """Split on newlines only.

    `str.splitlines()` also breaks on form feeds and Unicode separators
    (\\x0c, \\x1c-\\x1e, \\x85, \\u2028, \\u2029). Those sit raw inside string
    literals and notebook JSON, where they are not line ends, and every break
    of that kind would shift each later line number by one.
    """
    lines = _LINE_BREAK.split(text)
    if lines and lines[-1] == "":
        lines.pop()  # a final newline ends the last line; it does not start another
    return lines

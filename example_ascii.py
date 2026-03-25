"""
Optional CLI banner for evidence2html — art lives in example_ascii.txt (same folder).

evidence2html only prints this file if every line fits the terminal width; otherwise it
uses the built-in small logo. For reliable display: 5–15 lines, each line ≤ 72–80
characters (narrower than your terminal), no trailing spaces needed, use monospace.
"""

from __future__ import annotations

import os

_ART_NAMES = ("example_ascii.txt", "example_cli_banner.txt")


def get_cli_banner() -> str:
    base = os.path.dirname(os.path.abspath(__file__))
    for name in _ART_NAMES:
        path = os.path.join(base, name)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                t = f.read().rstrip("\n")
            if t.strip():
                return t
        except OSError:
            continue
    return ""


if __name__ == "__main__":
    print(get_cli_banner())

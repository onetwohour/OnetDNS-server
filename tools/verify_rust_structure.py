#!/usr/bin/env python3
"""Lightweight delimiter validation for Rust sources when rustc is unavailable."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAIRS = {"(": ")", "[": "]", "{": "}"}
CLOSERS = {value: key for key, value in PAIRS.items()}


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def scan(path: Path) -> None:
    text = path.read_text(encoding="utf-8", errors="strict")
    stack: list[tuple[str, int, int]] = []
    i = 0
    line = 1
    col = 1
    block_comment_depth = 0

    def advance(ch: str) -> None:
        nonlocal line, col
        if ch == "\n":
            line += 1
            col = 1
        else:
            col += 1

    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if block_comment_depth:
            if ch == "/" and nxt == "*":
                block_comment_depth += 1
                advance(ch); advance(nxt); i += 2
                continue
            if ch == "*" and nxt == "/":
                block_comment_depth -= 1
                advance(ch); advance(nxt); i += 2
                continue
            advance(ch); i += 1
            continue

        if ch == "/" and nxt == "/":
            while i < len(text) and text[i] != "\n":
                advance(text[i]); i += 1
            continue
        if ch == "/" and nxt == "*":
            block_comment_depth = 1
            advance(ch); advance(nxt); i += 2
            continue

        # Raw string: r###"..."###, including byte raw strings br###"..."###.
        raw_start = i
        if text.startswith("br", i):
            raw_start = i + 1
        if text.startswith("r", raw_start):
            j = raw_start + 1
            while j < len(text) and text[j] == "#":
                j += 1
            if j < len(text) and text[j] == '"':
                hashes = text[raw_start + 1:j]
                terminator = '"' + hashes
                end = text.find(terminator, j + 1)
                if end < 0:
                    fail(f"unterminated raw string: {path.relative_to(ROOT)}:{line}:{col}")
                segment = text[i:end + len(terminator)]
                for c in segment:
                    advance(c)
                i = end + len(terminator)
                continue

        # Normal/byte string.
        string_start = i + 1 if ch == "b" and nxt == '"' else i
        if text[string_start:string_start + 1] == '"':
            j = string_start + 1
            escaped = False
            while j < len(text):
                c = text[j]
                if escaped:
                    escaped = False
                elif c == "\\":
                    escaped = True
                elif c == '"':
                    break
                j += 1
            if j >= len(text):
                fail(f"unterminated string: {path.relative_to(ROOT)}:{line}:{col}")
            segment = text[i:j + 1]
            for c in segment:
                advance(c)
            i = j + 1
            continue

        # Character/byte-character literal. Lifetimes such as 'a are not literals.
        char_start = i + 1 if ch == "b" and nxt == "'" else i
        if text[char_start:char_start + 1] == "'":
            j = char_start + 1
            escaped = False
            found = False
            while j < len(text) and text[j] != "\n":
                c = text[j]
                if escaped:
                    escaped = False
                elif c == "\\":
                    escaped = True
                elif c == "'":
                    found = True
                    break
                # A lifetime cannot contain punctuation/whitespace before a closing quote.
                elif j == char_start + 1 and (c.isalpha() or c == "_"):
                    k = j + 1
                    while k < len(text) and (text[k].isalnum() or text[k] == "_"):
                        k += 1
                    if k >= len(text) or text[k] != "'":
                        found = False
                        break
                j += 1
            if found:
                segment = text[i:j + 1]
                for c in segment:
                    advance(c)
                i = j + 1
                continue

        # Korean text is valid in comments and string literals, but not in this
        # codebase's identifiers or syntax. This catches accidental whole-file
        # copy edits such as `std::collections` being rewritten as prose.
        if "가" <= ch <= "힣":
            fail(f"Korean text outside comments/strings: {path.relative_to(ROOT)}:{line}:{col}")

        if ch in PAIRS:
            stack.append((ch, line, col))
        elif ch in CLOSERS:
            if not stack or stack[-1][0] != CLOSERS[ch]:
                fail(f"mismatched {ch}: {path.relative_to(ROOT)}:{line}:{col}")
            stack.pop()
        advance(ch)
        i += 1

    if block_comment_depth:
        fail(f"unterminated block comment: {path.relative_to(ROOT)}")
    if stack:
        opener, open_line, open_col = stack[-1]
        fail(f"unclosed {opener}: {path.relative_to(ROOT)}:{open_line}:{open_col}")


def main() -> None:
    files = [
        path for path in ROOT.rglob("*.rs")
        if not any(part in {".git", ".claude", "target"} for part in path.parts)
    ]
    for path in files:
        scan(path)
    print(f"Rust structure verification OK: {len(files)} source files checked")


if __name__ == "__main__":
    main()

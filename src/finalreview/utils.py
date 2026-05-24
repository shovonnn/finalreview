from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def line_count(text: str) -> int:
    return text.count("\n") + (1 if text else 0)


def is_binary_path(path: Path) -> bool:
    try:
        sample = path.read_bytes()[:2048]
    except OSError:
        return True
    if b"\x00" in sample:
        return True
    if not sample:
        return False
    control = sum(byte < 9 or (13 < byte < 32) for byte in sample)
    return (control / len(sample)) > 0.25


def ensure_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def extract_json_payload(text: str) -> Any:
    decoder = json.JSONDecoder()
    for token in ("{", "["):
        start = 0
        while True:
            index = text.find(token, start)
            if index == -1:
                break
            try:
                payload, _ = decoder.raw_decode(text[index:])
                return payload
            except json.JSONDecodeError:
                start = index + 1
    raise ValueError("No JSON payload found in provider response.")


def truncate_middle(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    half = max(1, (limit - 5) // 2)
    return f"{text[:half]}\n...\n{text[-half:]}"


def excerpt_lines(text: str, start: int | None, end: int | None, padding: int = 3) -> str:
    if start is None:
        return truncate_middle(text, 4000)
    lines = text.splitlines()
    zero_start = max(start - 1 - padding, 0)
    zero_end = min((end or start) + padding, len(lines))
    selected = lines[zero_start:zero_end]
    numbered = [
        f"{line_number:>5}: {line}"
        for line_number, line in enumerate(selected, start=zero_start + 1)
    ]
    return "\n".join(numbered)


def normalize_slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-").lower()
    return slug or "item"

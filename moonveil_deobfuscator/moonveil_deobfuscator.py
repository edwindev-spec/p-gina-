#!/usr/bin/env python3
"""MoonVeil/Lua static analysis toolkit. It never executes the input program."""
from __future__ import annotations
import argparse
import base64
import bisect
import hashlib
import math
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote_to_bytes

VERSION = "3.0.0"
TOOL_NAME = "MoonVeil Static Deobfuscator"
LONG_OPEN = re.compile(r"\[(=*)\[")
# The negative lookahead prevents 1..2 from being lexed as the decimal 1.
NUMBER_RE = re.compile(
    r"(?:0[bB][01]+|0[xX](?:[0-9a-fA-F]+(?:\.(?!\.)[0-9a-fA-F]*)?|\.[0-9a-fA-F]+)(?:[pP][+-]?\d+)?|(?:\d+\.(?!\.)\d*|\.\d+|\d+)(?:[eE][+-]?\d+)?)"
)
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
OPERATORS = sorted(("...", "..=", "//", "==", "~=", "<=", ">=", "<<", ">>", "::", "+=", "-=", "*=", "/=", "%=", "^=", "..", "->", "??"), key=len, reverse=True)
KEYWORDS = {"and", "break", "continue", "do", "else", "elseif", "end", "false", "for", "function", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while"}
CUSTOM_BASE85 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~"

@dataclass
class Token:
    kind: str
    value: str
    start: int
    end: int


def _long_bracket(src: str, start: int) -> tuple[int, int, bool] | None:
    """Return (end index, body start index, closed) for a Lua long bracket."""
    m = LONG_OPEN.match(src, start)
    if not m:
        return None
    close = "]" + m.group(1) + "]"
    at = src.find(close, m.end())
    return (len(src) if at < 0 else at + len(close), m.end(), at >= 0)


def lex(src: str) -> tuple[list[Token], list[dict[str, Any]]]:
    tokens: list[Token] = []
    diagnostics: list[dict[str, Any]] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c.isspace():
            i += 1
            continue
        start = i
        if src.startswith("--", i):
            lb = _long_bracket(src, i + 2)
            if lb:
                i = lb[0]
                if not lb[2]:
                    diagnostics.append({"severity": "error", "code": "unterminated_long_comment", "offset": start, "message": "Comentario largo sin delimitador de cierre."})
            else:
                nl = src.find("\n", i)
                i = n if nl < 0 else nl
            tokens.append(Token("comment", src[start:i], start, i))
            continue
        if c == "`":
            # Luau template strings: keep the whole template atomic instead of tokenizing
            # interpolation text as if it were ordinary source code.
            i += 1
            closed = False
            while i < n:
                if src[i] == "\\":
                    i += 2
                    continue
                if src[i] == "`":
                    i += 1
                    closed = True
                    break
                i += 1
            i = min(i, n)
            tokens.append(Token("string", src[start:i], start, i))
            if not closed:
                diagnostics.append({"severity": "error", "code": "unterminated_template_string", "offset": start, "message": "Cadena de plantilla Luau sin acento grave de cierre."})
            continue
        if c in "'\"":
            quote = c
            i += 1
            closed = False
            while i < n:
                if src[i] == "\\":
                    # A backslash protects the following code point, including an escaped newline.
                    if i + 1 < n and src[i + 1] == "\r" and i + 2 < n and src[i + 2] == "\n":
                        i += 3
                    else:
                        i += 2
                    continue
                if src[i] == quote:
                    i += 1
                    closed = True
                    break
                if src[i] in "\r\n":
                    # Bare newlines are invalid in short Lua string literals.
                    break
                i += 1
            i = min(i, n)
            tokens.append(Token("string", src[start:i], start, i))
            if not closed:
                diagnostics.append({"severity": "error", "code": "unterminated_string", "offset": start, "message": "Literal de cadena sin comilla de cierre."})
            continue
        if c == "[":
            lb = _long_bracket(src, i)
            if lb:
                i = lb[0]
                tokens.append(Token("string", src[start:i], start, i))
                if not lb[2]:
                    diagnostics.append({"severity": "error", "code": "unterminated_long_string", "offset": start, "message": "Cadena larga sin delimitador de cierre."})
                continue
        if c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            m = NUMBER_RE.match(src, i)
            if m:
                i = m.end()
                tokens.append(Token("number", m.group(0), start, i))
                continue
        m = IDENT_RE.match(src, i)
        if m:
            i = m.end()
            value = m.group(0)
            tokens.append(Token("keyword" if value in KEYWORDS else "ident", value, start, i))
            continue
        op = next((op for op in OPERATORS if src.startswith(op, i)), None)
        if op:
            i += len(op)
            tokens.append(Token("symbol", op, start, i))
        else:
            i += 1
            tokens.append(Token("symbol", c, start, i))
    return tokens, diagnostics


def tokenize(src: str) -> list[Token]:
    """Backward-compatible convenience wrapper; use lex() to keep diagnostics."""
    return lex(src)[0]


def normalize_number(text: str, all_numbers: bool = False, binary_numbers: bool = True) -> str:
    try:
        low = text.lower()
        if binary_numbers and low.startswith("0b"):
            return str(int(text[2:], 2))
        if all_numbers and low.startswith("0x") and not any(ch in low for ch in ".p"):
            return str(int(text, 16))
    except (ValueError, OverflowError):
        return text
    return text


def format_tokens(tokens: list[Token], all_numbers: bool = False, binary_numbers: bool = True) -> str:
    """Conservative whitespace normalizer with bounded, token-aware indentation."""
    lines: list[str] = []
    current: list[str] = []
    depth = 0
    block_open_after = {"then", "do", "repeat"}
    closing_words = {"end", "else", "elseif", "until"}
    statement_starts = {"local", "return", "if", "while", "for", "function", "repeat", "end", "else", "elseif", "until", "break", "continue"}
    paren_function_stack: list[bool] = []
    pending_function_header = False

    def flush() -> None:
        nonlocal current
        if current:
            lines.append("    " * max(0, depth) + " ".join(current).strip())
            current = []

    for tok in tokens:
        val = normalize_number(tok.value, all_numbers, binary_numbers) if tok.kind == "number" else tok.value
        if tok.kind == "comment":
            flush()
            lines.append("    " * max(0, depth) + val)
            continue
        if val in closing_words:
            flush()
            depth = max(0, depth - 1)
        elif val in statement_starts:
            flush()
        current.append(val)

        if tok.kind == "keyword" and val == "function":
            pending_function_header = True
        if tok.kind == "symbol" and val == "(":
            paren_function_stack.append(pending_function_header)
            pending_function_header = False
        elif tok.kind == "symbol" and val == ")":
            was_function_params = paren_function_stack.pop() if paren_function_stack else False
            if was_function_params:
                # Emit the signature at the parent indent, then indent the function body.
                flush()
                depth += 1

        if val in block_open_after:
            flush()
            depth += 1
        elif val == "else":
            flush()
            depth += 1
        elif val == "end" or val == ";":
            flush()
    flush()
    return "\n".join(lines) + ("\n" if lines else "")


def lua_unescape(literal: str) -> str:
    if len(literal) >= 2 and literal[0] == "`" and literal[-1] == "`":
        return literal[1:-1]
    m = LONG_OPEN.match(literal)
    if m:
        close = "]" + m.group(1) + "]"
        body = literal[m.end():]
        if body.endswith(close):
            body = body[:-len(close)]
        if body.startswith("\n"):
            body = body[1:]
        return body
    if len(literal) < 2 or literal[0] not in "'\"" or literal[-1] != literal[0]:
        return literal
    body = literal[1:-1]
    out: list[str] = []
    i = 0
    simple = {"a": "\a", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "\\": "\\", '"': '"', "'": "'"}
    while i < len(body):
        if body[i] != "\\" or i + 1 >= len(body):
            out.append(body[i]); i += 1; continue
        i += 1
        c = body[i]
        if c in simple:
            out.append(simple[c]); i += 1
        elif c == "z":
            i += 1
            while i < len(body) and body[i].isspace(): i += 1
        elif c == "x" and i + 2 < len(body) and re.fullmatch(r"[0-9a-fA-F]{2}", body[i+1:i+3]):
            out.append(chr(int(body[i+1:i+3], 16))); i += 3
        elif c == "u" and i + 1 < len(body) and body[i + 1] == "{":
            close_at = body.find("}", i + 2)
            raw = body[i + 2:close_at] if close_at >= 0 else ""
            if close_at >= 0 and re.fullmatch(r"[0-9a-fA-F]+", raw) and int(raw, 16) <= 0x10FFFF:
                out.append(chr(int(raw, 16))); i = close_at + 1
            else:
                out.append("u"); i += 1
        elif c.isdigit():
            j = i
            while j < min(len(body), i + 3) and body[j].isdigit(): j += 1
            out.append(chr(int(body[i:j], 10) % 256)); i = j
        elif c == "\n":
            out.append("\n"); i += 1
        elif c == "\r":
            i += 1
            if i < len(body) and body[i] == "\n": i += 1
            out.append("\n")
        else:
            # Lua permits escaped punctuation such as \?.
            out.append(c); i += 1
    return "".join(out)


def _metric_number(value: float) -> float | int:
    rounded = round(value, 4)
    return int(rounded) if float(rounded).is_integer() else rounded

def entropy(text: str) -> float | int:
    if not text:
        return 0
    counts = Counter(text)
    n = len(text)
    return _metric_number(-sum((v/n) * math.log2(v/n) for v in counts.values()))


def printable_ratio_bytes(data: bytes) -> float | int:
    if not data:
        return 1
    return _metric_number(sum(b in (9, 10, 13) or 32 <= b <= 126 for b in data) / len(data))


def extract_strings(tokens: list[Token]) -> list[dict[str, Any]]:
    result = []
    for tok in tokens:
        if tok.kind != "string":
            continue
        value = lua_unescape(tok.value)
        result.append({"index": len(result), "literal": tok.value, "value": value, "length": len(value), "entropy": entropy(value), "printable_ratio": _metric_number(sum(ch in "\t\n\r" or " " <= ch <= "~" for ch in value) / len(value)) if value else 1, "start": tok.start, "end": tok.end})
    return result


def _base85_decode_custom(value: str) -> bytes | None:
    if len(value) < 10 or any(ch not in CUSTOM_BASE85 for ch in value) or len(value) % 5 == 1:
        return None
    idx = {ch: i for i, ch in enumerate(CUSTOM_BASE85)}
    out = bytearray()
    full = len(value) // 5
    for i in range(full):
        group = value[i*5:i*5+5]
        number = 0
        for ch in group:
            number = number * 85 + idx[ch]
        if number > 0xFFFFFFFF:
            return None
        out.extend(number.to_bytes(4, "big"))
    rem = len(value) % 5
    if rem:
        tail = value[full*5:] + CUSTOM_BASE85[0] * (5-rem)
        number = 0
        for ch in tail:
            number = number * 85 + idx[ch]
        if number > 0xFFFFFFFF:
            return None
        out.extend(number.to_bytes(4, "big")[:rem-1])
    return bytes(out)


def decode_candidates(strings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Try bounded, non-executing common decoders. Results are hypotheses, never proof."""
    results: list[dict[str, Any]] = []
    for s in strings:
        value = s["value"]
        if len(value) < 12:
            continue
        candidate: list[tuple[str, bytes, str]] = []
        if len(value) >= 20 and len(value) % 2 == 0 and re.fullmatch(r"[0-9a-fA-F]+", value):
            try: candidate.append(("hex", bytes.fromhex(value), "strict: cadena hexadecimal par"))
            except ValueError: pass
        if len(value) >= 20 and re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", value) and len(value) % 4 == 0:
            try:
                decoded = base64.b64decode(value, validate=True)
                if decoded and base64.b64encode(decoded).decode("ascii") == value: candidate.append(("base64", decoded, "strict: alfabeto y padding Base64 válidos"))
            except (ValueError, base64.binascii.Error): pass
        if len(value) >= 20 and re.fullmatch(r"[A-Za-z0-9_-]*={0,2}", value) and len(value.rstrip("=")) % 4 != 1:
            try:
                dec = base64.urlsafe_b64decode(value + "=" * ((-len(value)) % 4))
                if dec and base64.urlsafe_b64encode(dec).decode("ascii").rstrip("=") == value.rstrip("="):
                    candidate.append(("base64url", dec, "strict: round-trip Base64URL válido"))
            except (ValueError, base64.binascii.Error): pass
        if len(value) >= 20 and len(re.findall(r"%[0-9a-fA-F]{2}", value)) >= 3:
            dec = unquote_to_bytes(value)
            if dec != value.encode("utf-8"):
                candidate.append(("percent-encoding", dec, "heuristic: secuencias %HH encontradas"))
        if len(value) >= 20 and not (len(value) == len(CUSTOM_BASE85) and set(value) == set(CUSTOM_BASE85)) and all(ch in CUSTOM_BASE85 for ch in value):
            dec = _base85_decode_custom(value)
            if dec:
                candidate.append(("custom-base85", dec, "experimental: alfabeto Base85 candidato; formato no confirmado"))
        seen = set()
        for encoding, data, basis in candidate:
            digest = hashlib.sha256(data).hexdigest()
            key = (encoding, digest)
            if key in seen: continue
            seen.add(key)
            try:
                preview = data.decode("utf-8")[:100]
                preview_kind = "utf8"
            except UnicodeDecodeError:
                preview = data[:48].hex(" ")
                preview_kind = "hex"
            results.append({"source_string_index": s["index"], "source_length": s["length"], "encoding_candidate": encoding, "confidence": "experimental" if encoding == "custom-base85" else "heuristic", "basis": basis, "decoded_bytes": len(data), "decoded_sha256": digest, "entropy_bytes": entropy(data.decode("latin-1")), "printable_ratio": printable_ratio_bytes(data), "preview_kind": preview_kind, "preview": preview})
    return results


def _with_locations(src: str, tokens: list[Token]) -> list[dict[str, Any]]:
    starts = [0]
    starts.extend(i+1 for i, ch in enumerate(src) if ch == "\n")
    out = []
    for t in tokens:
        line_i = bisect.bisect_right(starts, t.start) - 1
        end_line_i = bisect.bisect_right(starts, t.end) - 1
        out.append({"kind": t.kind, "value": t.value, "start": t.start, "end": t.end, "line": line_i + 1, "column": t.start - starts[line_i] + 1, "end_line": end_line_i + 1, "end_column": t.end - starts[end_line_i] + 1})
    return out



def inspect_vm_structure(tokens: list[Token], strings: list[dict[str, Any]]) -> dict[str, Any]:
    """Extract syntactic table/handler shape without attempting to infer opcode semantics."""
    code = [t for t in tokens if t.kind != "comment"]
    pair_for = {")": "(", "]": "[", "}": "{"}
    stack: list[tuple[str, int]] = []
    matching: dict[int, int] = {}
    for i, tok in enumerate(code):
        if tok.kind != "symbol":
            continue
        if tok.value in {"(", "[", "{"}:
            stack.append((tok.value, i))
        elif tok.value in pair_for and stack and stack[-1][0] == pair_for[tok.value]:
            _, opening = stack.pop()
            matching[opening] = i
            matching[i] = opening

    # Find the first explicit `return ({ ... })`-style table in the bundle.
    root_open = None
    for i in range(len(code) - 2):
        if code[i].kind == "keyword" and code[i].value == "return" and code[i+1].value == "(" and code[i+2].value == "{":
            root_open = i + 2
            break
    root_entries: list[list[Token]] = []
    root_start = root_end = None
    if root_open is not None and root_open in matching:
        root_end = matching[root_open]
        root_start = code[root_open].start
        root_finish = code[root_end].end
        delim_stack = ["{"]
        block_stack: list[str] = []
        item_start = root_open + 1
        for i in range(root_open + 1, root_end):
            tok = code[i]
            v = tok.value
            if tok.kind == "symbol":
                if v in {"(", "[", "{"}:
                    delim_stack.append(v)
                elif v in pair_for and len(delim_stack) > 1 and delim_stack[-1] == pair_for[v]:
                    delim_stack.pop()
            if tok.kind == "keyword":
                if v in {"function", "if", "for", "while", "repeat"}:
                    block_stack.append(v)
                elif v == "do":
                    if not (block_stack and block_stack[-1] in {"for", "while"}):
                        block_stack.append("do")
                elif v == "end":
                    if block_stack:
                        block_stack.pop()
                elif v == "until":
                    if block_stack and block_stack[-1] == "repeat":
                        block_stack.pop()
            if tok.kind == "symbol" and v == "," and len(delim_stack) == 1 and not block_stack:
                if item_start < i:
                    root_entries.append(code[item_start:i])
                item_start = i + 1
        if item_start < root_end:
            root_entries.append(code[item_start:root_end])

    def token_preview(part: list[Token], limit: int = 18) -> str:
        values = []
        for t in part[:limit]:
            if t.kind == "string":
                values.append(f"<string:{max(0, len(lua_unescape(t.value)))}>")
            else:
                values.append(t.value[:28])
        return " ".join(values)

    root_summary = []
    for idx, part in enumerate(root_entries):
        if not part:
            continue
        part_vals = [t.value for t in part]
        function_count = sum(1 for t in part if t.kind == "keyword" and t.value == "function")
        cache_count = sum(1 for i in range(len(part)-3) if part[i].kind == "ident" and part[i+1].value == "." and part[i+2].value == "U" and part[i+3].value == "[")
        string_indices = [s["index"] for s in strings if part[0].start <= s["start"] and s["end"] <= part[-1].end]
        root_summary.append({
            "index": idx,
            "start": part[0].start,
            "end": part[-1].end,
            "token_count": len(part),
            "first_token_kind": part[0].kind,
            "first_token": part[0].value if part[0].kind != "string" else "<string>",
            "function_keyword_count": function_count,
            "bit32_references": sum(1 for t in part if t.kind == "ident" and t.value == "bit32"),
            "while_true_loops": sum(1 for i in range(len(part)-2) if [x.value for x in part[i:i+3]] == ["while", "true", "do"]),
            "vm_cache_style_accesses": cache_count,
            "string_indices": string_indices,
            "preview": token_preview(part),
        })

    # Candidate string-only arrays (e.g. the runtime's method-name map). Preserve as evidence;
    # do not assume an index alignment with returned closures.
    name_tables = []
    for i, tok in enumerate(code):
        if tok.kind != "symbol" or tok.value != "{" or i not in matching:
            continue
        close = matching[i]
        direct_values: list[str] = []
        valid = True
        depth = 1
        for j in range(i + 1, close):
            t = code[j]
            if t.kind == "symbol" and t.value in {"(", "[", "{"}:
                depth += 1
                if depth == 1: pass
            elif t.kind == "symbol" and t.value in {")", "]", "}"}:
                depth -= 1
            elif depth == 1:
                if t.kind == "string":
                    direct_values.append(lua_unescape(t.value))
                elif t.kind == "symbol" and t.value == ",":
                    continue
                else:
                    valid = False
                    break
        if valid and len(direct_values) >= 8:
            name_tables.append({"start": tok.start, "end": code[close].end, "count": len(direct_values), "values": direct_values})
    name_tables.sort(key=lambda item: (-item["count"], item["start"]))
    # Prefer one whose values look like short symbolic method names, not arbitrary text arrays.
    likely_name_tables = [x for x in name_tables if all(0 < len(v) <= 8 for v in x["values"])]
    selected_names = likely_name_tables[0] if likely_name_tables else (name_tables[0] if name_tables else None)
    return {
        "returned_table_found": root_open is not None and root_end is not None,
        "returned_table_start": root_start,
        "returned_table_end": root_finish if root_open is not None and root_end is not None else None,
        "returned_table_element_count": len(root_summary),
        "returned_table_elements": root_summary,
        "string_array_candidates": name_tables[:10],
        "likely_runtime_name_table": selected_names,
        "name_alignment": "not inferred: the returned table contains mixed values/nested closures; position-by-position mapping would be speculative",
    }


def analyze(src: str, tokens: list[Token], strings: list[dict[str, Any]], filename: str, diagnostics: list[dict[str, Any]] | None = None, decodings: list[dict[str, Any]] | None = None, raw_bytes: bytes | None = None) -> dict[str, Any]:
    header = src[:300]
    version_match = re.search(r"MoonVeil\s+([\w.-]+)", header, re.I)
    visible = [t for t in tokens if t.kind != "comment"]
    vals = [t.value for t in visible]
    type_counts = Counter(t.kind for t in tokens)
    idents = Counter(t.value for t in visible if t.kind == "ident")
    symbols = Counter(t.value for t in visible if t.kind == "symbol")
    kw = Counter(t.value for t in visible if t.kind == "keyword")

    def sequence_count(seq: list[str]) -> int:
        return sum(vals[i:i+len(seq)] == seq for i in range(max(0, len(vals)-len(seq)+1)))

    def ident_ref(name: str) -> int:
        return sum(t.kind == "ident" and t.value == name for t in visible)

    function_literals = sum(1 for i, v in enumerate(vals[:-1]) if v == "function" and vals[i+1] == "(")
    function_keyword_count = sum(1 for v in vals if v == "function")
    vm_cache = sum(1 for i in range(len(visible)-3) if visible[i].kind == "ident" and visible[i+1].value == "." and visible[i+2].value == "U" and visible[i+3].value == "[")
    signals = {
        "anonymous_function_literals": function_literals,
        "function_keywords": function_keyword_count,
        "while_true_loops": sequence_count(["while", "true", "do"]),
        "repeat_blocks": sum(1 for v in vals if v == "repeat"),
        "bit32_references": ident_ref("bit32"),
        "getfenv_references": ident_ref("getfenv"),
        "setfenv_references": ident_ref("setfenv"),
        "loadstring_references": ident_ref("loadstring"),
        "load_references": ident_ref("load"),
        "debug_references": ident_ref("debug"),
        "require_references": ident_ref("require"),
        "vm_cache_style_accesses": vm_cache,
        "hex_literals": sum(1 for t in tokens if t.kind == "number" and re.match(r"0[xX]", t.value)),
        "binary_literals": sum(1 for t in tokens if t.kind == "number" and re.match(r"0[bB]", t.value)),
    }
    known_alphabet_strings = [s for s in strings if len(s["value"]) >= 70 and len(set(s["value"])) == len(s["value"]) and all(ch in CUSTOM_BASE85 for ch in s["value"]) and len(s["value"]) in range(80, 100)]
    vm_structure = inspect_vm_structure(tokens, strings)
    source_bytes = raw_bytes if raw_bytes is not None else src.encode("utf-8")
    candidates = sorted((s for s in strings if s["length"] >= 32), key=lambda s: (-s["length"], s["index"]))
    top_strings = sorted(strings, key=lambda s: (-s["length"], s["index"]))[:10]
    return {
        "tool": TOOL_NAME,
        "tool_version": VERSION,
        "input_file": filename,
        "offset_unit": "Unicode code points (0-based start, end-exclusive)",
        "input_characters": len(src),
        "input_bytes_utf8": len(source_bytes),
        "sha256": hashlib.sha256(source_bytes).hexdigest(),
        "header": src.splitlines()[0] if src.splitlines() else "",
        "detected_moonveil_version": version_match.group(1) if version_match else None,
        "token_count": len(tokens),
        "token_counts": dict(sorted(type_counts.items())),
        "keyword_frequency": dict(sorted(kw.items(), key=lambda kv: (-kv[1], kv[0]))[:30]),
        "top_identifiers": [{"name": k, "count": v} for k, v in sorted(idents.items(), key=lambda kv: (-kv[1], kv[0]))[:30]],
        "top_operators": [{"operator": k, "count": v} for k, v in sorted(symbols.items(), key=lambda kv: (-kv[1], kv[0]))[:30]],
        "string_literal_count": len(strings),
        "largest_string_literals": [{"index": s["index"], "length": s["length"], "entropy": s["entropy"], "printable_ratio": s["printable_ratio"], "preview": s["value"][:72]} for s in top_strings],
        "long_string_candidates": [{"index": s["index"], "length": s["length"], "entropy": s["entropy"], "start": s["start"], "end": s["end"], "preview": s["value"][:100]} for s in candidates[:20]],
        "custom_base85_alphabet_candidates": [{"index": s["index"], "length": s["length"], "value": s["value"]} for s in known_alphabet_strings],
        "signals": signals,
        "vm_structure": vm_structure,
        "decoder_candidates": [{k: d[k] for k in ("source_string_index", "encoding_candidate", "confidence", "decoded_bytes", "decoded_sha256", "entropy_bytes", "printable_ratio", "preview_kind", "preview")} for d in (decodings or [])],
        "lexical_diagnostics": diagnostics or [],
        "assessment": [
            "El análisis excluye cadenas y comentarios al contar referencias a funciones y patrones de VM, reduciendo falsos positivos.",
            "La salida normalizada conserva el orden de tokens; la indentación es heurística y no equivale a un AST.",
            "Las decodificaciones generadas son hipótesis estáticas. En particular, custom-base85 no confirma por sí sola el formato del bytecode.",
            "El patrón observado es compatible con un dispatcher/VM. Recuperar el fuente requeriría reconstruir la semántica de su cargador y sus opcodes.",
        ],
        "safety": "No se ejecutó el sample ni se evaluó código Lua; solo se analizaron sus bytes/texto y tokens."
    }


def _human_structure(value: Any, prefix: str = "") -> str:
    lines: list[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{key}:")
                lines.append(_human_structure(item, prefix + "  "))
            else:
                lines.append(f"{prefix}{key}: {item}")
    elif isinstance(value, list):
        for item in value:
            lines.append(f"{prefix}- {item}" if not isinstance(item, (dict, list)) else f"{prefix}-\n{_human_structure(item, prefix + '  ')}")
    else:
        lines.append(f"{prefix}{value}")
    return "\n".join(lines) + "\n"


AST_OUTPUTS = ("deobfuscated.lua", "unflattened.lua", "deobfuscation_report.md", "state_oracle_template.tsv")


def run_ast_passes(tokens: list[Token], outdir: Path, resolve_boxes: bool = True, oracle_path: Path | None = None) -> dict[str, Any]:
    """Parse, fold and unflatten. Writes AST outputs; never executes the input."""
    import moonveil_ast as ma

    for name in AST_OUTPUTS:
        stale = outdir / name
        if stale.exists():
            stale.unlink()
    try:
        chunk = ma.parse(tokens)
    except (ma.ParseError, RecursionError) as exc:
        (outdir / "deobfuscation_report.md").write_text(
            "# Informe de desofuscación AST\n\nEl parser no pudo construir el AST, por lo que solo se generaron las salidas a nivel de tokens.\n\n"
            f"- Error: `{exc}`\n", encoding="utf-8")
        return {"parsed": False, "error": str(exc)}
    oracle = ma.load_oracle(oracle_path.read_text(encoding="utf-8")) if oracle_path else {}
    folded, stats = ma.fold_chunk(chunk, resolve_boxes)
    printer = ma.Printer()
    (outdir / "deobfuscated.lua").write_text(
        "-- Desofuscado estático: AST reimpreso con constantes plegadas" + (" y boxes resueltos" if resolve_boxes else "") + ".\n" + printer.chunk(folded),
        encoding="utf-8")
    dispatchers = ma.find_dispatchers(folded, oracle)
    (outdir / "unflattened.lua").write_text(ma.render_unflattened(folded, dispatchers), encoding="utf-8")
    (outdir / "deobfuscation_report.md").write_text(ma.cff_report(dispatchers, printer, stats, len(oracle)), encoding="utf-8")
    template = ma.oracle_template(dispatchers)
    if template.count("\n") > 1:
        (outdir / "state_oracle_template.tsv").write_text(template, encoding="utf-8")
    return {
        "parsed": True,
        "folded": stats.folded_expressions,
        "boxes": stats.resolved_boxes,
        "box_constructions": stats.box_constructions,
        "pruned_branches": stats.pruned_branches,
        "dispatchers": len(dispatchers),
        "nodes": sum(len(d.nodes) for d in dispatchers),
        "opaque": sum(len(d.opaque) for d in dispatchers),
    }


def run(input_path: Path, outdir: Path, all_numbers: bool = False, binary_numbers: bool = True, include_tokens: bool = True,
        ast_passes: bool = True, resolve_boxes: bool = True, oracle_path: Path | None = None) -> dict[str, Any]:
    raw = input_path.read_bytes()
    src = raw.decode("utf-8", errors="replace")
    tokens, diagnostics = lex(src)
    strings = extract_strings(tokens)
    decodings = decode_candidates(strings)
    report = analyze(src, tokens, strings, input_path.name, diagnostics, decodings, raw)
    outdir.mkdir(parents=True, exist_ok=True)
    # Remove stale JSON artifacts from previous releases; this version emits no JSON.
    for stale in outdir.rglob("*"):
        if stale.is_file() and stale.suffix.lower() in {".json", ".jsonl"}:
            stale.unlink()
    (outdir / "normalized.lua").write_text(format_tokens(tokens, all_numbers, binary_numbers), encoding="utf-8")
    # Human-readable outputs only: the tool deliberately emits no JSON/JSONL files.
    report_lines = [f"# {TOOL_NAME} {VERSION}", "", f"- Entrada: `{filename if (filename := input_path.name) else input_path}`", f"- SHA-256: `{report['sha256']}`", f"- Versión MoonVeil detectada: `{report['detected_moonveil_version'] or 'no detectada'}`", f"- Caracteres: {report['input_characters']}", f"- Bytes UTF-8: {report['input_bytes_utf8']}", f"- Tokens: {report['token_count']}", f"- Cadenas: {report['string_literal_count']}", "", "## Señales estáticas", ""]
    for key, value in report["signals"].items(): report_lines.append(f"- {key}: {value}")
    report_lines += ["", "## Diagnósticos léxicos", ""]
    report_lines += [f"- {d['severity']} `{d['code']}` offset {d['offset']}: {d['message']}" for d in diagnostics] or ["- Sin diagnósticos léxicos."]
    report_lines += ["", "## Evaluación", ""] + [f"- {item}" for item in report["assessment"]] + ["", "No se ejecutó el código Lua.", ""]
    (outdir / "analysis_report.md").write_text("\n".join(report_lines), encoding="utf-8")
    (outdir / "vm_structure.txt").write_text(_human_structure(report["vm_structure"]), encoding="utf-8")
    string_lines = [line for s in strings for line in (f"CADENA #{s['index']} | longitud={s['length']} | entropía={s['entropy']} | offsets={s['start']}:{s['end']}", s["value"], "=" * 72)]
    (outdir / "extracted_strings.txt").write_text("\n".join(string_lines) + "\n", encoding="utf-8")
    decode_lines = [f"Cadena #{d['source_string_index']} | candidato={d['encoding_candidate']} | confianza={d['confidence']} | bytes={d['decoded_bytes']} | sha256={d['decoded_sha256']} | ratio imprimible={d['printable_ratio']}\nBase: {d['basis']}\nVista previa: {d['preview']}\n" for d in decodings]
    (outdir / "string_decodings.txt").write_text("\n".join(decode_lines) if decode_lines else "No se encontraron candidatos de decodificación.\n", encoding="utf-8")
    if include_tokens:
        token_lines = ["index\tkind\tstart\tend\tvalue"]
        for idx, tok in enumerate(tokens):
            val = tok.value.replace("\\", "\\\\").replace("\t", "\\t").replace("\r", "\\r").replace("\n", "\\n")
            token_lines.append(f"{idx}\t{tok.kind}\t{tok.start}\t{tok.end}\t{val}")
        (outdir / "tokens.tsv").write_text("\n".join(token_lines) + "\n", encoding="utf-8")
    decoded_dir = outdir / "decoded_candidates"
    written = set()
    for d in decodings:
        if d["encoding_candidate"] != "custom-base85":
            continue
        key = (d["source_string_index"], d["encoding_candidate"])
        if key in written: continue
        written.add(key)
        value = strings[d["source_string_index"]]["value"]
        payload = _base85_decode_custom(value)
        if payload is None: continue
        decoded_dir.mkdir(exist_ok=True)
        (decoded_dir / f"string_{d['source_string_index']:04d}_custom_base85.bin").write_bytes(payload)
        (decoded_dir / f"string_{d['source_string_index']:04d}_custom_base85.hex.txt").write_text(payload.hex(" ") + "\n", encoding="utf-8")
    candidates = [s for s in strings if s["length"] >= 32]
    if candidates:
        candidate = max(candidates, key=lambda s: s["length"])
        (outdir / "largest_string_candidate.txt").write_text(candidate["value"], encoding="utf-8")
    else:
        (outdir / "largest_string_candidate.txt").write_text("No string literal of 32 or more characters was found.\n", encoding="utf-8")
    # Human-readable triage notes, linked to source string indices and static offsets.
    notes = ["# Static triage notes", "", f"- Input: `{input_path.name}`", f"- SHA-256: `{report['sha256']}`", f"- Detected MoonVeil version: `{report['detected_moonveil_version'] or 'not detected'}`", f"- Tokens: `{len(tokens)}`; string literals: `{len(strings)}`", f"- Lexical diagnostics: `{len(diagnostics)}`", "", "## Largest string candidates", ""]
    if candidates:
        for s in sorted(candidates, key=lambda x: (-x["length"], x["index"]))[:10]:
            notes.append(f"- String #{s['index']} at offsets {s['start']}–{s['end']}: length {s['length']}, entropy {s['entropy']}; preview `{s['value'][:80].replace('`', '\\`')}`")
    else:
        notes.append("- None")
    notes += ["", "## Decoder candidates", ""]
    if decodings:
        for d in decodings:
            notes.append(f"- String #{d['source_string_index']}: `{d['encoding_candidate']}` ({d['confidence']}), {d['decoded_bytes']} bytes, SHA-256 `{d['decoded_sha256']}`; printable ratio {d['printable_ratio']}. {d['basis']}")
    else:
        notes.append("- No supported candidate encoding met the current thresholds.")
    notes += ["", "## Important limitation", "", "This report is static triage, not a recovered original source or a proven VM disassembly. No Lua runtime was invoked.", ""]
    (outdir / "triage_notes.md").write_text("\n".join(notes), encoding="utf-8")
    ast_summary = run_ast_passes(tokens, outdir, resolve_boxes, oracle_path) if ast_passes else None
    report["ast"] = ast_summary
    print(f"{TOOL_NAME} {VERSION}")
    print(f"Input: {input_path} ({len(src)} characters; {len(raw)} source bytes)")
    if ast_summary is not None:
        if ast_summary["parsed"]:
            print(f"AST: {ast_summary['folded']} constant folds | {ast_summary['boxes']} box rewrites | {ast_summary['dispatchers']} dispatchers | {ast_summary['nodes']} recovered blocks | {ast_summary['opaque']} opaque transitions")
        else:
            print(f"AST: parse failed ({ast_summary['error']}); token-level outputs only")
    print(f"Detected version: {report['detected_moonveil_version'] or 'not detected'}")
    print(f"Tokens: {len(tokens)} | strings: {len(strings)} | decoder candidates: {len(decodings)} | lexical diagnostics: {len(diagnostics)}")
    print(f"Output: {outdir.resolve()}")
    print("Static analysis only; the Lua input was not executed.")
    return report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Análisis estático y normalización Lua/MoonVeil, sin ejecutar el sample.")
    ap.add_argument("input", nargs="?", default="sample_obfuscated.lua", help="Archivo Lua/texto de entrada")
    ap.add_argument("-o", "--out-dir", default="moonveil_out", help="Directorio para los resultados")
    ap.add_argument("--normalize-all-numbers", action="store_true", help="Convierte también enteros hexadecimales a decimal")
    ap.add_argument("--preserve-binary-literals", action="store_true", help="No convierte 0b101 a decimal en normalized.lua")
    ap.add_argument("--no-token-dump", action="store_true", help="Omite tokens.tsv para ahorrar espacio")
    ap.add_argument("--strict", action="store_true", help="Devuelve error si el lexer encuentra literales/comentarios sin cerrar")
    ap.add_argument("--no-ast", action="store_true", help="Omite el parser AST (deobfuscated.lua, unflattened.lua y su informe)")
    ap.add_argument("--no-resolve-boxes", action="store_true", help="No reescribe B[1][B[3]] como B[2]")
    ap.add_argument("--state-oracle", metavar="TSV", help="Valores conocidos de la caché de estados U[k] (clave<TAB>valor)")
    args = ap.parse_args(argv)
    input_path = Path(args.input)
    if not input_path.is_file():
        print(f"Error: no existe el archivo de entrada: {input_path}", file=sys.stderr)
        return 2
    oracle_path = Path(args.state_oracle) if args.state_oracle else None
    if oracle_path is not None and not oracle_path.is_file():
        print(f"Error: no existe el oráculo de estados: {oracle_path}", file=sys.stderr)
        return 2
    try:
        report = run(input_path, Path(args.out_dir), args.normalize_all_numbers, not args.preserve_binary_literals, not args.no_token_dump,
                     not args.no_ast, not args.no_resolve_boxes, oracle_path)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if args.strict and report["lexical_diagnostics"]:
        return 3
    return 0

if __name__ == "__main__":
    raise SystemExit(main())

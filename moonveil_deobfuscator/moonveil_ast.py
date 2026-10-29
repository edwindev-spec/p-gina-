"""Lua/Luau AST engine for the MoonVeil static deobfuscator.

Provides a parser, a precedence-aware pretty printer, constant folding,
box-indirection resolution and static control-flow-flattening recovery.
Nothing here executes the analysed program; evaluation is restricted to
literal constants.

Numeric semantics follow Luau (every number is an IEEE-754 double), the
runtime MoonVeil targets.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

# ---------------------------------------------------------------------------
# AST
# ---------------------------------------------------------------------------


class Node:
    __slots__ = ("kind", "f")

    def __init__(self, kind: str, **fields: Any) -> None:
        self.kind = kind
        self.f = fields

    def __getattr__(self, name: str) -> Any:
        try:
            return self.f[name]
        except KeyError as exc:
            raise AttributeError(name) from exc

    def __repr__(self) -> str:
        return f"Node({self.kind}, {self.f})"

    def copy(self, **changes: Any) -> "Node":
        data = dict(self.f)
        data.update(changes)
        return Node(self.kind, **data)


def N(kind: str, **fields: Any) -> Node:
    return Node(kind, **fields)


class ParseError(Exception):
    def __init__(self, message: str, offset: int) -> None:
        super().__init__(f"{message} (offset {offset})")
        self.offset = offset


# ---------------------------------------------------------------------------
# Literals
# ---------------------------------------------------------------------------

LONG_OPEN = re.compile(r"\[(=*)\[")


def lua_string_bytes(literal: str) -> bytes:
    """Decode a Lua string literal into the exact byte string Lua would build."""
    if len(literal) >= 2 and literal[0] == "`" and literal[-1] == "`":
        return literal[1:-1].encode("utf-8")
    m = LONG_OPEN.match(literal)
    if m:
        close = "]" + m.group(1) + "]"
        body = literal[m.end():]
        if body.endswith(close):
            body = body[: -len(close)]
        if body.startswith("\r\n"):
            body = body[2:]
        elif body[:1] in ("\n", "\r"):
            body = body[1:]
        return body.encode("utf-8")
    if len(literal) < 2 or literal[0] not in "'\"" or literal[-1] != literal[0]:
        return literal.encode("utf-8")
    body = literal[1:-1]
    out = bytearray()
    simple = {"a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11, "\\": 92, '"': 34, "'": 39, "\n": 10}
    i, n = 0, len(body)
    while i < n:
        c = body[i]
        if c != "\\" or i + 1 >= n:
            out += c.encode("utf-8")
            i += 1
            continue
        i += 1
        c = body[i]
        if c in simple:
            out.append(simple[c]); i += 1
        elif c == "z":
            i += 1
            while i < n and body[i].isspace():
                i += 1
        elif c == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", body[i + 1:i + 3]):
            out.append(int(body[i + 1:i + 3], 16)); i += 3
        elif c == "u" and i + 1 < n and body[i + 1] == "{":
            close_at = body.find("}", i + 2)
            raw = body[i + 2:close_at] if close_at >= 0 else ""
            if close_at >= 0 and re.fullmatch(r"[0-9a-fA-F]+", raw) and int(raw, 16) <= 0x10FFFF:
                out += chr(int(raw, 16)).encode("utf-8", "surrogatepass"); i = close_at + 1
            else:
                out += b"u"; i += 1
        elif c.isdigit():
            j = i
            while j < min(n, i + 3) and body[j].isdigit():
                j += 1
            out.append(int(body[i:j]) % 256); i = j
        elif c == "\r":
            i += 1
            if i < n and body[i] == "\n":
                i += 1
            out.append(10)
        else:
            out += c.encode("utf-8"); i += 1
    return bytes(out)


def parse_number(text: str) -> float:
    low = text.lower().replace("_", "")
    if low.startswith("0b"):
        return float(int(low[2:], 2))
    if low.startswith("0x"):
        if "." in low or "p" in low:
            return float.fromhex(low if "p" in low else low + "p0")
        return float(int(low, 16))
    return float(low)


def format_number(value: float) -> str:
    if math.isnan(value):
        return "(0/0)"
    if math.isinf(value):
        return "math.huge" if value > 0 else "-math.huge"
    if value.is_integer() and abs(value) < 2 ** 53:
        return "-0" if value == 0 and math.copysign(1, value) < 0 else str(int(value))
    return repr(value)


_ESCAPES = {9: "\\t", 10: "\\n", 13: "\\r", 34: '\\"', 92: "\\\\"}


def format_string(data: bytes) -> str:
    """Render bytes as a readable, round-trippable Lua double-quoted string."""
    out = ['"']
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is not None:
        for ch in text:
            code = ord(ch)
            if code in _ESCAPES:
                out.append(_ESCAPES[code])
            elif code < 32 or code == 127:
                out.append(f"\\{code:03d}")
            else:
                out.append(ch)
    else:
        for b in data:
            if b in _ESCAPES:
                out.append(_ESCAPES[b])
            elif 32 <= b <= 126:
                out.append(chr(b))
            else:
                out.append(f"\\{b:03d}")
    out.append('"')
    return "".join(out)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

BINARY_PRIORITY = {
    "or": (1, 1), "and": (2, 2),
    "<": (3, 3), ">": (3, 3), "<=": (3, 3), ">=": (3, 3), "~=": (3, 3), "==": (3, 3),
    "|": (4, 4), "~": (5, 5), "&": (6, 6), "<<": (7, 7), ">>": (7, 7),
    "..": (9, 8), "+": (10, 10), "-": (10, 10),
    "*": (11, 11), "/": (11, 11), "//": (11, 11), "%": (11, 11),
    "^": (14, 13),
}
UNARY_PRIORITY = 12
COMPOUND_OPS = {"+=": "+", "-=": "-", "*=": "*", "/=": "/", "//=": "//", "%=": "%", "^=": "^", "..=": ".."}
BLOCK_END = {"end", "else", "elseif", "until"}


class Parser:
    def __init__(self, tokens: list[Any]) -> None:
        self.toks = [t for t in tokens if t.kind != "comment"]
        self.i = 0

    def peek(self, k: int = 0) -> Any:
        j = self.i + k
        return self.toks[j] if j < len(self.toks) else None

    def at(self, value: str, k: int = 0) -> bool:
        t = self.peek(k)
        return t is not None and t.kind in ("symbol", "keyword") and t.value == value

    def offset(self) -> int:
        t = self.peek()
        return t.start if t else (self.toks[-1].end if self.toks else 0)

    def next(self) -> Any:
        t = self.peek()
        if t is None:
            raise ParseError("fin de entrada inesperado", self.offset())
        self.i += 1
        return t

    def expect(self, value: str) -> Any:
        if not self.at(value):
            t = self.peek()
            raise ParseError(f"se esperaba '{value}' y se encontró '{t.value if t else 'EOF'}'", self.offset())
        return self.next()

    def accept(self, value: str) -> bool:
        if self.at(value):
            self.i += 1
            return True
        return False

    def name(self) -> str:
        t = self.peek()
        if t is not None and (t.kind == "ident" or (t.kind == "keyword" and t.value == "continue")):
            self.i += 1
            return t.value
        raise ParseError(f"se esperaba un nombre y se encontró '{t.value if t else 'EOF'}'", self.offset())

    def parse_chunk(self) -> Node:
        body = self.block()
        if self.peek() is not None:
            raise ParseError(f"token inesperado '{self.peek().value}'", self.offset())
        return N("Chunk", body=body)

    def block(self) -> list[Node]:
        stmts: list[Node] = []
        while True:
            t = self.peek()
            if t is None or (t.kind == "keyword" and t.value in BLOCK_END):
                return stmts
            if t.kind == "keyword" and t.value == "return":
                self.next()
                values: list[Node] = []
                nt = self.peek()
                if not (nt is None or self.at(";") or (nt.kind == "keyword" and nt.value in BLOCK_END)):
                    values = self.exprlist()
                self.accept(";")
                stmts.append(N("Return", values=values))
                return stmts
            stmt = self.statement()
            if stmt is not None:
                stmts.append(stmt)

    def _continue_is_statement(self) -> bool:
        nxt = self.peek(1)
        if nxt is None or nxt.kind in ("keyword", "ident", "number"):
            return True
        if nxt.kind == "string":
            return False
        return not (nxt.value in {"=", "(", ".", "[", ",", ":", "{"} or nxt.value in COMPOUND_OPS)

    def statement(self) -> Node | None:
        t = self.peek()
        if self.accept(";"):
            return None
        if self.at("::"):
            self.next(); label = self.name(); self.expect("::")
            return N("Label", name=label)
        if t.kind == "keyword":
            v = t.value
            if v == "break":
                self.next(); return N("Break")
            if v == "continue" and self._continue_is_statement():
                self.next(); return N("Continue")
            if v == "do":
                self.next(); body = self.block(); self.expect("end")
                return N("Do", body=body)
            if v == "while":
                self.next(); cond = self.expr(); self.expect("do"); body = self.block(); self.expect("end")
                return N("While", cond=cond, body=body)
            if v == "repeat":
                self.next(); body = self.block(); self.expect("until")
                return N("Repeat", body=body, cond=self.expr())
            if v == "if":
                self.next()
                clauses = []
                cond = self.expr(); self.expect("then"); clauses.append((cond, self.block()))
                orelse = None
                while True:
                    if self.accept("elseif"):
                        cond = self.expr(); self.expect("then"); clauses.append((cond, self.block()))
                    elif self.accept("else"):
                        orelse = self.block(); self.expect("end"); break
                    else:
                        self.expect("end"); break
                return N("If", clauses=clauses, orelse=orelse)
            if v == "for":
                self.next()
                first = self.name()
                if self.accept("="):
                    start = self.expr(); self.expect(","); stop = self.expr()
                    step = self.expr() if self.accept(",") else None
                    self.expect("do"); body = self.block(); self.expect("end")
                    return N("NumFor", var=first, start=start, stop=stop, step=step, body=body)
                names = [first]
                while self.accept(","):
                    names.append(self.name())
                self.expect("in"); iters = self.exprlist(); self.expect("do"); body = self.block(); self.expect("end")
                return N("GenFor", names=names, iters=iters, body=body)
            if v == "function":
                self.next()
                target: Node = N("Name", name=self.name())
                is_method = False
                while self.at(".") or self.at(":"):
                    sep = self.next().value
                    target = N("Index", obj=target, key=N("Str", value=self.name().encode()))
                    if sep == ":":
                        is_method = True
                        break
                return N("Assign", targets=[target], values=[self.funcbody(is_method)], func_decl=True)
            if v == "local":
                self.next()
                if self.accept("function"):
                    nm = self.name()
                    return N("LocalFunction", name=nm, func=self.funcbody(False))
                names, attribs = [], []
                while True:
                    names.append(self.name())
                    attrib = None
                    if self.at("<"):
                        self.next(); attrib = self.name(); self.expect(">")
                    attribs.append(attrib)
                    if not self.accept(","):
                        break
                values = self.exprlist() if self.accept("=") else []
                return N("Local", names=names, attribs=attribs, values=values)
        if t.kind == "ident" and t.value == "goto":
            nxt = self.peek(1)
            if nxt is not None and nxt.kind == "ident":
                self.next(); return N("Goto", name=self.name())
        start = self.offset()
        expr = self.suffixedexp()
        if self.at("=") or self.at(","):
            targets = [expr]
            while self.accept(","):
                targets.append(self.suffixedexp())
            self.expect("=")
            if any(tg.kind not in ("Name", "Index") for tg in targets):
                raise ParseError("destino de asignación no válido", start)
            return N("Assign", targets=targets, values=self.exprlist())
        nt = self.peek()
        if nt is not None and nt.kind == "symbol" and nt.value in COMPOUND_OPS:
            self.next()
            return N("Compound", op=COMPOUND_OPS[nt.value], target=expr, value=self.expr())
        if expr.kind not in ("Call", "Invoke"):
            raise ParseError("se esperaba una llamada o una asignación", start)
        return N("CallStat", call=expr)

    def funcbody(self, is_method: bool) -> Node:
        self.expect("(")
        params: list[str] = ["self"] if is_method else []
        vararg = False
        if not self.at(")"):
            while True:
                if self.accept("..."):
                    vararg = True
                    break
                params.append(self.name())
                if not self.accept(","):
                    break
        self.expect(")")
        body = self.block()
        self.expect("end")
        return N("Function", params=params, vararg=vararg, body=body, is_method=is_method)

    def exprlist(self) -> list[Node]:
        exprs = [self.expr()]
        while self.accept(","):
            exprs.append(self.expr())
        return exprs

    def expr(self, limit: int = 0) -> Node:
        t = self.peek()
        if t is None:
            raise ParseError("se esperaba una expresión", self.offset())
        if (t.kind == "keyword" and t.value == "not") or (t.kind == "symbol" and t.value in ("-", "#", "~")):
            self.next()
            left = N("Unop", op=t.value, operand=self.expr(UNARY_PRIORITY))
        else:
            left = self.simpleexp()
        while True:
            t = self.peek()
            if t is None or t.kind not in ("symbol", "keyword") or t.value not in BINARY_PRIORITY:
                return left
            lp, rp = BINARY_PRIORITY[t.value]
            if lp <= limit:
                return left
            self.next()
            left = N("Binop", op=t.value, left=left, right=self.expr(rp))

    def simpleexp(self) -> Node:
        t = self.peek()
        if t.kind == "number":
            self.next(); return N("Num", value=parse_number(t.value))
        if t.kind == "string":
            self.next(); return N("Str", value=lua_string_bytes(t.value))
        if t.kind == "keyword":
            if t.value == "nil":
                self.next(); return N("Nil")
            if t.value in ("true", "false"):
                self.next(); return N("Bool", value=t.value == "true")
            if t.value == "function":
                self.next(); return self.funcbody(False)
            if t.value == "if":
                self.next()
                branches = []
                cond = self.expr(); self.expect("then"); branches.append((cond, self.expr()))
                while self.accept("elseif"):
                    cond = self.expr(); self.expect("then"); branches.append((cond, self.expr()))
                self.expect("else")
                return N("IfExpr", branches=branches, orelse=self.expr())
        if t.kind == "symbol":
            if t.value == "...":
                self.next(); return N("Vararg")
            if t.value == "{":
                return self.table()
        return self.suffixedexp()

    def primaryexp(self) -> Node:
        if self.accept("("):
            inner = self.expr()
            self.expect(")")
            return N("Paren", expr=inner)
        return N("Name", name=self.name())

    def suffixedexp(self) -> Node:
        e = self.primaryexp()
        while True:
            t = self.peek()
            if t is None:
                return e
            if self.at("."):
                self.next(); e = N("Index", obj=e, key=N("Str", value=self.name().encode()))
            elif self.at("["):
                self.next(); key = self.expr(); self.expect("]"); e = N("Index", obj=e, key=key)
            elif self.at(":"):
                self.next(); method = self.name(); e = N("Invoke", obj=e, method=method, args=self.callargs())
            elif self.at("(") or self.at("{") or t.kind == "string":
                e = N("Call", func=e, args=self.callargs())
            else:
                return e

    def callargs(self) -> list[Node]:
        t = self.peek()
        if t is not None and t.kind == "string":
            self.next(); return [N("Str", value=lua_string_bytes(t.value))]
        if self.at("{"):
            return [self.table()]
        self.expect("(")
        if self.accept(")"):
            return []
        args = self.exprlist()
        self.expect(")")
        return args

    def table(self) -> Node:
        self.expect("{")
        items: list[tuple[str, Node | None, Node]] = []
        while not self.at("}"):
            if self.at("["):
                self.next(); key = self.expr(); self.expect("]"); self.expect("=")
                items.append(("keyed", key, self.expr()))
            elif self.peek().kind == "ident" and self.at("=", 1):
                key = self.name(); self.next()
                items.append(("named", N("Str", value=key.encode()), self.expr()))
            else:
                items.append(("pos", None, self.expr()))
            if not (self.accept(",") or self.accept(";")):
                break
        self.expect("}")
        return N("Table", items=items)


def parse(tokens: list[Any]) -> Node:
    return Parser(tokens).parse_chunk()


# ---------------------------------------------------------------------------
# Printer
# ---------------------------------------------------------------------------

IDENT_OK = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
LUA_KEYWORDS = {"and", "break", "do", "else", "elseif", "end", "false", "for", "function", "goto", "if", "in", "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while"}
ATOM = 100


def _str_ident(node: Node) -> str | None:
    if node.kind != "Str":
        return None
    try:
        text = node.value.decode("ascii")
    except UnicodeDecodeError:
        return None
    return text if IDENT_OK.match(text) and text not in LUA_KEYWORDS else None


def _is_negative_num(e: Node) -> bool:
    return e.kind == "Num" and (e.value < 0 or (e.value == 0 and math.copysign(1, e.value) < 0))


def _priority(e: Node) -> int:
    if e.kind == "Binop":
        return BINARY_PRIORITY[e.op][0]
    if e.kind == "Unop" or _is_negative_num(e):
        return UNARY_PRIORITY
    return ATOM


class Printer:
    def __init__(self, indent: str = "    ") -> None:
        self.indent = indent

    def expr(self, e: Node, depth: int = 0) -> str:
        k = e.kind
        if k == "Num":
            return format_number(e.value)
        if k == "Str":
            return format_string(e.value)
        if k == "Nil":
            return "nil"
        if k == "Bool":
            return "true" if e.value else "false"
        if k == "Vararg":
            return "..."
        if k == "Name":
            return e.name
        if k == "Paren":
            return "(" + self.expr(e.expr, depth) + ")"
        if k == "Index":
            ident = _str_ident(e.key)
            base = self.prefix(e.obj, depth)
            return f"{base}.{ident}" if ident else f"{base}[{self.expr(e.key, depth)}]"
        if k == "Call":
            return self.prefix(e.func, depth) + self.args(e.args, depth)
        if k == "Invoke":
            return f"{self.prefix(e.obj, depth)}:{e.method}{self.args(e.args, depth)}"
        if k == "Function":
            return self.function("function", e, depth)
        if k == "Table":
            return self.table(e, depth)
        if k == "Unop":
            operand = e.operand
            inner = self.expr(operand, depth)
            if operand.kind == "Binop" and _priority(operand) <= UNARY_PRIORITY:
                inner = "(" + inner + ")"
            if e.op == "not":
                return "not " + inner
            sep = " " if e.op in ("-", "~") and inner.startswith(("-", "~")) else ""
            return e.op + sep + inner
        if k == "Binop":
            lp, rp = BINARY_PRIORITY[e.op]
            left = self.expr(e.left, depth)
            lprio = _priority(e.left)
            if lprio < lp or (lprio == lp and lp != rp):
                left = "(" + left + ")"
            right = self.expr(e.right, depth)
            rprio = _priority(e.right)
            if rprio != UNARY_PRIORITY and rprio <= rp:
                right = "(" + right + ")"
            return f"{left} {e.op} {right}"
        if k == "IfExpr":
            parts = [("if " if i == 0 else " elseif ") + self.expr(c, depth) + " then " + self.expr(v, depth) for i, (c, v) in enumerate(e.branches)]
            return "(" + "".join(parts) + " else " + self.expr(e.orelse, depth) + ")"
        raise ValueError(f"expresión desconocida: {k}")

    def prefix(self, e: Node, depth: int) -> str:
        if e.kind in ("Name", "Index", "Call", "Invoke", "Paren"):
            return self.expr(e, depth)
        return "(" + self.expr(e, depth) + ")"

    def args(self, args: list[Node], depth: int) -> str:
        return "(" + ", ".join(self.expr(a, depth) for a in args) + ")"

    def table(self, e: Node, depth: int) -> str:
        if not e.items:
            return "{}"
        parts = []
        for kind, key, value in e.items:
            if kind == "pos":
                parts.append(self.expr(value, depth + 1))
            else:
                ident = _str_ident(key)
                lhs = ident if ident else "[" + self.expr(key, depth + 1) + "]"
                parts.append(f"{lhs} = {self.expr(value, depth + 1)}")
        one_line = "{" + ", ".join(parts) + "}"
        if len(one_line) <= 100 and "\n" not in one_line:
            return one_line
        pad = self.indent * (depth + 1)
        return "{\n" + ",\n".join(pad + p for p in parts) + "\n" + self.indent * depth + "}"

    def function(self, head: str, fn: Node, depth: int) -> str:
        params = list(fn.params[1:] if fn.is_method else fn.params)
        if fn.vararg:
            params.append("...")
        lines = [f"{head}({', '.join(params)})"]
        lines.extend(self.block(fn.body, depth + 1))
        lines.append(self.indent * depth + "end")
        return "\n".join(lines)

    def block(self, stmts: list[Node], depth: int) -> list[str]:
        out: list[str] = []
        for s in stmts:
            out.extend(self.stmt(s, depth))
        return out

    def stmt(self, s: Node, depth: int) -> list[str]:
        pad = self.indent * depth
        k = s.kind
        if k == "Local":
            names = ", ".join(n + (f" <{a}>" if a else "") for n, a in zip(s.names, s.attribs))
            text = f"local {names}"
            if s.values:
                text += " = " + ", ".join(self.expr(v, depth) for v in s.values)
            return [pad + text]
        if k == "LocalFunction":
            return [pad + self.function(f"local function {s.name}", s.func, depth)]
        if k == "Assign":
            if s.f.get("func_decl") and len(s.targets) == 1 and s.values[0].kind == "Function":
                fn, target = s.values[0], s.targets[0]
                if fn.is_method and target.kind == "Index" and _str_ident(target.key):
                    head = f"function {self.expr(target.obj, depth)}:{_str_ident(target.key)}"
                else:
                    head = f"function {self.expr(target, depth)}"
                return [pad + self.function(head, fn, depth)]
            lhs = ", ".join(self.expr(t, depth) for t in s.targets)
            rhs = ", ".join(self.expr(v, depth) for v in s.values)
            return [f"{pad}{lhs} = {rhs}"]
        if k == "Compound":
            return [f"{pad}{self.expr(s.target, depth)} {s.op}= {self.expr(s.value, depth)}"]
        if k == "CallStat":
            text = self.expr(s.call, depth)
            return [pad + (";" + text if text.startswith("(") else text)]
        if k == "Do":
            return [pad + "do", *self.block(s.body, depth + 1), pad + "end"]
        if k == "While":
            return [f"{pad}while {self.expr(s.cond, depth)} do", *self.block(s.body, depth + 1), pad + "end"]
        if k == "Repeat":
            return [pad + "repeat", *self.block(s.body, depth + 1), f"{pad}until {self.expr(s.cond, depth)}"]
        if k == "If":
            lines = []
            for idx, (cond, body) in enumerate(s.clauses):
                lines.append(f"{pad}{'if' if idx == 0 else 'elseif'} {self.expr(cond, depth)} then")
                lines.extend(self.block(body, depth + 1))
            if s.orelse is not None:
                lines.append(pad + "else")
                lines.extend(self.block(s.orelse, depth + 1))
            lines.append(pad + "end")
            return lines
        if k == "NumFor":
            rng = f"{self.expr(s.start, depth)}, {self.expr(s.stop, depth)}"
            if s.step is not None:
                rng += f", {self.expr(s.step, depth)}"
            return [f"{pad}for {s.var} = {rng} do", *self.block(s.body, depth + 1), pad + "end"]
        if k == "GenFor":
            iters = ", ".join(self.expr(e, depth) for e in s.iters)
            return [f"{pad}for {', '.join(s.names)} in {iters} do", *self.block(s.body, depth + 1), pad + "end"]
        if k == "Return":
            return [pad + ("return " + ", ".join(self.expr(v, depth) for v in s.values) if s.values else "return")]
        if k == "Break":
            return [pad + "break"]
        if k == "Continue":
            return [pad + "continue"]
        if k == "Goto":
            return [f"{pad}goto {s.name}"]
        if k == "Label":
            return [f"{pad}::{s.name}::"]
        if k == "Comment":
            return [pad + "-- " + line for line in (s.text.splitlines() or [""])]
        raise ValueError(f"sentencia desconocida: {k}")

    def chunk(self, chunk: Node) -> str:
        return "\n".join(self.block(chunk.body, 0)) + "\n"


# ---------------------------------------------------------------------------
# Traversal helpers
# ---------------------------------------------------------------------------


def child_exprs(e: Node) -> Iterator[Node]:
    k = e.kind
    if k == "Paren":
        yield e.expr
    elif k == "Index":
        yield e.obj; yield e.key
    elif k == "Call":
        yield e.func; yield from e.args
    elif k == "Invoke":
        yield e.obj; yield from e.args
    elif k == "Unop":
        yield e.operand
    elif k == "Binop":
        yield e.left; yield e.right
    elif k == "Table":
        for _, key, value in e.items:
            if key is not None:
                yield key
            yield value
    elif k == "IfExpr":
        for c, v in e.branches:
            yield c; yield v
        yield e.orelse


def walk_expr(e: Node) -> Iterator[Node]:
    """Pre-order walk that does not descend into nested function bodies."""
    yield e
    if e.kind == "Function":
        return
    for c in child_exprs(e):
        yield from walk_expr(c)


def stmt_exprs(s: Node) -> list[Node]:
    k = s.kind
    if k == "Local":
        return list(s.values)
    if k == "LocalFunction":
        return [s.func]
    if k == "Assign":
        return list(s.targets) + list(s.values)
    if k == "Compound":
        return [s.target, s.value]
    if k == "CallStat":
        return [s.call]
    if k in ("While", "Repeat"):
        return [s.cond]
    if k == "If":
        return [c for c, _ in s.clauses]
    if k == "NumFor":
        return [x for x in (s.start, s.stop, s.step) if x is not None]
    if k == "GenFor":
        return list(s.iters)
    if k == "Return":
        return list(s.values)
    return []


def stmt_blocks(s: Node) -> list[list[Node]]:
    k = s.kind
    if k in ("Do", "While", "Repeat", "NumFor", "GenFor"):
        return [s.body]
    if k == "If":
        return [b for _, b in s.clauses] + ([s.orelse] if s.orelse is not None else [])
    return []


def map_expr(e: Node, fn: Callable[[Node], Node | None]) -> Node:
    """Bottom-up rewrite of an expression tree (not entering function bodies)."""
    replaced = fn(e)
    if replaced is not None:
        return replaced
    k = e.kind
    if k == "Paren":
        return e.copy(expr=map_expr(e.expr, fn))
    if k == "Index":
        return e.copy(obj=map_expr(e.obj, fn), key=map_expr(e.key, fn))
    if k == "Call":
        return e.copy(func=map_expr(e.func, fn), args=[map_expr(a, fn) for a in e.args])
    if k == "Invoke":
        return e.copy(obj=map_expr(e.obj, fn), args=[map_expr(a, fn) for a in e.args])
    if k == "Unop":
        return e.copy(operand=map_expr(e.operand, fn))
    if k == "Binop":
        return e.copy(left=map_expr(e.left, fn), right=map_expr(e.right, fn))
    if k == "Table":
        return e.copy(items=[(kind, map_expr(key, fn) if key is not None else None, map_expr(v, fn)) for kind, key, v in e.items])
    if k == "IfExpr":
        return e.copy(branches=[(map_expr(c, fn), map_expr(v, fn)) for c, v in e.branches], orelse=map_expr(e.orelse, fn))
    return e


def map_stmt(s: Node, fn: Callable[[Node], Node | None]) -> Node:
    """Apply map_expr to every expression of a statement, recursing into nested blocks."""
    k = s.kind
    m = lambda e: map_expr(e, fn)  # noqa: E731
    blk = lambda b: [map_stmt(x, fn) for x in b]  # noqa: E731
    if k == "Local":
        return s.copy(values=[m(v) for v in s.values])
    if k == "Assign":
        return s.copy(targets=[t if t.kind == "Name" else m(t) for t in s.targets], values=[m(v) for v in s.values])
    if k == "Compound":
        return s.copy(target=s.target if s.target.kind == "Name" else m(s.target), value=m(s.value))
    if k == "CallStat":
        return s.copy(call=m(s.call))
    if k == "Do":
        return s.copy(body=blk(s.body))
    if k == "While":
        return s.copy(cond=m(s.cond), body=blk(s.body))
    if k == "Repeat":
        return s.copy(body=blk(s.body), cond=m(s.cond))
    if k == "If":
        return s.copy(clauses=[(m(c), blk(b)) for c, b in s.clauses], orelse=blk(s.orelse) if s.orelse is not None else None)
    if k == "NumFor":
        return s.copy(start=m(s.start), stop=m(s.stop), step=m(s.step) if s.step is not None else None, body=blk(s.body))
    if k == "GenFor":
        return s.copy(iters=[m(e) for e in s.iters], body=blk(s.body))
    if k == "Return":
        return s.copy(values=[m(v) for v in s.values])
    return s


def iter_functions(chunk: Node) -> Iterator[Node]:
    """Yield the chunk and every nested Function node in pre-order."""
    yield chunk

    def from_expr(e: Node) -> Iterator[Node]:
        if e.kind == "Function":
            yield e
            yield from from_block(e.body)
            return
        for c in child_exprs(e):
            yield from from_expr(c)

    def from_block(stmts: list[Node]) -> Iterator[Node]:
        for s in stmts:
            for e in stmt_exprs(s):
                yield from from_expr(e)
            for b in stmt_blocks(s):
                yield from from_block(b)

    yield from from_block(chunk.body)


def expr_equal(a: Node, b: Node) -> bool:
    if a.kind != b.kind:
        return False
    if a.kind == "Name":
        return a.name == b.name
    if a.kind in ("Num", "Str", "Bool"):
        return a.value == b.value
    if a.kind == "Nil":
        return True
    if a.kind == "Index":
        return expr_equal(a.obj, b.obj) and expr_equal(a.key, b.key)
    return False


def is_pure_path(e: Node) -> bool:
    """A name or chain of constant-key indexes; re-reading it has no extra side effect."""
    if e.kind == "Name":
        return True
    if e.kind == "Index":
        return e.key.kind in ("Num", "Str") and is_pure_path(e.obj)
    return False


# ---------------------------------------------------------------------------
# Constant folding (Luau double semantics)
# ---------------------------------------------------------------------------


@dataclass
class Stats:
    folded_expressions: int = 0
    pruned_branches: int = 0
    removed_dead_loops: int = 0
    resolved_boxes: int = 0
    box_constructions: int = 0
    redundant_parens: int = 0


def _is_const(e: Node) -> bool:
    return e.kind in ("Num", "Str", "Bool", "Nil")


def _truthy(e: Node) -> bool:
    return not (e.kind == "Nil" or (e.kind == "Bool" and not e.value))


def _num(value: float) -> Node:
    return N("Num", value=float(value))


def _lua_tostring_number(value: float) -> bytes | None:
    if math.isnan(value) or math.isinf(value):
        return None
    if value.is_integer() and abs(value) < 2 ** 53:
        return str(int(value)).encode()
    text = f"{value:.14g}"
    return text.encode() if float(text) == value else None


def fold_binop(op: str, a: Node, b: Node) -> Node | None:
    if a.kind == "Num" and b.kind == "Num":
        x, y = a.value, b.value
        try:
            if op == "+": return _num(x + y)
            if op == "-": return _num(x - y)
            if op == "*": return _num(x * y)
            if op == "/": return _num(x / y) if y != 0 else None
            if op == "//": return _num(math.floor(x / y)) if y != 0 else None
            if op == "%": return _num(x - math.floor(x / y) * y) if y != 0 else None
            if op == "^":
                r = math.pow(x, y)
                return None if math.isnan(r) else _num(r)
        except (OverflowError, ValueError, ZeroDivisionError):
            return None
        if op in ("==", "~=", "<", "<=", ">", ">="):
            return N("Bool", value=_compare(op, x, y))
    if a.kind == "Str" and b.kind == "Str":
        if op == "..": return N("Str", value=a.value + b.value)
        if op in ("==", "~=", "<", "<=", ">", ">="):
            return N("Bool", value=_compare(op, a.value, b.value))
    if op == ".." and a.kind in ("Num", "Str") and b.kind in ("Num", "Str"):
        left = a.value if a.kind == "Str" else _lua_tostring_number(a.value)
        right = b.value if b.kind == "Str" else _lua_tostring_number(b.value)
        if left is not None and right is not None:
            return N("Str", value=left + right)
    if op in ("==", "~=") and _is_const(a) and _is_const(b):
        if a.kind != b.kind:
            return N("Bool", value=op == "~=")
        if a.kind in ("Nil", "Bool"):
            same = a.kind == "Nil" or a.value == b.value
            return N("Bool", value=same if op == "==" else not same)
    return None


def _compare(op: str, x: Any, y: Any) -> bool:
    if op == "<": return x < y
    if op == "<=": return x <= y
    if op == ">": return x > y
    if op == ">=": return x >= y
    if op == "==": return x == y
    return x != y


class Folder:
    def __init__(self, stats: Stats | None = None, resolve_boxes: bool = True) -> None:
        self.stats = stats or Stats()
        self.resolve_boxes = resolve_boxes

    def expr(self, e: Node) -> Node:
        k = e.kind
        st = self.stats
        if k == "Function":
            return e.copy(body=self.block(e.body))
        if k == "Paren":
            inner = self.expr(e.expr)
            # Parentheses only matter for truncating multiple results.
            if inner.kind in ("Call", "Invoke", "Vararg"):
                return e.copy(expr=inner)
            st.redundant_parens += 1
            return inner
        if k == "Index":
            node = e.copy(obj=self.expr(e.obj), key=self.expr(e.key))
            if self.resolve_boxes:
                resolved = self.box(node)
                if resolved is not None:
                    st.resolved_boxes += 1
                    return resolved
            return node
        if k == "Call":
            return e.copy(func=self.expr(e.func), args=[self.expr(a) for a in e.args])
        if k == "Invoke":
            return e.copy(obj=self.expr(e.obj), args=[self.expr(a) for a in e.args])
        if k == "Table":
            return e.copy(items=[(kind, self.expr(key) if key is not None else None, self.expr(v)) for kind, key, v in e.items])
        if k == "IfExpr":
            branches = [(self.expr(c), self.expr(v)) for c, v in e.branches]
            orelse = self.expr(e.orelse)
            for c, v in branches:
                if not _is_const(c):
                    return e.copy(branches=branches, orelse=orelse)
                if _truthy(c):
                    st.folded_expressions += 1
                    return v
            st.folded_expressions += 1
            return orelse
        if k == "Unop":
            operand = self.expr(e.operand)
            if e.op == "-" and operand.kind == "Num":
                st.folded_expressions += 1
                return _num(-operand.value)
            if e.op == "not" and _is_const(operand):
                st.folded_expressions += 1
                return N("Bool", value=not _truthy(operand))
            if e.op == "#" and operand.kind == "Str":
                st.folded_expressions += 1
                return _num(len(operand.value))
            return e.copy(operand=operand)
        if k == "Binop":
            left, right = self.expr(e.left), self.expr(e.right)
            if e.op in ("and", "or") and _is_const(left):
                st.folded_expressions += 1
                if e.op == "and":
                    return right if _truthy(left) else left
                return left if _truthy(left) else right
            folded = fold_binop(e.op, left, right)
            if folded is not None:
                st.folded_expressions += 1
                return folded
            return e.copy(left=left, right=right)
        return e

    @staticmethod
    def box(node: Node) -> Node | None:
        """Rewrite `B[1][B[3]]` to `B[2]` (MoonVeil upvalue box: B[1] == B and B[3] == 2)."""
        obj, key = node.obj, node.key
        if obj.kind != "Index" or obj.key.kind != "Num" or obj.key.value != 1:
            return None
        if key.kind != "Index" or key.key.kind != "Num" or key.key.value != 3:
            return None
        base = obj.obj
        if not (is_pure_path(base) and expr_equal(base, key.obj)):
            return None
        return N("Index", obj=base, key=_num(2))

    def block(self, stmts: list[Node]) -> list[Node]:
        out: list[Node] = []
        for s in stmts:
            out.extend(self.stmt(s))
        self._count_boxes(out)
        return out

    def _count_boxes(self, stmts: list[Node]) -> None:
        """Count `X = {[3]=2, [2]=v}` immediately followed by `X[1] = X`."""
        for a, b in zip(stmts, stmts[1:]):
            if a.kind != "Assign" or b.kind != "Assign" or len(b.targets) != 1 or len(b.values) != 1:
                continue
            tgt, val = b.targets[0], b.values[0]
            if not (tgt.kind == "Index" and tgt.key.kind == "Num" and tgt.key.value == 1 and tgt.obj.kind == "Name"):
                continue
            if val.kind != "Name" or val.name != tgt.obj.name:
                continue
            for t, v in zip(a.targets, a.values):
                if t.kind == "Name" and t.name == val.name and v.kind == "Table":
                    keys = {key.value for _, key, _ in v.items if key is not None and key.kind == "Num"}
                    if {2.0, 3.0} <= keys:
                        self.stats.box_constructions += 1

    @staticmethod
    def _splice(body: list[Node]) -> list[Node]:
        declares = any(s.kind in ("Local", "LocalFunction", "Label") for s in body)
        return [N("Do", body=body)] if declares else body

    def stmt(self, s: Node) -> list[Node]:
        k = s.kind
        if k == "Local":
            return [s.copy(values=[self.expr(v) for v in s.values])]
        if k == "LocalFunction":
            return [s.copy(func=self.expr(s.func))]
        if k == "Assign":
            return [s.copy(targets=[self.expr(t) for t in s.targets], values=[self.expr(v) for v in s.values])]
        if k == "Compound":
            return [s.copy(target=self.expr(s.target), value=self.expr(s.value))]
        if k == "CallStat":
            return [s.copy(call=self.expr(s.call))]
        if k == "Do":
            return [s.copy(body=self.block(s.body))]
        if k == "While":
            cond = self.expr(s.cond)
            if _is_const(cond) and not _truthy(cond):
                self.stats.removed_dead_loops += 1
                return []
            return [s.copy(cond=cond, body=self.block(s.body))]
        if k == "Repeat":
            return [s.copy(body=self.block(s.body), cond=self.expr(s.cond))]
        if k == "If":
            clauses = []
            for cond, body in s.clauses:
                cond = self.expr(cond)
                if _is_const(cond):
                    self.stats.pruned_branches += 1
                    if _truthy(cond):
                        if not clauses:
                            return self._splice(self.block(body))
                        return [s.copy(clauses=clauses, orelse=self.block(body))]
                    continue
                clauses.append((cond, self.block(body)))
            orelse = self.block(s.orelse) if s.orelse is not None else None
            if not clauses:
                return self._splice(orelse) if orelse else []
            return [s.copy(clauses=clauses, orelse=orelse)]
        if k == "NumFor":
            return [s.copy(start=self.expr(s.start), stop=self.expr(s.stop), step=self.expr(s.step) if s.step is not None else None, body=self.block(s.body))]
        if k == "GenFor":
            return [s.copy(iters=[self.expr(e) for e in s.iters], body=self.block(s.body))]
        if k == "Return":
            return [s.copy(values=[self.expr(v) for v in s.values])]
        return [s]


def fold_chunk(chunk: Node, resolve_boxes: bool = True) -> tuple[Node, Stats]:
    stats = Stats()
    return N("Chunk", body=Folder(stats, resolve_boxes).block(chunk.body)), stats


# ---------------------------------------------------------------------------
# Control-flow-flattening recovery
# ---------------------------------------------------------------------------

COMPARE_OPS = {"<", "<=", ">", ">=", "==", "~="}
MIRROR = {"<": ">", "<=": ">=", ">": "<", ">=": "<=", "==": "==", "~=": "~="}
NEGATE = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "==": "~=", "~=": "=="}
MAX_NODES_PER_DISPATCHER = 4096


def _state_comparison(cond: Node, var: str | None) -> tuple[str, str, float] | None:
    """Return (var, op, k) normalised so the condition reads `var op k`."""
    if cond.kind != "Binop" or cond.op not in COMPARE_OPS:
        return None
    left, right = cond.left, cond.right
    if left.kind == "Name" and right.kind == "Num" and (var is None or left.name == var):
        return left.name, cond.op, right.value
    if right.kind == "Name" and left.kind == "Num" and (var is None or right.name == var):
        return right.name, MIRROR[cond.op], left.value
    return None


def _dispatch_if(stmts: list[Node], var: str) -> Node | None:
    if len(stmts) != 1 or stmts[0].kind != "If":
        return None
    node = stmts[0]
    return node if all(_state_comparison(c, var) for c, _ in node.clauses) else None


class Interval:
    def __init__(self) -> None:
        self.lo, self.lo_closed = -math.inf, False
        self.hi, self.hi_closed = math.inf, False
        self.eq: float | None = None
        self.ne: list[float] = []

    def clone(self) -> "Interval":
        other = Interval()
        other.lo, other.lo_closed, other.hi, other.hi_closed = self.lo, self.lo_closed, self.hi, self.hi_closed
        other.eq, other.ne = self.eq, list(self.ne)
        return other

    def apply(self, op: str, k: float, truth: bool) -> None:
        if not truth:
            op = NEGATE[op]
        if op == "==":
            self.eq = k
        elif op == "~=":
            self.ne.append(k)
        elif op in ("<", "<="):
            if k < self.hi or (k == self.hi and op == "<"):
                self.hi, self.hi_closed = k, op == "<="
        elif k > self.lo or (k == self.lo and op == ">"):
            self.lo, self.lo_closed = k, op == ">="

    def __str__(self) -> str:
        if self.eq is not None:
            return f"{{{format_number(self.eq)}}}"
        lo = ("[" if self.lo_closed else "(") + ("-inf" if self.lo == -math.inf else format_number(self.lo))
        hi = ("inf" if self.hi == math.inf else format_number(self.hi)) + ("]" if self.hi_closed else ")")
        text = f"{lo}, {hi}"
        if self.ne:
            text += " \\ {" + ", ".join(format_number(v) for v in self.ne) + "}"
        return text


@dataclass
class Leaf:
    index: int
    body: list[Node]
    interval: str


@dataclass
class Transition:
    kind: str  # goto | cond | return | opaque | fallthrough | complex
    target: float | None = None
    cond: Node | None = None
    branches: list["Transition"] = field(default_factory=list)
    expr: Node | None = None
    note: str = ""

    def constant_targets(self) -> list[float]:
        if self.kind in ("goto", "fallthrough") and self.target is not None:
            return [self.target]
        if self.kind == "cond":
            return [t for b in self.branches for t in b.constant_targets()]
        return []

    def opaque_notes(self) -> list[str]:
        if self.kind == "opaque":
            return [self.note]
        if self.kind == "cond":
            return [n for b in self.branches for n in b.opaque_notes()]
        return []


@dataclass
class Dispatcher:
    function_label: str
    var: str
    loop_kind: str
    entry: float | None
    entry_expr: Node | None
    leaves: list[Leaf]
    loop: Node
    nodes: dict[Any, tuple[Leaf, list[Node], Transition]] = field(default_factory=dict)
    order: list[Any] = field(default_factory=list)

    @property
    def opaque(self) -> list[str]:
        return [n for _, _, t in self.nodes.values() for n in t.opaque_notes()]


def _collect_leaves(node: Node, var: str, interval: Interval, out: list[tuple[list[Node], Interval]]) -> None:
    current = interval.clone()
    for cond, body in node.clauses:
        _, op, k = _state_comparison(cond, var)  # type: ignore[misc]
        taken = current.clone()
        taken.apply(op, k, True)
        inner = _dispatch_if(body, var)
        if inner is not None:
            _collect_leaves(inner, var, taken, out)
        else:
            out.append((body, taken))
        current.apply(op, k, False)
    body = node.orelse if node.orelse is not None else []
    inner = _dispatch_if(body, var)
    if inner is not None:
        _collect_leaves(inner, var, current, out)
    else:
        out.append((body, current))


def _dispatch(node: Node, var: str, value: float) -> list[Node]:
    while True:
        chosen: list[Node] | None = None
        for cond, body in node.clauses:
            _, op, k = _state_comparison(cond, var)  # type: ignore[misc]
            if _compare(op, value, k):
                chosen = body
                break
        if chosen is None:
            chosen = node.orelse if node.orelse is not None else []
        inner = _dispatch_if(chosen, var)
        if inner is None:
            return chosen
        node = inner


def _substituter(var: str, value: float) -> Callable[[Node], Node | None]:
    def fn(e: Node) -> Node | None:
        if e.kind == "Name" and e.name == var:
            return _num(value)
        if e.kind == "Function":
            return e
        return None
    return fn


def _substitute(e: Node, var: str, value: float | None) -> Node:
    return e if value is None else map_expr(e, _substituter(var, value))


def _refs(e: Node, var: str) -> bool:
    return any(x.kind == "Name" and x.name == var for x in walk_expr(e))


def _refs_deep(s: Node, var: str) -> bool:
    return any(_refs(e, var) for e in stmt_exprs(s)) or any(_refs_deep(x, var) for b in stmt_blocks(s) for x in b)


def _assigns_var_deep(stmts: list[Node], var: str) -> bool:
    for s in stmts:
        if s.kind == "Assign" and any(t.kind == "Name" and t.name == var for t in s.targets):
            return True
        if s.kind == "Compound" and s.target.kind == "Name" and s.target.name == var:
            return True
        if s.kind == "Local" and var in s.names:
            return True
        if s.kind in ("NumFor",) and s.var == var:
            return True
        if s.kind == "GenFor" and var in s.names:
            return True
        if any(_assigns_var_deep(b, var) for b in stmt_blocks(s)):
            return True
    return False


def cache_key(e: Node) -> float | None:
    """Match the MoonVeil state cache `X.U[k] or X:M(...)` and return k."""
    if e.kind == "Paren":
        e = e.expr
    if e.kind != "Binop" or e.op != "or":
        return None
    left = e.left
    if left.kind == "Index" and left.key.kind == "Num" and left.obj.kind == "Index" and _str_ident(left.obj.key) == "U":
        return left.key.value
    return None


class StateEvaluator:
    def __init__(self, var: str, oracle: dict[float, float]) -> None:
        self.var = var
        self.oracle = oracle
        self.folder = Folder(resolve_boxes=False)

    def eval(self, e: Node, current: float | None) -> Transition:
        e = self.folder.expr(_substitute(e, self.var, current))
        if e.kind == "Num":
            return Transition("goto", e.value)
        key = cache_key(e)
        if key is not None:
            if key in self.oracle:
                return Transition("goto", self.oracle[key], note=f"oráculo U[{format_number(key)}]")
            return Transition("opaque", expr=e, note=f"U[{format_number(key)}]")
        if e.kind == "Binop" and e.op == "or" and e.left.kind == "Binop" and e.left.op == "and" and e.left.right.kind != "Nil":
            # `c and A or B` behaves as `if c then A else B` because A is never falsy here.
            then_t = self.eval(e.left.right, current)
            if then_t.kind == "goto" or then_t.kind == "opaque" and then_t.expr is not None and cache_key(then_t.expr) is not None:
                return Transition("cond", cond=e.left.left, branches=[then_t, self.eval(e.right, current)])
        if e.kind == "IfExpr" and len(e.branches) == 1:
            return Transition("cond", cond=e.branches[0][0], branches=[self.eval(e.branches[0][1], current), self.eval(e.orelse, current)])
        return Transition("opaque", expr=e, note="expresión no constante")


def _leaf_transition(body: list[Node], var: str, entry: float | None, ev: StateEvaluator) -> tuple[list[Node], Transition]:
    """Strip state assignments from a dispatcher leaf and compute its successor."""
    out: list[Node] = []
    current = entry
    transition = Transition("fallthrough", entry)
    folder = Folder(resolve_boxes=False)
    for idx, s in enumerate(body):
        if s.kind == "Return":
            # Lua only allows `return` as the last statement of a block; other labelled blocks follow it.
            out.append(N("Do", body=[s]))
            return out, Transition("return")
        if s.kind == "Break":
            return out, Transition("return", note="break: sale del dispatcher")
        if s.kind == "Assign" and any(t.kind == "Name" and t.name == var for t in s.targets):
            if len(s.values) < len(s.targets) and s.values and s.values[-1].kind in ("Call", "Invoke", "Vararg"):
                out.extend(body[idx:])
                return out, Transition("complex", note="asignación multivalor sobre el estado")
            targets, values = [], []
            state_expr: Node = N("Nil")
            for pos, target in enumerate(s.targets):
                value = s.values[pos] if pos < len(s.values) else N("Nil")
                if target.kind == "Name" and target.name == var:
                    state_expr = value
                else:
                    targets.append(target if target.kind == "Name" else folder.expr(_substitute(target, var, current)))
                    values.append(folder.expr(_substitute(value, var, current)))
            values.extend(s.values[len(s.targets):])
            if targets:
                out.append(N("Assign", targets=targets, values=values))
            transition = ev.eval(state_expr, current)
            current = transition.target if transition.kind == "goto" else None
            continue
        if _assigns_var_deep([s], var):
            out.extend(body[idx:])
            return out, Transition("complex", note="el estado se modifica dentro de una estructura anidada")
        if _refs_deep(s, var):
            if current is None:
                out.append(N("Comment", text=f"[cff] lee `{var}` con valor desconocido en este punto"))
            else:
                s = folder.stmt(map_stmt(s, _substituter(var, current)))
                out.extend(s)
                continue
        out.append(s)
    if transition.kind == "opaque" or transition.kind == "cond":
        if transition.kind == "opaque" and transition.expr is not None:
            out.append(N("Assign", targets=[N("Name", name=var)], values=[transition.expr]))
        return out, transition
    if current is not None and transition.kind == "goto":
        return out, Transition("goto", current, note=transition.note)
    return out, transition


def _initial_state(container: list[Node], loop_index: int, var: str, ev: StateEvaluator) -> tuple[float | None, Node | None]:
    for s in reversed(container[:loop_index]):
        if s.kind in ("Assign", "Local"):
            names = [t.name if t.kind == "Name" else None for t in s.targets] if s.kind == "Assign" else list(s.names)
            if var in names:
                pos = names.index(var)
                if pos >= len(s.values):
                    return None, None
                t = ev.eval(s.values[pos], None)
                return (t.target if t.kind == "goto" else None), s.values[pos]
        if _assigns_var_deep([s], var):
            return None, None
    return None, None


def find_dispatchers(chunk: Node, oracle: dict[float, float] | None = None) -> list[Dispatcher]:
    oracle = oracle or {}
    found: list[Dispatcher] = []
    for fn_index, fn in enumerate(iter_functions(chunk)):
        label = "chunk" if fn.kind == "Chunk" else f"función #{fn_index}"

        def scan(stmts: list[Node]) -> None:
            for idx, s in enumerate(stmts):
                loop_kind = None
                if s.kind == "While" and _is_const(s.cond) and _truthy(s.cond):
                    loop_kind = "while true"
                elif s.kind == "Repeat" and _is_const(s.cond) and not _truthy(s.cond):
                    loop_kind = "repeat until false"
                if loop_kind and len(s.body) == 1 and s.body[0].kind == "If":
                    first = _state_comparison(s.body[0].clauses[0][0], None)
                    root = _dispatch_if(s.body, first[0]) if first else None
                    if root is not None:
                        found.append(_build_dispatcher(label, first[0], loop_kind, root, s, stmts, idx, oracle))
                        continue
                for b in stmt_blocks(s):
                    scan(b)

        scan(fn.body)
    return found


def _build_dispatcher(label: str, var: str, loop_kind: str, root: Node, loop: Node, container: list[Node], idx: int, oracle: dict[float, float]) -> Dispatcher:
    raw: list[tuple[list[Node], Interval]] = []
    _collect_leaves(root, var, Interval(), raw)
    leaves = [Leaf(i, body, str(iv)) for i, (body, iv) in enumerate(raw)]
    by_id = {id(leaf.body): leaf for leaf in leaves}
    ev = StateEvaluator(var, oracle)
    entry, entry_expr = _initial_state(container, idx, var, ev)
    d = Dispatcher(label, var, loop_kind, entry, entry_expr, leaves, loop)

    worklist: list[tuple[Leaf, float | None]] = []
    if entry is not None:
        worklist.append((by_id[id(_dispatch(root, var, entry))], entry))
    seeded = False
    while True:
        while worklist and len(d.nodes) < MAX_NODES_PER_DISPATCHER:
            leaf, value = worklist.pop(0)
            key = ("s", value) if value is not None else ("b", leaf.index)
            if key in d.nodes:
                continue
            body, trans = _leaf_transition(leaf.body, var, value, ev)
            d.nodes[key] = (leaf, body, trans)
            d.order.append(key)
            for target in trans.constant_targets():
                worklist.append((by_id[id(_dispatch(root, var, target))], target))
        if seeded:
            break
        seeded = True
        reached = {id(n[0].body) for n in d.nodes.values()}
        worklist.extend((leaf, None) for leaf in leaves if id(leaf.body) not in reached)
    return d


def state_label(key: Any) -> str:
    kind, value = key
    if kind == "s":
        return "s_" + format_number(value).replace("-", "m").replace(".", "_").replace("(", "").replace(")", "").replace("/", "_")
    return f"bloque_{value}"


def render_dispatcher(d: Dispatcher, printer: Printer, depth: int) -> list[str]:
    preds: dict[Any, int] = {k: 0 for k in d.nodes}
    for key in d.order:
        for target in d.nodes[key][2].constant_targets():
            tk = ("s", target)
            if tk in preds:
                preds[tk] += 1
    if d.order:
        preds[d.order[0]] = preds.get(d.order[0], 0) + 1  # entry edge from the function itself

    pad = printer.indent * depth
    entry = format_number(d.entry) if d.entry is not None else "dinámica"
    lines = [f"{pad}-- [cff] dispatcher `{d.var}` ({d.loop_kind}); entrada={entry}; hojas={len(d.leaves)}; nodos={len(d.nodes)}; opacas={len(d.opaque)}"]
    needs_dispatch = False
    emitted: set[Any] = set()

    def jump(t: Transition) -> str:
        nonlocal needs_dispatch
        if t.kind in ("goto", "fallthrough") and t.target is not None:
            return f"goto {state_label(('s', t.target))}"
        needs_dispatch = True
        if t.kind == "opaque" and t.expr is not None:
            return f"{d.var} = {printer.expr(t.expr, depth)}; goto __dispatch_{d.var}"
        return f"goto __dispatch_{d.var}"

    for start in d.order:
        key: Any = start
        first = True
        while key is not None and key not in emitted:
            emitted.add(key)
            leaf, body, trans = d.nodes[key]
            if first or preds.get(key, 0) != 1:
                lines.append(f"{pad}::{state_label(key)}:: -- hoja {leaf.index}; {d.var} ∈ {leaf.interval}")
            else:
                lines.append(f"{pad}-- ({state_label(key)}, hoja {leaf.index})")
            first = False
            lines.extend(printer.block(body, depth))
            nxt = None
            if trans.kind == "goto":
                tk = ("s", trans.target)
                if tk in d.nodes and tk not in emitted and preds.get(tk, 0) == 1:
                    nxt = tk
                else:
                    lines.append(pad + jump(trans) + (f" -- {trans.note}" if trans.note else ""))
            elif trans.kind == "cond":
                a, b = trans.branches
                lines.append(f"{pad}if {printer.expr(trans.cond, depth)} then {jump(a)} else {jump(b)} end")
            elif trans.kind == "fallthrough":
                if trans.target is not None:
                    lines.append(f"{pad}{jump(trans)} -- el estado no cambia en este bloque")
                else:
                    needs_dispatch = True
                    lines.append(f"{pad}goto __dispatch_{d.var} -- [cff] estado de entrada desconocido")
            elif trans.kind == "opaque":
                needs_dispatch = True
                lines.append(f"{pad}goto __dispatch_{d.var} -- [cff] transición opaca: {trans.note}")
            elif trans.kind == "complex":
                needs_dispatch = True
                lines.append(f"{pad}goto __dispatch_{d.var} -- [cff] {trans.note}")
            key = nxt
    if needs_dispatch:
        lines.append(f"{pad}::__dispatch_{d.var}:: -- [cff] destino calculado en tiempo de ejecución; ver cff_report.md")
    return lines


def render_unflattened(chunk: Node, dispatchers: list[Dispatcher]) -> str:
    by_loop = {id(d.loop): d for d in dispatchers}

    class CffPrinter(Printer):
        def stmt(self, s: Node, depth: int) -> list[str]:
            d = by_loop.get(id(s))
            if d is not None:
                return render_dispatcher(d, self, depth)
            return super().stmt(s, depth)

    header = [
        "-- Pseudocódigo desaplanado generado por análisis estático (no ejecutable tal cual).",
        "-- Cada bucle dispatcher se sustituye por bloques etiquetados y saltos `goto`.",
        "-- Los saltos a __dispatch_* dependen de valores calculados por el runtime.",
        "",
    ]
    return "\n".join(header) + CffPrinter().chunk(chunk)


def cff_report(dispatchers: list[Dispatcher], printer: Printer, stats: Stats | None = None, oracle_size: int = 0) -> str:
    lines = ["# Informe de desofuscación AST", ""]
    if stats is not None:
        lines += [
            "## Transformaciones semánticamente equivalentes (deobfuscated.lua)",
            "",
            f"- Expresiones constantes plegadas: {stats.folded_expressions}",
            f"- Ramas con condición constante eliminadas: {stats.pruned_branches}",
            f"- Bucles muertos eliminados: {stats.removed_dead_loops}",
            f"- Paréntesis redundantes eliminados: {stats.redundant_parens}",
            f"- Construcciones de box detectadas (`X={{[3]=2,[2]=v}}; X[1]=X`): {stats.box_constructions}",
            f"- Accesos `B[1][B[3]]` reescritos como `B[2]`: {stats.resolved_boxes}",
            "",
        ]
    lines += ["## Desaplanado de control de flujo (unflattened.lua)", ""]
    if not dispatchers:
        lines.append("No se encontraron bucles dispatcher reconocibles.")
        return "\n".join(lines) + "\n"
    total_opaque = sum(len(d.opaque) for d in dispatchers)
    lines += [
        f"- Dispatchers detectados: {len(dispatchers)}",
        f"- Con estado inicial constante: {sum(1 for d in dispatchers if d.entry is not None)}",
        f"- Hojas totales: {sum(len(d.leaves) for d in dispatchers)}",
        f"- Nodos (hoja, estado) recuperados: {sum(len(d.nodes) for d in dispatchers)}",
        f"- Transiciones opacas: {total_opaque}",
        f"- Entradas del oráculo de estados cargadas: {oracle_size}",
        "",
        "Las transiciones opacas usan la caché `X.U[k] or X:M(...)` del runtime. Se pueden resolver con "
        "`--state-oracle archivo.tsv` (una línea `clave<TAB>valor` por entrada; admite 0x, 0b y negativos).",
        "",
        "| # | función | var | bucle | entrada | hojas | nodos | goto | cond | return | opacas | complejas |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    keys: dict[str, int] = {}
    for idx, d in enumerate(dispatchers):
        kinds: dict[str, int] = {}
        for _, _, t in d.nodes.values():
            kinds[t.kind] = kinds.get(t.kind, 0) + 1
        for note in d.opaque:
            if note.startswith("U["):
                keys[note[2:-1]] = keys.get(note[2:-1], 0) + 1
        entry = format_number(d.entry) if d.entry is not None else "dinámica"
        lines.append(
            f"| {idx} | {d.function_label} | `{d.var}` | {d.loop_kind} | {entry} | {len(d.leaves)} | {len(d.nodes)} | "
            f"{kinds.get('goto', 0) + kinds.get('fallthrough', 0)} | {kinds.get('cond', 0)} | {kinds.get('return', 0)} | {len(d.opaque)} | {kinds.get('complex', 0)} |"
        )
    lines.append("")
    if keys:
        lines += ["## Claves de caché de estado sin resolver", "", "| clave | usos |", "|---|---|"]
        for key, count in sorted(keys.items(), key=lambda kv: (-kv[1], float(kv[0]) if re.fullmatch(r"-?\d+", kv[0]) else 0)):
            lines.append(f"| `{key}` | {count} |")
        lines.append("")
        lines.append("Plantilla para el oráculo: `state_oracle_template.tsv`.")
        lines.append("")
    return "\n".join(lines) + "\n"


def oracle_template(dispatchers: list[Dispatcher]) -> str:
    seen: list[str] = []
    for d in dispatchers:
        for note in d.opaque:
            if note.startswith("U[") and note[2:-1] not in seen:
                seen.append(note[2:-1])
    lines = ["# clave\tvalor  (rellene la segunda columna y use --state-oracle)"]
    lines.extend(f"{k}\t" for k in seen)
    return "\n".join(lines) + "\n"


def load_oracle(text: str) -> dict[float, float]:
    def num(x: str) -> float:
        neg = x.startswith("-")
        v = parse_number(x[1:] if neg else x)
        return -v if neg else v

    oracle: dict[float, float] = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = re.split(r"[\t,; ]+", line)
        if len(parts) < 2 or not parts[1]:
            continue
        try:
            oracle[num(parts[0])] = num(parts[1])
        except ValueError as exc:
            raise ValueError(f"oráculo: línea {lineno} no válida: {line!r}") from exc
    return oracle

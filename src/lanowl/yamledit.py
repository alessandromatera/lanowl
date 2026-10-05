"""Edits to config.yaml and inventory.yaml that leave the rest of the file as it was.

A save from the dashboard changes a few values; everything else in the file — its comments,
its order, its alignment, a flow map wrapped over two lines — has to come out byte for byte.
Dumping a parsed file never does that (every YAML library re-formats something), so this
module edits the TEXT: PyYAML's composer says where each value starts and ends, and only
those characters change. A new key goes in on a line of its own, where the example file
has it; a key taken out takes its lines with it; a list keeps the items that did not change,
with their comments.

Every edit is checked the one way that cannot be fooled: the new text is parsed again and
must equal the old data with the change applied. If it does not, the edit is refused
(EditError) — a file lanowl cannot edit exactly is one it leaves alone.

    new_text = apply(text, [{"op": "set", "path": ["model", "name"], "value": "qwen3:32b"},
                            {"op": "del", "path": ["model", "keep_alive"]}])
"""
from __future__ import annotations

import copy
import json
import re
from typing import Callable, Optional

import yaml
from yaml.nodes import MappingNode, ScalarNode, SequenceNode


class EditError(Exception):
    """The edit could not be made exactly; nothing should be written."""


COMMENT_COL = 36           # where a new key's comment starts, as in the example files
_PLAIN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-/@+]*$")


# --- the data side: what the file must say afterwards -----------------------------------
def load(text: str):
    return yaml.safe_load(text) if text.strip() else None


def expected(data, ops: list):
    """The data with the operations applied — what the edited text must parse to."""
    d = copy.deepcopy(data) if data is not None else {}
    for op in ops:
        path, kind = list(op["path"]), op["op"]
        if kind in ("set", "del"):
            parent = d
            for k in path[:-1]:
                nxt = parent[k] if isinstance(parent, list) else parent.get(k)
                if nxt is None:
                    if kind == "del":
                        parent = None
                        break
                    nxt = {}
                    parent[k] = nxt
                parent = nxt
            if parent is None:
                continue
            if kind == "set":
                parent[path[-1]] = copy.deepcopy(op["value"])
            elif isinstance(parent, dict):
                parent.pop(path[-1], None)
        elif kind == "insert":
            lst = _dget(d, path)
            if lst is None:
                lst = []
                _dset(d, path, lst)
            i = op.get("index", len(lst))
            lst.insert(len(lst) if i is None else i, copy.deepcopy(op["value"]))
        elif kind == "remove":
            _dget(d, path[:-1]).pop(path[-1])
        else:
            raise EditError(f"unknown operation {kind!r}")
    return d


def _dget(d, path):
    for k in path:
        if d is None:
            return None
        d = d[k] if isinstance(d, list) else d.get(k)
    return d


def _dset(d, path, v):
    for k in path[:-1]:
        d = d.setdefault(k, {}) if isinstance(d, dict) else d[k]
    d[path[-1]] = v


# --- rendering values --------------------------------------------------------------------
def scalar(v, style: Optional[str] = None) -> str:
    """One scalar as YAML. `style`: '"' or "'" keeps a quoted original quoted; None writes a
    plain word where YAML reads it back unchanged, and double quotes otherwise."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float):
        s = repr(v)
        return s.replace("e", ".0e") if "e" in s and "." not in s else s
    s = str(v)
    if style == "'":
        return "'" + s.replace("'", "''") + "'"
    if style is None and _PLAIN.match(s):
        try:
            if yaml.safe_load(s) == s:
                return s
        except yaml.YAMLError:
            pass
    return json.dumps(s, ensure_ascii=False)


def flow(v, style: Optional[str] = None) -> str:
    """A value on one line: [a, b], {k: v}, or a scalar."""
    if isinstance(v, dict):
        return "{" + ", ".join(f"{scalar(k)}: {flow(x, style)}" for k, x in v.items()) + "}"
    if isinstance(v, list):
        return "[" + ", ".join(flow(x, style) for x in v) + "]"
    return scalar(v, style)


def flow_like(node, v, default: Optional[str] = None) -> str:
    """`v` on one line, each part quoted the way the same part of `node` was (a flow map's
    `name: "Home"` keeps its quotes, `key: home` stays plain); new parts in `default`."""
    if isinstance(v, dict):
        kids = {k.value: x for k, x in node.value} if isinstance(node, MappingNode) else {}
        return "{" + ", ".join(f"{scalar(k)}: {flow_like(kids.get(str(k)), x, default)}"
                               for k, x in v.items()) + "}"
    if isinstance(v, list):
        first = node.value[0] if isinstance(node, SequenceNode) and node.value else None
        return "[" + ", ".join(flow_like(first, x, default) for x in v) + "]"
    if isinstance(node, ScalarNode):
        return scalar(v, node.style if node.style in ('"', "'") else None)
    return scalar(v, default)


def block(v, indent: int, style: Optional[str] = None) -> list:
    """A collection as block lines, each already indented. Lists of maps become block
    sequences of flow maps (`- {type: icmp}`), as the example files write checks; a map
    inside a map stays on one line, in flow style."""
    pad = " " * indent
    out = []
    if isinstance(v, dict):
        for k, x in v.items():
            if isinstance(x, list) and x and any(isinstance(i, (dict, list)) for i in x):
                out.append(f"{pad}{scalar(k)}:")
                out += block(x, indent + 2, style)
            else:
                out.append(f"{pad}{scalar(k)}: {flow(x, style)}")
    elif isinstance(v, list):
        for x in v:
            if isinstance(x, dict) and any(isinstance(i, list) and i and isinstance(i[0], dict)
                                           for i in x.values()):
                inner = block(x, indent + 2, style)
                out.append(pad + "- " + inner[0][indent + 2:])
                out += inner[1:]
            else:
                out.append(f"{pad}- {flow(x, style)}")
    return out


def item_lines(v, indent: int, style: Optional[str] = None, quoted=()) -> list:
    """One new item of a block sequence of maps (a device): `- key: value` and its keys
    under it. `quoted`: keys whose string values are written in double quotes (a device's
    name), as the example does."""
    rel = []                             # relative to the item's keys
    for k, x in v.items():
        st = '"' if (k in quoted and isinstance(x, str)) else style
        if isinstance(x, list) and x and isinstance(x[0], dict):
            rel.append(f"{scalar(k)}:")
            rel += block(x, 2, style)
        else:
            rel.append(f"{scalar(k)}: {flow(x, st)}")
    pad = " " * indent
    return [pad + "- " + rel[0]] + [pad + "  " + ln for ln in rel[1:]]


# --- the text side -----------------------------------------------------------------------
def _compose(text: str):
    try:
        return yaml.compose(text, Loader=yaml.SafeLoader) if text.strip() else None
    except yaml.YAMLError as e:
        raise EditError(f"the file does not parse: {e}") from None


def _child(node, key):
    """(key node, value node) of a map's key, or (None, item) of a list's index."""
    if isinstance(node, MappingNode):
        for k, v in node.value:
            if isinstance(k, ScalarNode) and k.value == str(key):
                return k, v
        return None
    if isinstance(node, SequenceNode) and isinstance(key, int) and 0 <= key < len(node.value):
        return None, node.value[key]
    return None


def _end(node) -> int:
    """Where the node's own text ends (exclusive): its last character, never the comments or
    blank lines a block collection's end mark runs on into."""
    if isinstance(node, ScalarNode) or node.flow_style:
        return node.end_mark.index
    ends = [node.start_mark.index]
    if isinstance(node, MappingNode):
        for k, v in node.value:
            ends += [_end(k), _end(v)]
    else:
        ends += [_end(v) for v in node.value]
    return max(ends)


def _bol(text: str, i: int) -> int:
    return text.rfind("\n", 0, i) + 1


def _eol(text: str, i: int) -> int:
    j = text.find("\n", i)
    return len(text) if j < 0 else j


def _after_line(text: str, end: int) -> int:
    """The start of the line after the one holding the character before `end`."""
    j = _eol(text, max(end - 1, 0))
    return min(j + 1, len(text))


def _comment_col(text: str, i: int) -> int:
    """The column of a comment-only line, or -1."""
    line = text[i:_eol(text, i)]
    s = line.lstrip(" ")
    return len(line) - len(s) if s.startswith("#") else -1


def _past_continuations(text: str, i: int, key_col: int) -> int:
    """Skip the comment lines that continue the line above (indented deeper than the keys):
    a new key goes after them, not between a comment and the rest of it."""
    while i < len(text):
        c = _comment_col(text, i)
        if c <= key_col:
            break
        i = _after_line(text, _eol(text, i) + 1) if _eol(text, i) < len(text) else len(text)
    return i


def _style(node) -> Optional[str]:
    if isinstance(node, ScalarNode) and node.style in ('"', "'"):
        return node.style
    if isinstance(node, (SequenceNode, MappingNode)) and node.value:
        first = node.value[0] if isinstance(node, SequenceNode) else node.value[0][1]
        return _style(first)
    return None


class _Editor:
    def __init__(self, text: str, order: Optional[Callable] = None, comment: Optional[Callable] = None,
                 quoted=(), new_style: Optional[str] = '"'):
        self.text = text
        self.order = order or (lambda path: [])
        self.comment = comment or (lambda path: "")
        self.quoted = tuple(quoted)
        self.new_style = new_style

    # -- finding --
    def _walk(self, path):
        """[(key node, value node)] along the path, as far as it exists."""
        node, out = _compose(self.text), []
        for k in path:
            if node is None:
                break
            hit = _child(node, k)
            if hit is None:
                break
            out.append(hit)
            node = hit[1]
        return out

    def _root(self):
        return _compose(self.text)

    # -- the edits, one at a time, each on fresh marks --
    def set(self, path, value):
        trail = self._walk(path)
        if len(trail) == len(path):
            k, v = trail[-1]
            self._replace(path, k, v, value)
            return
        # the deepest part that exists gets the rest as a new key
        have = len(trail)
        parent = trail[-1][1] if trail else self._root()
        rest = path[have:]
        nested = value
        for key in reversed(rest[1:]):
            nested = {key: nested}
        if parent is None:
            self._top(rest[0], nested, path[:have])
        elif isinstance(parent, ScalarNode) and parent.value in ("", "~", "null"):
            self._fill_null(trail[-1][0], parent, {rest[0]: nested}, path[:have])
        elif isinstance(parent, MappingNode):
            self._insert_key(parent, rest[0], nested, path[:have])
        else:
            raise EditError(f"{'.'.join(map(str, path[:have]))} is not a section")

    def delete(self, path):
        trail = self._walk(path)
        if len(trail) != len(path):
            return
        parent = trail[-2][1] if len(trail) > 1 else self._root()
        k, v = trail[-1]
        if isinstance(parent, MappingNode) and parent.flow_style:
            self._flow_remove(parent, k, v)
            return
        if len(parent.value) == 1:
            # the last key of a section: the section stays, empty
            pk = trail[-2][0] if len(trail) > 1 else None
            if pk is None:
                self.text = ""
                return
            self._splice(pk.end_mark.index, _end(parent), ": {}")
            return
        start = _bol(self.text, k.start_mark.index)
        if self.text[start:k.start_mark.index].strip():
            raise EditError(f"{'.'.join(map(str, path))} starts a list item and cannot be removed alone")
        self._splice(start, _after_line(self.text, _end(v)), "")

    def insert(self, path, index, value):
        """A new item in the list at `path` (index None = at the end)."""
        trail = self._walk(path)
        if len(trail) != len(path):
            self.set(path, [value])
            return
        k, seq = trail[-1]
        empty = isinstance(seq, ScalarNode) or (isinstance(seq, SequenceNode) and not seq.value)
        if empty:
            if isinstance(seq, SequenceNode) and seq.flow_style and not isinstance(value, dict):
                self._splice(seq.start_mark.index, seq.end_mark.index, flow([value], self.new_style))
                return
            if k is None:
                raise EditError("an empty list inside a list")
            col = k.start_mark.column + 2
            lines = (item_lines(value, col, None, self.quoted) if isinstance(value, dict)
                     else [" " * col + "- " + flow(value, self.new_style)])
            if isinstance(seq, SequenceNode):            # `key: []`
                self._splice(k.end_mark.index, seq.end_mark.index, ":\n" + "\n".join(lines))
            else:                                        # `key:` and nothing (maybe a comment)
                eol = _eol(self.text, k.end_mark.index)
                self._splice(eol, eol, "\n" + "\n".join(lines))
            return
        if not isinstance(seq, SequenceNode):
            raise EditError(f"{'.'.join(map(str, path))} is not a list")
        n = len(seq.value)
        i = n if index is None else max(0, min(int(index), n))
        st = _style(seq) or self.new_style
        if seq.flow_style:
            if i == n:
                close = seq.end_mark.index - 1
                while self.text[close] != "]":
                    close -= 1
                self._splice(close, close, ", " + flow(value, st))
            else:
                at = seq.value[i].start_mark.index
                self._splice(at, at, flow(value, st) + ", ")
            return
        first = seq.value[0]
        dash = self.text.rfind("-", 0, first.start_mark.index)
        col = dash - _bol(self.text, dash)
        if isinstance(value, dict) and isinstance(first, MappingNode) and not first.flow_style:
            lines = item_lines(value, col, None, self.quoted)
        else:
            lines = [" " * col + "- " + flow_like(first, value, self.new_style)]
        if i == n:
            at = _past_continuations(self.text, _after_line(self.text, _end(seq.value[-1])), col)
        else:
            at = _bol(self.text, seq.value[i].start_mark.index)
        if at >= len(self.text) and not self.text.endswith("\n"):
            self._splice(len(self.text), len(self.text), "\n" + "\n".join(lines) + "\n")
        else:
            self._splice(at, at, "\n".join(lines) + "\n")

    def remove(self, path):
        """Take item `path[-1]` out of the list at `path[:-1]`."""
        trail = self._walk(path[:-1])
        if len(trail) != len(path) - 1:
            raise EditError("no such list")
        k, seq = trail[-1]
        i = path[-1]
        if not isinstance(seq, SequenceNode) or not 0 <= i < len(seq.value):
            raise EditError("no such item")
        item = seq.value[i]
        if seq.flow_style:
            if len(seq.value) == 1:
                self._splice(seq.start_mark.index, seq.end_mark.index, "[]")
            elif i < len(seq.value) - 1:
                self._splice(item.start_mark.index, seq.value[i + 1].start_mark.index, "")
            else:
                prev = _end(seq.value[i - 1])
                self._splice(prev, item.end_mark.index, "")
            return
        if len(seq.value) == 1:
            self._splice(k.end_mark.index, _end(seq), ": []")
            return
        self._splice(_bol(self.text, item.start_mark.index), _after_line(self.text, _end(item)), "")

    # -- helpers --
    def _splice(self, a: int, b: int, s: str):
        self.text = self.text[:a] + s + self.text[b:]

    def _inline(self, a: int, b: int, s: str):
        """Replace a value on its line; a comment after it stays at its column."""
        eol = _eol(self.text, b)
        m = re.match(r"( +)#", self.text[b:eol])
        if m and "\n" not in s and "\n" not in self.text[a:b]:
            col = b - _bol(self.text, b) + len(m.group(1))          # the comment's column now
            new_end = a - _bol(self.text, a) + len(s)
            self._splice(a, b + len(m.group(1)), s + " " * max(2, col - new_end))
            return
        self._splice(a, b, s)

    def _replace(self, path, k, v, value):
        st = _style(v)
        if isinstance(value, str) and "\n" in value.strip("\n"):
            self._literal(k, v, value)
            return
        inline = isinstance(v, ScalarNode) and v.style not in ("|", ">") or \
            (not isinstance(v, ScalarNode) and v.flow_style)
        if isinstance(v, ScalarNode) and v.style in ("|", ">"):
            end = v.end_mark.index
            nl = "\n" if self.text[end - 1:end] == "\n" else ""
            self._splice(v.start_mark.index, end, flow(value, '"') + nl)
            return
        if inline:
            self._inline(v.start_mark.index, v.end_mark.index, flow_like(v, value, self.new_style))
            return
        # a block collection
        if isinstance(value, (dict, list)) and value and k is not None:
            if isinstance(v, MappingNode):
                col = v.start_mark.column
            else:
                dash = self.text.rfind("-", 0, v.value[0].start_mark.index)
                col = dash - _bol(self.text, dash)
            lines = block(value, col, st)
            self._splice(_bol(self.text, v.start_mark.index), _after_line(self.text, _end(v)),
                         "\n".join(lines) + "\n")
            return
        if k is None:
            raise EditError("a list item in block style is changed key by key, not replaced")
        self._splice(k.end_mark.index, _end(v), ": " + flow(value, st))

    def _literal(self, k, v, value: str):
        col = (k.start_mark.column if k is not None else v.start_mark.column) + 2
        body = "\n".join((" " * col + ln) if ln else "" for ln in value.rstrip("\n").split("\n"))
        ind = "|" + ("-" if not value.endswith("\n") else "")
        if isinstance(v, ScalarNode) and v.style in ("|", ">"):
            a, end = v.start_mark.index, v.end_mark.index
            head = self.text[a:_eol(self.text, a)]
            cm = head[head.find("#"):] if "#" in head else ""
            m = re.search(r"\n[ \t\n]*$", self.text[a:end])
            tail = m.group() if m else ""
            self._splice(a, end, ind + ("  " + cm if cm else "") + "\n" + body + tail)
            return
        # a one-line value becomes a block; a comment after it moves up beside the `|`
        eol = _eol(self.text, v.end_mark.index)
        rest = self.text[v.end_mark.index:eol]
        cm = rest.strip() if rest.strip().startswith("#") else ""
        self._splice(v.start_mark.index, eol, ind + ("  " + cm if cm else "") + "\n" + body)

    def _line(self, key, value, path, col: int) -> list:
        """A new `key: value` at `col`, as lines; a comment from the example on the first."""
        pad = " " * col
        if isinstance(value, list) and value and isinstance(value[0], dict):
            lines = [f"{pad}{scalar(key)}:"] + block(value, col + 2, self.new_style)
        elif isinstance(value, dict) and value and (col == 0 or any(isinstance(x, dict) for x in value.values())):
            lines = [f"{pad}{scalar(key)}:"]
            for kk, vv in value.items():
                lines += self._line(kk, vv, path + [key], col + 2)
        elif isinstance(value, str) and "\n" in value.strip("\n"):
            lines = [f"{pad}{scalar(key)}: |" + ("-" if not value.endswith("\n") else "")]
            lines += [(" " * (col + 2) + ln) if ln else "" for ln in value.rstrip("\n").split("\n")]
            return lines
        else:
            st = '"' if key in self.quoted and isinstance(value, str) else self.new_style
            lines = [f"{pad}{scalar(key)}: {flow(value, st)}"]
        cm = self.comment(path + [key])
        if cm and "\n" not in cm:
            first = lines[0]
            lines[0] = first + " " * max(2, COMMENT_COL - len(first)) + "# " + cm
        return lines

    def _insert_key(self, parent, key, value, ppath):
        if parent.flow_style:
            close = parent.end_mark.index - 1
            while self.text[close] != "}":
                close -= 1
            self._splice(close, close, (", " if parent.value else "")
                         + f"{scalar(key)}: {flow(value, self.new_style)}")
            return
        col = parent.value[0][0].start_mark.column
        lines = self._line(key, value, ppath, col)
        order = list(self.order(ppath))
        if key in order:
            pos = order.index(key)
            before = [kv for kv in parent.value if kv[0].value in order[:pos]]
            after = [kv for kv in parent.value if kv[0].value in order[pos + 1:]]
            if not before and after:
                kn = after[0][0]
                at = _bol(self.text, kn.start_mark.index)
                if not self.text[at:kn.start_mark.index].strip():     # not a `- key:` line
                    # the comment lines just above that key are its own: go above them too
                    while at > 0 and _comment_col(self.text, _bol(self.text, at - 1)) == col:
                        at = _bol(self.text, at - 1)
                    self._splice(at, at, "\n".join(lines) + "\n")
                    return
            anchor = before[-1] if before else parent.value[-1]
        else:
            anchor = parent.value[-1]
        at = _past_continuations(self.text, _after_line(self.text, _end(anchor[1])), col)
        if at >= len(self.text) and not self.text.endswith("\n"):
            self._splice(len(self.text), len(self.text), "\n" + "\n".join(lines) + "\n")
        else:
            self._splice(at, at, "\n".join(lines) + "\n")

    def _top(self, key, value, ppath):
        lines = self._line(key, value, ppath, 0)
        t = self.text
        sep = "" if not t or t.endswith("\n") else "\n"
        self.text = t + sep + "\n".join(lines) + "\n"

    def _fill_null(self, k, v, value: dict, ppath):
        col = k.start_mark.column + 2
        lines = []
        for kk, vv in value.items():
            lines += self._line(kk, vv, ppath, col)
        # `key:` with nothing after it (maybe a comment): the new lines go under it
        eol = _eol(self.text, k.end_mark.index)
        self._splice(eol, eol, "\n" + "\n".join(lines))

    def _flow_remove(self, parent, k, v):
        items = parent.value
        i = next(n for n, kv in enumerate(items) if kv[0] is k)
        if len(items) == 1:
            self._splice(k.start_mark.index, v.end_mark.index, "")
        elif i < len(items) - 1:
            self._splice(k.start_mark.index, items[i + 1][0].start_mark.index, "")
        else:
            self._splice(_end(items[i - 1][1]), v.end_mark.index, "")


def _fine(text: str, ops: list) -> list:
    """Coarse operations into fine ones: setting a whole block section or block list becomes
    a set per changed key and an insert or remove per changed item, so whatever did not change
    keeps its lines and their comments."""
    out = []
    data = load(text)
    root = _compose(text)

    def node_at(path):
        n = root
        for k in path:
            if n is None:
                return None
            hit = _child(n, k)
            if hit is None:
                return None
            n = hit[1]
        return n

    for op in ops:
        if op["op"] != "set":
            out.append(op)
            continue
        path, new = list(op["path"]), op["value"]
        old = _dget(data, path) if data is not None else None
        n = node_at(path)
        if n is None or old == new:
            if old != new or n is None:
                out.append(op)
            continue
        out += _expand(path, old, new, n)
    return out


def _expand(path, old, new, n) -> list:
    if isinstance(old, dict) and isinstance(new, dict) and isinstance(n, MappingNode) and not n.flow_style:
        ops = []
        for k in old:
            if k not in new:
                ops.append({"op": "del", "path": path + [k]})
        for k, v in new.items():
            if k not in old:
                ops.append({"op": "set", "path": path + [k], "value": v})
            elif old[k] != v:
                child = _child(n, k)
                ops += _expand(path + [k], old[k], v, child[1]) if child else \
                    [{"op": "set", "path": path + [k], "value": v}]
        return ops
    if isinstance(old, list) and isinstance(new, list) and isinstance(n, SequenceNode) and not n.flow_style \
            and old and new:
        # keep the items that are the same, in order (a longest common subsequence)
        a, b = old, new
        m = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
        for i in range(len(a) - 1, -1, -1):
            for j in range(len(b) - 1, -1, -1):
                m[i][j] = m[i + 1][j + 1] + 1 if a[i] == b[j] else max(m[i + 1][j], m[i][j + 1])
        keep, i, j = [], 0, 0
        while i < len(a) and j < len(b):
            if a[i] == b[j]:
                keep.append((i, j))
                i += 1
                j += 1
            elif m[i + 1][j] >= m[i][j + 1]:
                i += 1
            else:
                j += 1
        # the gaps between kept items: changed items in place first (set, so a flow map
        # stays a flow map), then what was taken out or added; from the end, so the indexes
        # of the earlier gaps still hold
        bounds = [(-1, -1)] + keep + [(len(a), len(b))]
        ops = []
        for (pi, pj), (ni, nj) in reversed(list(zip(bounds, bounds[1:]))):
            olds, news = list(range(pi + 1, ni)), list(range(pj + 1, nj))
            k = min(len(olds), len(news))
            for t in range(k - 1, -1, -1):
                i, j = olds[t], news[t]
                child = n.value[i]
                ops += _expand(path + [i], a[i], b[j], child) if isinstance(child, MappingNode) \
                    and not child.flow_style and isinstance(a[i], dict) and isinstance(b[j], dict) \
                    else [{"op": "set", "path": path + [i], "value": b[j]}]
            for i in reversed(olds[k:]):
                ops.append({"op": "remove", "path": path + [i]})
            for t, j in enumerate(news[k:]):
                ops.append({"op": "insert", "path": path, "index": (olds[0] if olds else pi + 1) + k + t,
                            "value": b[j]})
        return ops
    return [{"op": "set", "path": path, "value": new}]


def apply(text: str, ops: list, order: Optional[Callable] = None, comment: Optional[Callable] = None,
          quoted=(), new_style: Optional[str] = '"') -> str:
    """The text with the operations made. `order(path)`: the keys of the section at `path`
    in the example's order, for where a new key goes; `comment(path)`: the example's
    comment for a new key; `quoted`: keys whose strings are double-quoted when new;
    `new_style`: '"' writes new strings quoted (config.yaml), None plain where it can
    (inventory.yaml). EditError if the result would not be exactly the change."""
    try:
        before = load(text)
    except yaml.YAMLError as e:
        raise EditError(f"the file does not parse: {e}") from None
    want = expected(before, ops)
    ed = _Editor(text, order, comment, quoted, new_style)
    for op in _fine(text, ops):
        kind, path = op["op"], list(op["path"])
        if kind == "set":
            ed.set(path, op["value"])
        elif kind == "del":
            ed.delete(path)
        elif kind == "insert":
            ed.insert(path, op.get("index"), op["value"])
        elif kind == "remove":
            ed.remove(path)
    try:
        got = load(ed.text)
    except yaml.YAMLError as e:
        raise EditError(f"the edit would break the file: {e}") from None
    if (got or {}) != (want or {}):
        raise EditError("the edit would not come out exactly as asked")
    return ed.text

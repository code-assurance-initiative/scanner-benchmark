"""Resource boundaries of IaC files, for contract 1.6 resource-scope concepts (taxonomy `matchScope: "resource"`).

A resource-scope concept's defect is a property of a whole IaC resource — usually an ABSENCE (no limits, no probes, no
securityContext, no USER, no HEALTHCHECK) that has no line of its own. For an entry naming such a concept, a result of
it anywhere in the same RESOURCE is on the entry's site. A resource is:

- YAML (`*.yaml`, `*.yml`): one document. Documents are split at a document marker — `---` or `...` at column 0,
  followed by whitespace or the end of the line. YAML 1.2 (production c-forbidden) forbids such a line inside any
  scalar, so an indented `---` in a block scalar, a quoted `"---"` and `----` split nothing. The `---` line starts
  its document; the `...` line ends its own. Lines holding only comments, blanks or directives join the next document
  (or, at the end of the file, the previous one), so a leading comment is part of the first document.
- Dockerfile / Containerfile (`Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, `Containerfile`, `Containerfile.*`):
  one build stage, from its `FROM` to the line before the next `FROM`. The lines before the first `FROM` (parser
  directives, global `ARG`s) belong to every stage: they are the file's own header, not one stage's. Continuation
  lines (after a trailing `\\`) and heredoc bodies (`<<EOF` … `EOF`) are never instructions.
- Terraform / HCL (`*.tf`, `*.hcl`, `*.tfvars`): one top-level construct — from its first line to the line where its
  braces, brackets and parentheses balance again — so a `resource "…" "…" { … }` block with nested blocks is one
  resource. Strings (with `${…}` interpolation, nested strings inside it), `#`, `//` and `/* */` comments and heredocs
  (`<<EOT`, `<<-EOT`) are skipped. Lines outside every construct (comments, blanks) are in no resource.

Any other file is `unsupported` (the line rule applies); a file the source cannot read is `unavailable` (the line rule
applies, and the report says so).

Contract 1.7 adds the ELEMENT boundaries of markup files, for element-scope concepts (taxonomy `matchScope:
"element"`): an element's START TAG, from its `<name` to the `>` that closes it, wherever line breaks fall between its
attributes (`markup_start_tags`). Markup files are `*.html`, `*.htm`, `*.xhtml`, `*.cshtml`, `*.razor`, `*.vue`,
`*.svelte`, `*.jsx`, `*.tsx`; any other file is `unsupported` for the element scope. Standard library only.
"""
import bisect
import os
import re
import subprocess

YAML, DOCKERFILE, HCL, MARKUP = "yaml", "dockerfile", "hcl", "markup"
KIND_NAMES = {YAML: "yaml-document", DOCKERFILE: "dockerfile-stage", HCL: "hcl-block", MARKUP: "markup-start-tag"}
UNAVAILABLE, UNSUPPORTED = "unavailable", "unsupported"
RESOURCE, ELEMENT = "resource", "element"  # the scopes boundaries are read for


def kind_of(path):
    """yaml | dockerfile | hcl, or None for a file type without resource boundaries."""
    name = path.rsplit("/", 1)[-1].lower()
    if name.endswith((".yaml", ".yml")):
        return YAML
    if name in ("dockerfile", "containerfile") or name.startswith(("dockerfile.", "containerfile.")) \
            or name.endswith((".dockerfile", ".containerfile")):
        return DOCKERFILE
    if name.endswith((".tf", ".hcl", ".tfvars")):
        return HCL
    return None


MARKUP_SUFFIXES = (".html", ".htm", ".xhtml", ".cshtml", ".razor", ".vue", ".svelte", ".jsx", ".tsx")


def markup_kind_of(path):
    """markup, or None for a file without element boundaries."""
    return MARKUP if path.rsplit("/", 1)[-1].lower().endswith(MARKUP_SUFFIXES) else None


def kind_for(path, scope=RESOURCE):
    """The boundary kind of `path` for a scope: an IaC kind for "resource", markup for "element"; None: unsupported."""
    return markup_kind_of(path) if scope == ELEMENT else kind_of(path)


# --- YAML ------------------------------------------------------------------------------------------------------------

_MARKER = re.compile(r"^(---|\.\.\.)(?:[ \t]|$)")
_CONTENT_FREE = re.compile(r"^\s*(?:#.*)?$")


def yaml_documents(text):
    """[(first line, last line)] of each document, 1-based and inclusive, covering every line of the file."""
    lines = text.splitlines()
    n = len(lines)
    if n == 0:
        return []
    segs = []  # [start, end, has content]
    cur = [1, 0, False]
    for i, line in enumerate(lines, 1):
        m = _MARKER.match(line)
        if m and m.group(1) == "---":
            if cur[1] >= cur[0]:
                segs.append(cur)
            cur = [i, i, bool(line[3:].split("#", 1)[0].strip())]  # `--- {a: 1}` / `--- |` start with content
            continue
        cur[1] = i
        if m:  # "...": the end of the current document; whatever follows starts a new one
            cur[2] = True
            segs.append(cur)
            cur = [i + 1, i, False]
            continue
        if not cur[2] and not _CONTENT_FREE.match(line) and not line.startswith("%"):
            cur[2] = True
    if cur[1] >= cur[0]:
        segs.append(cur)
    return _merge_content_free(segs, n)


def _merge_content_free(segs, n):
    out = []
    pending = None  # a content-free run waiting for the next document
    for s, e, content in segs:
        if not content:
            pending = pending if pending is not None else s
            continue
        out.append([pending if pending is not None else s, e])
        pending = None
    if pending is not None:
        if out:
            out[-1][1] = n
        else:
            out.append([pending, n])
    return [tuple(x) for x in out]


# --- Dockerfile -----------------------------------------------------------------------------------------------------

_FROM = re.compile(r"^\s*from\s", re.IGNORECASE)
_HEREDOC = re.compile(r"<<(-?)([\"']?)([A-Za-z_][A-Za-z0-9_]*)\2")


def dockerfile_stages(text):
    """([(first line, last line)] of each build stage, (first, last) of the lines before the first FROM or None)."""
    lines = text.splitlines()
    starts = []
    continued = False
    heredocs = []  # delimiters still open, in order
    for i, line in enumerate(lines, 1):
        if heredocs:
            if line.strip() == heredocs[0]:
                heredocs.pop(0)
            continue
        stripped = line.strip()
        if continued:
            # a continuation line is never an instruction (comment lines inside a continuation are skipped too)
            continued = line.rstrip().endswith("\\")
            heredocs += [m.group(3) for m in _HEREDOC.finditer(line)]
            continue
        if stripped.startswith("#") or not stripped:
            continue
        if _FROM.match(line):
            starts.append(i)
        heredocs += [m.group(3) for m in _HEREDOC.finditer(line)]
        continued = line.rstrip().endswith("\\")
    n = len(lines)
    if not starts:
        return ([(1, n)] if n else []), None
    stages = [(s, (starts[k + 1] - 1) if k + 1 < len(starts) else n) for k, s in enumerate(starts)]
    return stages, ((1, starts[0] - 1) if starts[0] > 1 else None)


# --- HCL -------------------------------------------------------------------------------------------------------------

_HCL_HEREDOC = re.compile(r"<<(-?)([A-Za-z_][A-Za-z0-9_]*)")


def hcl_blocks(text):
    """[(first line, last line)] of each top-level construct (a block, or an attribute) of an HCL file."""
    out = []
    depth = 0
    start = None
    line = 1
    i, n = 0, len(text)
    stack = []  # lexical states: "str" (in a string), "tpl" (in ${…} inside a string: counts its own braces)
    tpl_depth = []
    heredoc = None
    while i < n:
        ch = text[i]
        if ch == "\n":
            if heredoc is None and not stack and depth == 0 and start is not None:
                out.append((start, line))
                start = None
            line += 1
            i += 1
            if heredoc is not None:  # a heredoc body: skip whole lines up to the delimiter line
                while i < n:
                    j = text.find("\n", i)
                    j = n if j < 0 else j
                    body = text[i:j]
                    if body.strip() == heredoc:
                        heredoc = None
                        i = j
                        break
                    if j < n:
                        line += 1
                    i = j + 1
            continue
        if stack and stack[-1] == "str":
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                stack.pop()
            elif text.startswith("${", i) or text.startswith("%{", i):
                stack.append("tpl")
                tpl_depth.append(0)
                i += 2
                continue
            i += 1
            continue
        # code (top level or inside a template interpolation)
        if ch == "#" or text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
            continue
        if text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            line += text.count("\n", i, j)
            i = j
            continue
        if ch.isspace():
            i += 1
            continue
        if start is None and not stack:
            start = line
        if ch == '"':
            stack.append("str")
        elif text.startswith("<<", i) and not stack:
            m = _HCL_HEREDOC.match(text, i)
            if m:
                heredoc = m.group(2)
                i = m.end()
                continue
        elif stack and stack[-1] == "tpl":
            if ch == "{":
                tpl_depth[-1] += 1
            elif ch == "}":
                if tpl_depth[-1] == 0:
                    stack.pop()
                    tpl_depth.pop()
                else:
                    tpl_depth[-1] -= 1
        elif ch in "{[(":
            depth += 1
        elif ch in "}])":
            depth = max(0, depth - 1)
        i += 1
    if start is not None:
        out.append((start, line if not text.endswith("\n") else line - 1))
    return out


# --- markup start tags (contract 1.7) -------------------------------------------------------------------------------

_TAG_NAME = re.compile(r"[A-Za-z][\w:.-]*")
_CODE_HOSTED = (".jsx", ".tsx", ".cshtml", ".razor")  # markup inside code: a tag never directly follows an operand
_JSX = (".jsx", ".tsx")
_RAW_TEXT = ("script", "style")  # HTML raw-text elements: their content is not markup
_MAX_TAG = 20000  # a start tag longer than this is not one (an unbalanced quote or brace ran away)


def _tag_end(text, k):
    """The index of the `>` that closes the start tag whose attributes begin at `k`, or None when what began is not a
    start tag (a `<` outside quotes and expressions, or no `>` before the end). Quoted values are skipped, and so are
    `{…}` expressions (JSX; nested braces and the strings inside them) and Razor `@(…)` expressions."""
    n = len(text)
    depth = 0          # braces / Razor parentheses
    closers = []
    i = k
    limit = min(n, k + _MAX_TAG)
    while i < limit:
        ch = text[i]
        if ch in "\"'" or (ch == "`" and depth):
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if (text[j] == "\\" and depth) else 1
            if j >= n:
                return None
            i = j + 1
            continue
        if ch == "{":
            depth += 1
            closers.append("}")
        elif ch == "(" and (depth or (i > 0 and text[i - 1] == "@")):
            depth += 1
            closers.append(")")
        elif depth and ch == closers[-1]:
            depth -= 1
            closers.pop()
        elif not depth:
            if ch == ">":
                return i
            if ch == "<":
                return None
        i += 1
    return None


def markup_start_tags(text, path=""):
    """[(first line, last line)] of every element start tag of a markup file, in order, 1-based and inclusive.
    Comments (`<!-- -->`), declarations and processing instructions are skipped, end tags are not start tags, and the
    content of `<script>` / `<style>` is not markup (outside JSX). In a file where markup is embedded in code (`*.jsx`,
    `*.tsx`, `*.cshtml`, `*.razor`) a `<` directly after an operand (`Map<string>`, `a<b`) opens no tag; everywhere a
    tag name must be followed by whitespace, `/` or `>` (`a < b`, `i <n;` open none)."""
    name = path.rsplit("/", 1)[-1].lower()
    code_hosted, jsx = name.endswith(_CODE_HOSTED), name.endswith(_JSX)
    newlines = [k for k, ch in enumerate(text) if ch == "\n"]

    def line_at(k):
        return bisect.bisect_left(newlines, k) + 1

    out = []
    i, n = 0, len(text)
    lower = None
    while True:
        j = text.find("<", i)
        if j < 0:
            break
        if text.startswith("<!--", j):
            e = text.find("-->", j + 4)
            i = n if e < 0 else e + 3
            continue
        if text.startswith("<!", j) or text.startswith("<?", j):
            e = text.find(">", j)
            i = n if e < 0 else e + 1
            continue
        m = _TAG_NAME.match(text, j + 1)
        if not m:
            i = j + 1
            continue
        if code_hosted:
            b = j - 1
            while b >= 0 and text[b] in " \t":
                b -= 1
            if b >= 0 and (text[b].isalnum() or text[b] in "_$)]"):
                i = j + 1
                continue
        after = m.end()
        if after < n and not (text[after].isspace() or text[after] in "/>"):
            i = j + 1
            continue
        end = _tag_end(text, after)
        if end is None:
            i = j + 1
            continue
        out.append((line_at(j), line_at(end)))
        i = end + 1
        tag = m.group(0).lower()
        if not jsx and tag in _RAW_TEXT and text[end - 1] != "/":
            lower = lower if lower is not None else text.lower()
            c = lower.find("</" + tag, i)
            i = n if c < 0 else c
    return out


# --- boundaries of one file -----------------------------------------------------------------------------------------

class Boundaries:
    """The resources of one file: `segments` [(lo, hi)], and `shared` lines that lie in every segment."""

    def __init__(self, kind, segments, shared=None):
        self.kind = KIND_NAMES[kind]
        self.segments = list(segments)
        self.shared = shared

    def ids_at(self, line):
        if line is None:
            return set()
        if self.shared and self.shared[0] <= line <= self.shared[1]:
            return set(range(len(self.segments)))
        return {k for k, (lo, hi) in enumerate(self.segments) if lo <= line <= hi}

    def ids_over(self, lo, hi):
        out = set()
        for line in range(lo, hi + 1):
            out |= self.ids_at(line)
        return out


def boundaries(path, text, scope=RESOURCE):
    if scope == ELEMENT:
        return Boundaries(MARKUP, markup_start_tags(text, path)) if markup_kind_of(path) else None
    k = kind_of(path)
    if k == YAML:
        return Boundaries(k, yaml_documents(text))
    if k == DOCKERFILE:
        stages, preamble = dockerfile_stages(text)
        return Boundaries(k, stages, preamble)
    if k == HCL:
        return Boundaries(k, hcl_blocks(text))
    return None


class ResourceIndex:
    """Boundaries per repository-relative path and scope ("resource": IaC resources, contract 1.6; "element": markup
    start tags, contract 1.7), read through `source` (path -> text or None) and cached. `get` returns a Boundaries,
    "unsupported" (no boundaries of that scope for this file type) or "unavailable" (no source, or the source cannot
    read the file)."""

    def __init__(self, source):
        self.source = source
        self._cache = {}
        self._text = {}

    def _read(self, path):
        if path not in self._text:
            self._text[path] = self.source(path) if self.source is not None else None
        return self._text[path]

    def get(self, path, scope=RESOURCE):
        if (path, scope) in self._cache:
            return self._cache[(path, scope)]
        if kind_for(path, scope) is None:
            got = UNSUPPORTED
        else:
            text = self._read(path)
            got = UNAVAILABLE if text is None else boundaries(path, text, scope)
        self._cache[(path, scope)] = got
        return got


def _safe(path):
    p = path.replace("\\", "/").lstrip("/")
    parts = p.split("/")
    return None if not p or ".." in parts else p


def dir_source(root):
    """A source reading repository-relative paths from a directory (a materialised unit or the scanned checkout)."""
    def read(path):
        p = _safe(path)
        if p is None:
            return None
        try:
            with open(os.path.join(root, p), encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError:
            return None
    read.description = f"dir {root}"
    return read


def git_source(repo, rev):
    """A source reading repository-relative paths at `rev` (a tag) of a git repository — the unit as it was keyed,
    whatever its work tree holds."""
    def read(path):
        p = _safe(path)
        if p is None:
            return None
        r = subprocess.run(["git", "-C", repo, "show", f"{rev}:{p}"], capture_output=True)
        return r.stdout.decode("utf-8", errors="replace") if r.returncode == 0 else None
    read.description = f"git {repo}@{rev}"
    return read

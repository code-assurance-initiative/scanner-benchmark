"""Path normalisation and the suffix-tolerant path rule.

Same rule as kennel tools/multilang/matching.py: two paths name the same file when they are equal or either is a
`/`-boundary suffix of the other (answer keys are repo-relative; scanners report from whatever root they ran in).
Unlike that file's `lstrip("./")`, only a leading "./" segment is removed here — `lstrip` also eats the dot of
".github/…", which then no longer suffix-matches an absolute ".../.github/…" path.
"""
from urllib.parse import unquote, urlparse


def _strip_dot_segments(s):
    while s.startswith("./"):
        s = s[2:]
    while "/./" in s:
        s = s.replace("/./", "/")
    while "//" in s:
        s = s.replace("//", "/")
    return s


def norm(path, prefixes=()):
    """A `/`-separated path with file:// URIs decoded, backslashes turned, "./" and trailing "/" removed and the
    first matching `prefixes` entry stripped. None stays None."""
    if path is None:
        return None
    s = str(path)
    if s.lower().startswith("file:"):
        u = urlparse(s)
        p = unquote(u.path)
        if u.netloc and u.netloc.lower() != "localhost":
            p = "//" + u.netloc + p  # UNC: file://server/share/x
        if len(p) >= 3 and p[0] == "/" and p[2] == ":":
            p = p[1:]  # file:///C:/x -> C:/x
        s = p
    else:
        s = unquote(s)
    s = _strip_dot_segments(s.replace("\\", "/")).rstrip("/")
    for prefix in prefixes:
        pre = _strip_dot_segments(str(prefix).replace("\\", "/")).rstrip("/")
        if pre and s.startswith(pre + "/"):
            s = s[len(pre) + 1:]
            break
    return s or None


def path_match(a, b):
    """True when `a` and `b` (already normalised) name the same file under the suffix rule."""
    if a is None or b is None:
        return False
    a, b = a.lstrip("/"), b.lstrip("/")
    return a == b or a.endswith("/" + b) or b.endswith("/" + a)

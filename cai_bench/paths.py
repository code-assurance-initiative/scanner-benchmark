"""Path normalisation, repo-relative paths, and the path rules.

Contract 1.4: a result path that can be made REPO-RELATIVE (`repo_relative`) is compared with an entry's path
EXACTLY (`pathMatch: exact`); only a path that cannot (an absolute path under an unknown root, a `../` path, a
basename read out of a message) falls back to the suffix rule below (`pathMatch: suffix`).

The suffix rule:

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


# Absolute checkout roots a scanner commonly reports from, stripped when no configured prefix applies: the
# container mount point of a contained scan. (The checkout directory named after the repository is handled by
# `repo_name`.)
CHECKOUT_ROOTS = ("/src",)


def is_relative(path):
    """A normalised path that names a file relative to some root: no leading `/`, no drive letter, no `..`."""
    if not path:
        return False
    if path.startswith("/") or (len(path) >= 2 and path[1] == ":"):
        return False
    return not (path == ".." or path.startswith("../") or "/../" in path)


def repo_relative(path, prefixes=(), repo_name=None):
    """(path, exact): the path made repository-relative, and whether that succeeded. A relative path is taken as
    relative to the repository root (SARIF: a relative uri without a base is relative to the analysis root, which
    for a benchmark is the repository). An absolute path is made relative by stripping, in order, the first
    matching configured `prefixes` entry, a built-in checkout root (CHECKOUT_ROOTS) or everything up to and
    including the first path segment equal to `repo_name` (the checkout directory, e.g. /tmp/x/<repo>/…). If none
    applies, the normalised path is returned with exact=False and is matched by the suffix rule."""
    s = norm(path)
    if s is None:
        return None, False
    if is_relative(s):
        return s, True
    for prefix in list(prefixes) + list(CHECKOUT_ROOTS):
        pre = _strip_dot_segments(str(prefix).replace("\\", "/")).rstrip("/")
        if pre and s.startswith(pre + "/") and is_relative(s[len(pre) + 1:]):
            return s[len(pre) + 1:], True
    if repo_name:
        seg = "/" + repo_name.strip("/") + "/"
        i = s.find(seg)
        if i >= 0 and is_relative(s[i + len(seg):]):
            return s[i + len(seg):], True
    return s, False


def same_file(result, entry_path):
    """The result's file is the entry's file: exactly, when the result's path is repo-relative (contract 1.4), else
    by the suffix rule."""
    f = result.get("file")
    if f is None or entry_path is None:
        return False
    if result.get("pathExact"):
        return f == entry_path.lstrip("/")
    return path_match(f, entry_path)

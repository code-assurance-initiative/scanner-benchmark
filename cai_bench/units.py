"""Read a benchmark unit's answer key at a registered tag, wherever the unit lives.

The units are held in a TRAINING SET repository (`code-assurance-initiative/training-set-2026`): one git bundle per
unit, `units/<unit>.bundle`, carrying the unit's full history and every tag. A unit can be read from:

- a directory of MATERIALISED units (`<units-dir>/<unit>`, made by the set's `tools/materialize.sh`, or any clone that
  carries the tags);
- the set repository itself (`<set-dir>/units/<unit>.bundle`), read through a temporary bare repository;
- a legacy authoring workspace (`<workspace>/<unit>`, a clone) — how the units were read before the set existed.

`read_key` tries the sources it is given in that order and takes the first that HAS the tag; the bytes must hash to
the registered keySha256 or it raises. Standard library only.
"""
import atexit
import hashlib
import os
import shutil
import subprocess
import tempfile

KEY_PATH = "benchmark/answer-key.json"
SET_NAME = "training-set-2026"

_bundle_repos = {}


class UnitNotFound(LookupError):
    pass


class KeyMismatch(ValueError):
    pass


def default_set_dir(workspace=None):
    """The training-set checkout next to scanner-benchmark (or inside the workspace), if there is one."""
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for cand in filter(None, (os.environ.get("BENCH_SET_DIR"),
                              workspace and os.path.join(workspace, SET_NAME),
                              os.path.join(os.path.dirname(here), SET_NAME))):
        if os.path.isdir(os.path.join(cand, "units")):
            return cand
    return None


def _git_show(git_dir_args, tag):
    p = subprocess.run(["git", *git_dir_args, "show", f"refs/tags/{tag}:{KEY_PATH}"], capture_output=True)
    return p.stdout if p.returncode == 0 else None


def _bundle_repo(bundle):
    repo = _bundle_repos.get(bundle)
    if repo is None:
        tmp = tempfile.mkdtemp(prefix="cai-bench-bundle-")
        atexit.register(shutil.rmtree, tmp, True)
        repo = os.path.join(tmp, "unit.git")
        subprocess.run(["git", "init", "-q", "--bare", repo], check=True, capture_output=True)
        subprocess.run(["git", "-C", repo, "fetch", "-q", bundle, "+refs/tags/*:refs/tags/*"], check=True,
                       capture_output=True)
        _bundle_repos[bundle] = repo
    return repo


def sources(name, units_dir=None, set_dir=None, workspace=None):
    """[(description, git args)] for every place `name` could be read from, in priority order: materialised units,
    the set's bundle, a legacy workspace clone."""
    out = []
    if units_dir and os.path.isdir(os.path.join(units_dir, name)):
        out.append((f"materialised {os.path.join(units_dir, name)}", ("-C", os.path.join(units_dir, name))))
    bundle = set_dir and os.path.join(set_dir, "units", f"{name}.bundle")
    if bundle and os.path.isfile(bundle):
        out.append((f"bundle {bundle}", ("--git-dir", _bundle_repo(bundle))))
    if workspace and os.path.isdir(os.path.join(workspace, name)):
        out.append((f"workspace {os.path.join(workspace, name)}", ("-C", os.path.join(workspace, name))))
    return out


def read_key(name, tag, key_sha256, units_dir=None, set_dir=None, workspace=None):
    """The answer-key bytes of unit `name` at `tag`, sha256-checked against `key_sha256`.

    Raises UnitNotFound when no source has the tag, KeyMismatch when the first source that has it holds other bytes.
    """
    tried = []
    for desc, args in sources(name, units_dir, set_dir, workspace):
        raw = _git_show(args, tag)
        if raw is None:
            tried.append(desc)
            continue
        got = hashlib.sha256(raw).hexdigest()
        if got != key_sha256:
            raise KeyMismatch(f"{name}: key at {tag} from {desc} has sha256 {got}, registered {key_sha256}")
        return raw
    raise UnitNotFound(f"{name}: tag {tag} not found (tried: {', '.join(tried) or 'no source given/existing'}); "
                       f"materialise the unit from the training set or pass --units-dir/--set-dir")


def files_source(name, tag, units_dir=None, set_dir=None, workspace=None):
    """Contract 1.6: a source (resources.git_source) reading unit `name`'s files at `tag` from the first source that
    has the tag — the files the key was written against, for resource boundaries — or None when none has it."""
    from .resources import git_source
    for desc, args in sources(name, units_dir, set_dir, workspace):
        if subprocess.run(["git", *args, "rev-parse", "-q", "--verify", f"refs/tags/{tag}"],
                          capture_output=True).returncode == 0:
            src = git_source(args[1], f"refs/tags/{tag}")
            src.description = f"{desc.split()[0]} {name} @ {tag}"  # no machine-local path in a recorded report
            return src
    return None

"""cai_bench.units: answer keys read from the training set's bundles, from materialised units, or from a legacy clone —
always sha256-checked. The units' GitHub repositories and the authoring clones are retired; nothing that scores or
builds the matrix may depend on them."""
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import unittest

from cai_bench import units
from cai_bench.units import KeyMismatch, UnitNotFound, default_set_dir, read_key

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def git(repo, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t", GIT_COMMITTER_NAME="t",
               GIT_COMMITTER_EMAIL="t@t")
    return subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True, env=env).stdout.decode().strip()


def sha(b):
    return hashlib.sha256(b).hexdigest()


class Sources(unittest.TestCase):
    """A unit `bench-x` with key v1 at tag v1.0.0 and key v2 at tag v1.1.0, bundled into a fake set."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="test-units-")
        cls.addClassCleanup(shutil.rmtree, cls.tmp)
        src = os.path.join(cls.tmp, "authoring", "bench-x")
        os.makedirs(os.path.join(src, "benchmark"))
        git(src, "init", "-q", "-b", "main")
        cls.keys = {}
        for tag, ver in (("v1.0.0", "1.0.0"), ("v1.1.0", "1.1.0")):
            raw = json.dumps({"keyVersion": ver, "entries": []}).encode()
            with open(os.path.join(src, "benchmark", "answer-key.json"), "wb") as f:
                f.write(raw)
            git(src, "add", "-A")
            git(src, "commit", "-q", "-m", ver)
            git(src, "tag", "-a", tag, "-m", tag)
            cls.keys[tag] = raw
        cls.workspace = os.path.join(cls.tmp, "authoring")
        cls.set_dir = os.path.join(cls.tmp, "set")
        os.makedirs(os.path.join(cls.set_dir, "units"))
        git(src, "bundle", "create", os.path.join(cls.set_dir, "units", "bench-x.bundle"), "--all")
        cls.units_dir = os.path.join(cls.tmp, "materialised")
        os.makedirs(cls.units_dir)
        subprocess.run(["git", "clone", "-q", os.path.join(cls.set_dir, "units", "bench-x.bundle"),
                        os.path.join(cls.units_dir, "bench-x")], check=True, capture_output=True)

    def test_reads_every_tag_from_the_bundle_alone(self):
        for tag, raw in self.keys.items():
            self.assertEqual(read_key("bench-x", tag, sha(raw), set_dir=self.set_dir), raw)

    def test_reads_from_materialised_units_alone(self):
        for tag, raw in self.keys.items():
            self.assertEqual(read_key("bench-x", tag, sha(raw), units_dir=self.units_dir), raw)

    def test_reads_from_a_legacy_workspace_clone(self):
        raw = self.keys["v1.1.0"]
        self.assertEqual(read_key("bench-x", "v1.1.0", sha(raw), workspace=self.workspace), raw)

    def test_priority_is_materialised_then_bundle_then_workspace(self):
        got = [d.split()[0] for d, _ in units.sources("bench-x", self.units_dir, self.set_dir, self.workspace)]
        self.assertEqual(got, ["materialised", "bundle", "workspace"])

    def test_a_hash_that_differs_from_the_registry_raises(self):
        with self.assertRaises(KeyMismatch):
            read_key("bench-x", "v1.0.0", sha(self.keys["v1.1.0"]), set_dir=self.set_dir)

    def test_an_unknown_tag_or_unit_raises_not_found(self):
        with self.assertRaises(UnitNotFound):
            read_key("bench-x", "v9.0.0", "0" * 64, set_dir=self.set_dir, units_dir=self.units_dir)
        with self.assertRaises(UnitNotFound):
            read_key("bench-y", "v1.0.0", "0" * 64, set_dir=self.set_dir, workspace=self.workspace)

    def test_nothing_given_is_not_found_not_a_crash(self):
        with self.assertRaises(UnitNotFound):
            read_key("bench-x", "v1.0.0", sha(self.keys["v1.0.0"]))


class RealRegistryFromTheSet(unittest.TestCase):
    """Every registered version of every unit resolves from the training set's bundles ALONE (no clone, no GitHub) —
    the path build.py, rescore.py and baseline.py take once the unit repositories are gone."""

    def test_every_registry_entry_reads_from_the_bundles(self):
        set_dir = default_set_dir()
        if not set_dir:
            self.skipTest("no training-set-2026 checkout next to scanner-benchmark (or $BENCH_SET_DIR)")
        with open(os.path.join(ROOT, "registry.json"), encoding="utf-8") as f:
            reg = json.load(f)
        for e in reg["repos"]:
            name = e["repo"].split("/")[1]
            self.assertEqual(e["source"], {"set": "code-assurance-initiative/training-set-2026",
                                           "bundle": f"units/{name}.bundle"})
            self.assertTrue(os.path.isfile(os.path.join(set_dir, e["source"]["bundle"])), e["source"]["bundle"])
            raw = read_key(name, e["tag"], e["keySha256"], set_dir=set_dir)
            self.assertEqual(json.loads(raw)["keyVersion"], e["tag"].lstrip("v"))


if __name__ == "__main__":
    unittest.main()

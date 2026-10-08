"""Contract 1.6: location equivalence — resource-scope concepts (taxonomy `matchScope: "resource"`).

An IaC concept whose defect can be an ABSENCE in a resource (no limits, no probes, no securityContext, no USER, no
HEALTHCHECK …) has no line of its own: a scanner reports it at the resource or container header, a key at the field
it would go to. For an entry naming such a concept, a result of the concept anywhere in the SAME resource is on the
entry's site: one YAML document, one Dockerfile build stage, one top-level HCL block. The scorer reads the boundaries
from the unit's files (`source`); without them the line rule applies and the entry says `resource-unavailable`."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest

from cai_bench import CONTRACT_VERSION
from cai_bench.keyfile import load_json
from cai_bench.mapping import Mapping
from cai_bench.resources import (ResourceIndex, dir_source, dockerfile_stages, git_source, hcl_blocks, kind_of,
                                 yaml_documents)
from cai_bench.sarif import read_results
from cai_bench.scoring import render, score as score_report
from cai_bench.taxonomy import file_scope_concepts, resource_scope_concepts
from tests.helpers import MAPPING_DOC, clean, entry, key, mf, mnf, outcomes, res, sarif

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RESOURCE_SCOPE = {
    "container-runs-as-root", "container-privilege-escalation-allowed", "container-excess-capabilities",
    "container-writable-root-filesystem", "container-confinement-profile-unset", "container-security-context-missing",
    "container-missing-resource-limits", "container-missing-resource-requests", "missing-health-probes",
    "missing-image-healthcheck", "automounted-service-account-token"}

M = copy.deepcopy(MAPPING_DOC)
M["concepts"].update({
    "missing-health-probes": {"rules": [{"rule": "^D31$", "messages": ["^NoProbes:"]}], "dimensions": ["D31"]},
    "container-missing-resource-limits": {"rules": [{"rule": "^D31$", "messages": ["^NoLimits:"]}],
                                          "dimensions": ["D31"]},
    "container-runs-as-root": {"rules": [{"rule": "^D31$", "messages": ["^Root:"]}], "dimensions": ["D31"]},
    "missing-image-healthcheck": {"rules": [{"rule": "^D31$", "messages": ["^NoHealthcheck:"]}],
                                  "dimensions": ["D31"]},
    "privileged-container": {"rules": [{"rule": "^D31$", "messages": ["^Privileged:"]}], "dimensions": ["D31"]},
})
PROBES, LIMITS, ROOT_, HC, PRIV = ("NoProbes: no liveness probe", "NoLimits: no memory limit", "Root: runs as root",
                                   "NoHealthcheck: no HEALTHCHECK", "Privileged: privileged: true")

# lines:            1          2                   3                   4                       5
DEPLOY = "\n".join([
    "# reminders and api",                    # 1  leading comment: belongs to the first document
    "---",                                    # 2
    "apiVersion: v1",                         # 3
    "kind: ConfigMap",                        # 4
    "data:",                                  # 5
    "  seed.yaml: |",                         # 6
    "    ---",                                # 7  inside a block scalar: not a document marker
    "    a: 1",                               # 8
    "  note: \"--- not a marker\"",           # 9
    "---  # the deployment",                  # 10 a marker with a comment
    "apiVersion: apps/v1",                    # 11
    "kind: Deployment",                       # 12
    "spec:",                                  # 13
    "  template:",                            # 14
    "    spec:",                              # 15
    "      containers:",                      # 16
    "        - name: reminders",              # 17
    "          image: r:1.0",                 # 18
    "          ports:",                       # 19
    "            - containerPort: 8080",      # 20
    "          env:",                         # 21
    "            - name: A",                  # 22
    "              value: b",                 # 23
    "          volumeMounts: []",             # 24
    "          resources: {}",                # 25
    "----",                                   # 26 four dashes: not a marker, still the deployment
    "---",                                    # 27
    "apiVersion: apps/v1",                    # 28
    "kind: Deployment",                       # 29
    "metadata: {name: api}",                  # 30
    "spec:",                                  # 31
    "  template:",                            # 32
    "    spec:",                              # 33
    "      containers:",                      # 34
    "        - name: api",                    # 35
    "          image: a:1.0",                 # 36
    "          securityContext: {privileged: true}",  # 37
    "...",                                    # 38 document end: still the api deployment
    "# trailing comment",                     # 39 content-free tail: belongs to the last document
    ""])

DOCKERFILE = "\n".join([
    "# syntax=docker/dockerfile:1",           # 1  preamble: shared by every stage
    "ARG SDK=8.0",                            # 2
    "FROM mcr.microsoft.com/dotnet/sdk:${SDK} AS build",  # 3
    "WORKDIR /src",                           # 4
    "RUN apt-get install -y curl \\",         # 5
    "    from the mirror",                    # 6  a continuation line, not an instruction
    "RUN <<EOF",                              # 7
    "FROM inside a heredoc is not a stage",   # 8
    "EOF",                                    # 9
    "from mcr.microsoft.com/dotnet/aspnet:8.0 as final",  # 10 instructions are case-insensitive
    "COPY --from=build /out /app",            # 11
    "EXPOSE 8080",                            # 12
    "ENV A=1",                                # 13
    "ENV B=2",                                # 14
    "ENV C=3",                                # 15
    "ENV D=4",                                # 16
    "ENTRYPOINT [\"dotnet\", \"App.dll\"]",   # 17
    ""])

HCL = "\n".join([
    "# ECS task with a container definition",            # 1
    "variable \"image\" { default = \"x\" }",            # 2  a one-line block
    "",                                                  # 3
    "resource \"aws_ecs_task_definition\" \"app\" {",    # 4
    "  family = \"app\"",                                # 5
    "  container_definitions = jsonencode([{",           # 6
    "    name  = \"app\"",                               # 7
    "    image = \"${var.image}:${lookup(var.tags, \"}\", \"1\")}\"",  # 8 braces inside strings/interpolation
    "    # a comment with an unbalanced {",              # 9
    "    /* and a block comment } */",                   # 10
    "  }])",                                             # 11
    "  volume {",                                        # 12
    "    name = \"data\"",                               # 13
    "    efs_volume_configuration {",                    # 14
    "      file_system_id = \"fs-1\"",                   # 15
    "    }",                                             # 16
    "  }",                                               # 17
    "  user_data = <<-EOT",                              # 18
    "    { not a brace {",                               # 19
    "    EOT",                                           # 20
    "}",                                                 # 21
    "",                                                  # 22
    "resource \"aws_ecs_service\" \"app\" {",            # 23
    "  name = \"app\"",                                  # 24
    "}",                                                 # 25
    ""])

FILES = {"deploy/k8s/app.yaml": DEPLOY, "src/App/Dockerfile": DOCKERFILE, "infra/ecs.tf": HCL,
         "deploy/values.json": "{\n  \"a\": 1\n}\n"}


def source(path):
    return FILES.get(path)


def score(k, *results, mapping=M, contract=None, src=source):
    return score_report(json.loads(json.dumps(k)), read_results(sarif(*results)), Mapping(mapping), None,
                        contract=contract, source=src)


Y = "deploy/k8s/app.yaml"


class Taxonomy(unittest.TestCase):
    def test_the_resource_scope_concepts(self):
        self.assertEqual(resource_scope_concepts(), frozenset(RESOURCE_SCOPE))

    def test_file_scope_is_unchanged_and_disjoint(self):
        self.assertEqual(len(file_scope_concepts()), 12)
        self.assertFalse(file_scope_concepts() & resource_scope_concepts())

    def test_taxonomy_json_scopes(self):
        tax = load_json(os.path.join(ROOT, "taxonomy.json"))
        self.assertEqual({c.get("matchScope") for c in tax["concepts"]}, {None, "file", "resource", "element", "group"})
        self.assertEqual({c["id"] for c in tax["concepts"] if c.get("matchScope") == "resource"}, RESOURCE_SCOPE)

    def test_line_valued_iac_concepts_stay_line_based(self):
        for c in ("privileged-container", "host-namespace-sharing", "host-path-mount", "overly-permissive-rbac",
                  "mutable-image-reference", "image-not-from-allowed-registry", "iac-misconfiguration",
                  "container-excessive-privilege"):
            self.assertNotIn(c, resource_scope_concepts(), c)

    def test_an_explicit_taxonomy_decides(self):
        tax = {"concepts": [{"id": "x", "matchScope": "resource"}, {"id": "y", "matchScope": "file"}, {"id": "z"}]}
        self.assertEqual(resource_scope_concepts(tax), frozenset({"x"}))
        self.assertEqual(file_scope_concepts(tax), frozenset({"y"}))
        with self.assertRaises(ValueError):
            resource_scope_concepts({"concepts": [{"id": "x", "matchScope": "document"}]})


class Boundaries(unittest.TestCase):
    def test_kinds(self):
        for p, k in (("a/b.yaml", "yaml"), ("a/b.YML", "yaml"), ("Dockerfile", "dockerfile"),
                     ("src/x/Dockerfile.prod", "dockerfile"), ("api.Dockerfile", "dockerfile"),
                     ("Containerfile", "dockerfile"), ("infra/main.tf", "hcl"), ("x.hcl", "hcl"),
                     ("x.tfvars", "hcl"), ("x.tf.json", None), ("values.json", None), ("App.cs", None)):
            self.assertEqual(kind_of(p), k, p)

    def test_yaml_multi_document_with_a_block_scalar_and_quoted_dashes(self):
        # the leading comment joins the first document; the indented "---" in the block scalar, the quoted one and
        # "----" split nothing; "..." ends a document and the content-free tail joins the last one
        self.assertEqual(yaml_documents(DEPLOY), [(1, 9), (10, 26), (27, 39)])

    def test_yaml_single_document(self):
        self.assertEqual(yaml_documents("a: 1\nb: 2\n"), [(1, 2)])
        self.assertEqual(yaml_documents("---\na: 1\n"), [(1, 2)])

    def test_yaml_content_free_documents_join_a_neighbour(self):
        self.assertEqual(yaml_documents("a: 1\n---\n# only a comment\n"), [(1, 3)])
        self.assertEqual(yaml_documents("--- {a: 1}\n---\nb: 2\n"), [(1, 1), (2, 3)])

    def test_yaml_document_after_an_end_marker_without_a_start_marker(self):
        self.assertEqual(yaml_documents("a: 1\n...\nb: 2\n"), [(1, 2), (3, 3)])

    def test_yaml_top_level_block_scalar_ends_at_a_marker(self):
        # YAML 1.2 (c-forbidden): a column-0 document marker ends any scalar, block scalars included
        self.assertEqual(yaml_documents("--- |\n  text\n---\nb: 2\n"), [(1, 2), (3, 4)])

    def test_dockerfile_stages(self):
        stages, preamble = dockerfile_stages(DOCKERFILE)
        self.assertEqual(stages, [(3, 9), (10, 17)])
        self.assertEqual(preamble, (1, 2))

    def test_dockerfile_single_stage(self):
        self.assertEqual(dockerfile_stages("FROM alpine\nRUN true\n"), ([(1, 2)], None))

    def test_hcl_blocks(self):
        self.assertEqual(hcl_blocks(HCL), [(2, 2), (4, 21), (23, 25)])

    def test_hcl_nested_braces_on_one_line(self):
        self.assertEqual(hcl_blocks('a "x" { b { c = { d = 1 } } }\nz "y" {\n}\n'), [(1, 1), (2, 3)])

    def test_index_ids(self):
        idx = ResourceIndex(source)
        b = idx.get(Y)
        self.assertEqual(b.kind, "yaml-document")
        self.assertEqual(b.ids_over(20, 22), {1})
        self.assertEqual(b.ids_over(9, 10), {0, 1})
        self.assertEqual(b.ids_over(500, 500), set())
        d = idx.get("src/App/Dockerfile")
        self.assertEqual(d.ids_over(1, 1), {0, 1})  # the preamble is in every stage
        self.assertEqual(idx.get("deploy/values.json"), "unsupported")
        self.assertEqual(idx.get("missing.yaml"), "unavailable")
        self.assertEqual(ResourceIndex(None).get(Y), "unavailable")

    def test_dir_and_git_sources(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "deploy"))
            with open(os.path.join(d, "deploy", "a.yaml"), "w") as f:
                f.write("a: 1\n")
            self.assertEqual(dir_source(d)("deploy/a.yaml"), "a: 1\n")
            with open(os.path.join(os.path.dirname(d), os.path.basename(d) + "-outside.yaml"), "w") as f:
                f.write("outside\n")
            try:  # a path leaving the unit is never read
                self.assertIsNone(dir_source(d)(f"../{os.path.basename(d)}-outside.yaml"))
            finally:
                os.remove(os.path.join(os.path.dirname(d), os.path.basename(d) + "-outside.yaml"))
            self.assertIsNone(dir_source(d)("deploy/none.yaml"))
            g = ["git", "-C", d]
            subprocess.run(g + ["init", "-q"], check=True)
            subprocess.run(g + ["add", "."], check=True)
            subprocess.run(g + ["-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x"], check=True)
            subprocess.run(g + ["tag", "v1.0.0"], check=True)
            with open(os.path.join(d, "deploy", "a.yaml"), "w") as f:
                f.write("changed\n")
            self.assertEqual(git_source(d, "v1.0.0")("deploy/a.yaml"), "a: 1\n")  # the tag, not the work tree
            self.assertIsNone(git_source(d, "v1.0.0")("deploy/none.yaml"))


class ResourceScope(unittest.TestCase):
    K = key(mf("PRB", "missing-health-probes", Y, [17, 20]))

    def test_a_result_at_the_resource_header_is_a_hit(self):
        for line in (11, 12, 13, 26):  # anywhere in the deployment's document, outside the ±3 tolerance
            r = score(self.K, res("D31", Y, line, PROBES))
            self.assertEqual(entry(r, "PRB")["outcome"], "TP", line)
            self.assertEqual(r["results"][0]["matchScope"], "resource", line)

    def test_another_document_of_the_file_is_not_the_same_resource(self):
        for line in (3, 9, 28, 35):
            r = score(self.K, res("D31", Y, line, PROBES))
            self.assertEqual(entry(r, "PRB")["outcome"], "FN", line)

    def test_under_contract_1_5_the_line_still_decides(self):
        r = score(self.K, res("D31", Y, 11, PROBES), contract="1.5")
        self.assertEqual(entry(r, "PRB")["outcome"], "FN")
        self.assertNotIn("resourceScopeMatches", r["summary"])

    def test_a_line_valued_concept_keeps_the_line_rule(self):
        r = score(key(mf("PRV", "privileged-container", Y, [37, 37])), res("D31", Y, 28, PRIV))
        self.assertEqual(entry(r, "PRV")["outcome"], "FN")

    def test_a_result_on_the_lines_is_preferred_and_a_second_is_redundant(self):
        r = score(self.K, res("D31", Y, 11, PROBES), res("D31", Y, 17, PROBES))
        self.assertEqual(outcomes(r), [(0, "redundant", "PRB"), (1, "tp", "PRB")])

    def test_two_resources_two_plants_each_found_by_its_own_header(self):
        k = key(mf("P1", "missing-health-probes", Y, [17, 17]), mf("P2", "missing-health-probes", Y, [35, 35]))
        r = score(k, res("D31", Y, 28, PROBES), res("D31", Y, 11, PROBES))
        self.assertEqual(outcomes(r), [(0, "tp", "P2"), (1, "tp", "P1")])

    def test_symmetric_at_a_trap(self):
        k = key(mnf("T", "container-missing-resource-limits", Y, [35, 36]))
        r = score(k, res("D31", Y, 28, LIMITS))
        self.assertEqual(outcomes(r), [(0, "trap-fp", "T")])
        r = score(k, res("D31", Y, 12, LIMITS))  # the other deployment: not the trap
        self.assertEqual(entry(r, "T")["outcome"], "TN")

    def test_symmetric_in_a_clean_region_naming_the_concept(self):
        r = score(key(clean("C", ["container-runs-as-root"], Y, [35, 37])), res("D31", Y, 29, ROOT_))
        self.assertEqual(entry(r, "C")["outcome"], "FP")

    def test_a_wildcard_clean_region_keeps_its_lines(self):
        r = score(key(clean("C", "*", Y, [35, 37]), mf("X", "sql-injection", "src/Z.cs", [1, 1])),
                  res("D31", Y, 29, ROOT_))
        self.assertEqual(entry(r, "C")["outcome"], "TN")

    def test_located_entry_shields_its_resource_from_a_repository_level_entry(self):
        k = key(mf("P", "missing-health-probes", Y, [17, 17]), mnf("REPO", "missing-health-probes"))
        r = score(k, res("D31", Y, 11, PROBES), res("D31", Y, 12, PROBES), res("D31", Y, 30, PROBES))
        self.assertEqual(outcomes(r), [(0, "tp", "P"), (1, "redundant", "P"), (2, "trap-fp", "REPO")])

    def test_without_the_files_the_line_rule_applies_and_says_so(self):
        r = score(self.K, res("D31", Y, 11, PROBES), src=None)
        self.assertEqual(entry(r, "PRB")["outcome"], "FN")
        self.assertEqual(entry(r, "PRB")["matchScope"], "resource-unavailable")
        self.assertEqual(r["summary"]["resourceScope"]["unavailable"], 1)
        self.assertIn("resource-unavailable", render(r))

    def test_an_unsupported_file_type_keeps_the_line_rule(self):
        k = key(mf("J", "missing-health-probes", "deploy/values.json", [3, 3]))
        r = score(k, res("D31", "deploy/values.json", 1, PROBES))
        self.assertEqual(entry(r, "J")["outcome"], "TP")  # within ±3 anyway
        k = key(mf("J", "missing-health-probes", "deploy/values.json", [9, 9]))
        r = score(k, res("D31", "deploy/values.json", 1, PROBES))
        self.assertEqual(entry(r, "J")["outcome"], "FN")
        self.assertEqual(entry(r, "J")["matchScope"], "resource-unsupported")

    def test_entry_row_states_the_resource_kind(self):
        r = score(self.K, res("D31", Y, 11, PROBES))
        self.assertEqual(entry(r, "PRB")["matchScope"], "resource")
        self.assertEqual(entry(r, "PRB")["resourceKind"], "yaml-document")
        self.assertEqual(r["summary"]["resourceScopeMatches"], 1)
        self.assertIn("resource-scope", render(r))

    def test_per_dimension_rows_use_the_rule_too(self):
        r = score(self.K, res("D31", Y, 11, PROBES))
        self.assertEqual(r["dimensions"]["D31"]["tp"], 1)
        r = score(self.K, res("D31", Y, 11, PROBES), contract="1.5")
        self.assertEqual(r["dimensions"]["D31"]["tp"], 0)

    def test_dockerfile_final_stage(self):
        D = "src/App/Dockerfile"
        k = key(mf("HC", "missing-image-healthcheck", D, [17, 17]))
        self.assertEqual(entry(score(k, res("D31", D, 10, HC)), "HC")["outcome"], "TP")  # the final FROM line
        self.assertEqual(entry(score(k, res("D31", D, 1, HC)), "HC")["outcome"], "TP")   # the shared preamble
        self.assertEqual(entry(score(k, res("D31", D, 4, HC)), "HC")["outcome"], "FN")   # the build stage

    def test_dockerfile_build_stage_trap(self):
        D = "src/App/Dockerfile"
        k = key(mnf("T", "container-runs-as-root", D, [4, 4]), mf("P", "container-runs-as-root", D, [17, 17]))
        r = score(k, res("D31", D, 8, ROOT_), res("D31", D, 10, ROOT_))
        self.assertEqual(outcomes(r), [(0, "trap-fp", "T"), (1, "tp", "P")])

    def test_hcl_enclosing_block(self):
        T = "infra/ecs.tf"
        k = key(mf("L", "container-missing-resource-limits", T, [15, 15]))
        self.assertEqual(entry(score(k, res("D31", T, 4, LIMITS)), "L")["outcome"], "TP")
        self.assertEqual(entry(score(k, res("D31", T, 21, LIMITS)), "L")["outcome"], "TP")
        self.assertEqual(entry(score(k, res("D31", T, 23, LIMITS)), "L")["outcome"], "FN")  # the next block
        self.assertEqual(entry(score(k, res("D31", T, 2, LIMITS)), "L")["outcome"], "FN")   # the variable


class Cli(unittest.TestCase):
    def test_repo_dir(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "repo", "deploy", "k8s"))
            with open(os.path.join(d, "repo", Y), "w") as f:
                f.write(DEPLOY)
            paths = {}
            for name, doc in (("key", key(mf("PRB", "missing-health-probes", Y, [17, 20]))),
                              ("sarif", sarif(res("D31", Y, 11, PROBES))), ("mapping", M)):
                paths[name] = os.path.join(d, name + ".json")
                with open(paths[name], "w") as f:
                    json.dump(doc, f)

            def run(*extra):
                p = subprocess.run([sys.executable, "-m", "cai_bench", "score", "--key", paths["key"], "--sarif",
                                    paths["sarif"], "--mapping", paths["mapping"], "--json",
                                    os.path.join(d, "out.json"), *extra], cwd=ROOT, capture_output=True, text=True)
                self.assertEqual(p.returncode, 0, p.stderr)
                with open(os.path.join(d, "out.json")) as f:
                    return json.load(f)

            out = run("--repo-dir", os.path.join(d, "repo"))
            self.assertEqual(entry(out, "PRB")["outcome"], "TP")
            self.assertEqual(out["harness"]["contract"], CONTRACT_VERSION)
            out = run()
            self.assertEqual(entry(out, "PRB")["outcome"], "FN")
            self.assertEqual(entry(out, "PRB")["matchScope"], "resource-unavailable")


if __name__ == "__main__":
    unittest.main()

"""Build mappings/cai-reference.json from the CAI reference implementation's own generated mapping.

    dotnet Cai.Reference.dll mapping --taxonomy taxonomy.json --out /tmp/cai-reference.generated.json
    python3 mappings/cai-reference-build/build.py /tmp/cai-reference.generated.json [--check]

The reference implementation (github.com/code-assurance-initiative/reference-implementation) names every SARIF rule
after the taxonomy concept it reports, so its generated mapping is one exact-ruleId rule per concept plus the concepts
it does not detect (`unmapped`). It declares no `parent`: the generator lists the umbrellas `container-excessive-
privilege` and `iac-misconfiguration` as unmapped with the reason "umbrella: this engine emits the precise child
concepts", and maps `visual-and-motion-safety` while also emitting its children `focus-outline-removed` and
`motion-without-reduced-motion` separately. Contract 1.3 says a mapping's `parent` should mirror the taxonomy's, and
the harness reads umbrellas from the mapping only — without it a key entry naming an umbrella (a plant, a trap, or a
clean region listing it) never sees the children's results, which is neither the engine's stated intent nor what the
Watchdog mapping gets. This step adds exactly the taxonomy's `parent` to every child concept and changes nothing else
(rules, dimensions, unmapped and their reasons stay as generated). `--check` exits 1 when the committed mapping is not
the build of the given generated file.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(ROOT, "mappings", "cai-reference.json")
NOTE = ("Parents: `parent` mirrors taxonomy.json on every child concept (mappings/cai-reference-build/build.py; "
        "contract 1.3) — the generated mapping declares none, although the engine reports the umbrellas through their "
        "precise children. Nothing else differs from the generated file.")


def build(generated, taxonomy):
    parents = {c["id"]: c["parent"] for c in taxonomy["concepts"] if c.get("parent")}
    out = json.loads(json.dumps(generated))
    for c, spec in out["concepts"].items():
        if c in parents:
            if parents[c] not in out["concepts"]:
                raise SystemExit(f"{c}: parent {parents[c]} is not a concept of the generated mapping")
            spec["parent"] = parents[c]
    out["notes"] = (out.get("notes", "") + " " + NOTE).strip()
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("generated", help="output of `cai-ref mapping --taxonomy taxonomy.json --out …`")
    ap.add_argument("--taxonomy", default=os.path.join(ROOT, "taxonomy.json"))
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    with open(a.generated, encoding="utf-8") as f:
        generated = json.load(f)
    with open(a.taxonomy, encoding="utf-8") as f:
        taxonomy = json.load(f)
    text = json.dumps(build(generated, taxonomy), indent=2) + "\n"
    if a.check:
        with open(a.out, encoding="utf-8") as f:
            same = f.read() == text
        print("up to date" if same else f"{a.out} is stale: rebuild it")
        return 0 if same else 1
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"wrote {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

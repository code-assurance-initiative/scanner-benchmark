#!/usr/bin/env python3
"""Builds taxonomy.json, mappings/watchdog.json and coverage/matrix.json for the scanner-benchmark harness
from the kennel engine sources (read-only) plus the curated tables in concepts.py / dims.py."""
import json, os, re, sys
from collections import OrderedDict, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from concepts import C
from dims import D, PHASE, CB, TB, CS

KENNEL = os.environ.get("WATCHDOG_SOURCE", "/home/jimmy/RiderProjects/kennel.canine.dev")  # the Watchdog engine checkout (read only)
OUT = os.path.dirname(os.path.dirname(HERE))  # this repository

cat = json.load(open(f"{KENNEL}/engine/rubrics/rubric-catalog-snapshot.json"))
assert cat["rubricVersion"] == "rubric-2026.10.1", cat["rubricVersion"]
dims = cat["dimensions"]
assert len(dims) == 165, len(dims)
lenses = {l["key"]: l["label"] for l in cat["lenses"]}
langm = {x["Id"]: x for x in json.load(open(f"{KENNEL}/engine/docs/dimension-language-matrix.json"))["Dimensions"]}

def cs_list(path, name):
    s = open(path, encoding="utf-8-sig").read()
    m = re.search(name + r"\s*=\s*(?:new\(StringComparer\.OrdinalIgnoreCase\)|)\s*[\[{](.*?)[\]}];", s, re.S)
    return set(re.findall(r'"([A-Z]+[0-9]+)"', m.group(1)))

ed_path = f"{KENNEL}/engine/src/Core/Edition/DimensionEditions.cs"
editions = {}
for grp in ["Included", "WithheldCommercial", "WithheldNotSelfSufficient", "WithheldNoStandaloneMeaning"]:
    for i in cs_list(ed_path, grp):
        assert i not in editions
        editions[i] = grp
ap_path = f"{KENNEL}/engine/src/CodeHealth.Core/Scoring/AbsencePolicy.cs"
clean_scan = cs_list(ap_path, "CleanScanIds")
evidence_req = cs_list(ap_path, "EvidenceRequiredIds")
sampled_llm = cs_list(ap_path, "SampledLlmIds")
reward = cs_list(ap_path, "RewardLeaningIds")

meth_src = open(f"{KENNEL}/engine/src/CodeHealth.Reporting/Dimensions/DimensionMethods.cs", encoding="utf-8-sig").read()
methods = {}
for m in re.finditer(r'\["([A-Z0-9]+)"\]\s*=\s*((?:"(?:[^"\\]|\\.)*"\s*\+?\s*)+)', meth_src):
    txt = "".join(re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(2)))
    txt = re.sub(r"\\u([0-9a-fA-F]{4})", lambda u: chr(int(u.group(1), 16)), txt).replace('\\"', '"')
    methods[m.group(1)] = txt

concept_ids = [c["id"] for c in C]
assert len(concept_ids) == len(set(concept_ids)), "duplicate concept id"
for cid in concept_ids:
    assert re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", cid), cid
    assert "watchdog" not in cid

# ---------------- taxonomy.json ----------------
used = set()
for d in D.values():
    used.update(d["c"])
missing = used - set(concept_ids)
assert not missing, missing
unused = set(concept_ids) - used
assert not unused, unused
taxonomy = OrderedDict(version="1.0", concepts=C)
for c in C:
    text = (c["id"] + " " + c["title"] + " " + c["description"]).lower()
    for bad in ("watchdog", "codehealth", "canine", "kennel"):
        assert bad not in text, (c["id"], bad)

# ---------------- mappings/watchdog.json ----------------
by_concept = defaultdict(list)
order = [x["id"] for x in dims]
for did in order:
    for cid in D[did]["c"]:
        by_concept[cid].append(did)

def rule_for(ds):
    return "^(?:" + "|".join(ds) + ")$"

D13_TYPES = {
    "hardcoded-credential": ["aws-access-key", "gcp-api-key", "gcp-oauth-client-secret", "supabase-secret-key", "supabase-service-role-key", "slack-token", "github-token", "jwt", "high-entropy-secret", "azure-devops-pat", "http-cookie-credential", "http-authorization-credential", "credential-file"],
    "hardcoded-password": ["hardcoded-credential", "http-basic-credential", "password-hash-credential"],
    "hardcoded-cryptographic-key": ["signing-key", "hardcoded-crypto-key", "crypto-key-passphrase"],
    "committed-private-key": ["private-key", "private-key-blob", "private-key-store"],
}
D28_RULES = {
    "hardcoded-credential": ["generic-api-key", "aws-access-token", "aws-secret-key", "github-pat", "github-fine-grained-pat", "slack-[a-z-]+", "jwt", "gcp-api-key", "gcp-oauth-client-secret", "supabase-secret-key", "supabase-service-role-key", "stripe-access-token", "http-cookie-credential", "http-authorization-credential", "[a-z0-9-]+-(?:api-key|token|access-token)"],
    "hardcoded-password": ["http-basic-credential", "password-hash-credential"],
    "hardcoded-cryptographic-key": ["crypto-key-passphrase", "hardcoded-crypto-key"],
    "committed-private-key": ["private-key", "private-key-blob", "private-key-store"],
}
D13_SRC = "engine/src/Scanner/Security/D13/SecretScanningAnalyzer.cs:108 (title = \"Leaked secret: {SecretType}\"); SecretType vocabulary from engine/src/Core/Security/NativeSecretScanner.cs Rules (:84-131), ScanLines (:993-1060) and ScanAsync (:546-574), PrivateKeyBlobFile.cs:61, KeyStoreFile.cs:77. D13's own type `hardcoded-credential` is the password|passwd|pwd assignment rule (NativeSecretScanner.cs:231 CredentialAssignment), hence hardcoded-password"
D28_SRC = "engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:266 (title = \"Secret: {gitleaks RuleID}\"); rule ids = gitleaks defaults (useDefault = true) + engine/rulesets/gitleaks/watchdog-gitleaks.toml; D28's own binary/config rules title \"{severity} secret: WD-SECRET-000N\" (engine/src/Scanner/Security/D28/Scanners: CommittedPrivateKeyBlobScan 0001, ConfigCredentialBindingScan 0002, PrivateKeyBlobHistoryScan 0003, CommittedKeyStoreScan 0004)"
D29_SRC = "engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,822 (title = \"{severity}: {semgrep check id after its last '.'}\"); check ids from engine/rulesets/semgrep/watchdog-sast.yml (native D29 checks carry no watchdog- prefix)"
D31_SRC = "engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:914 (title = \"{severity} IaC: {trivy id}\"); DS-0031 = secrets in ENV (engine/src/Scanner/Security/D31/Scanners/DockerfileShapeRuleFilter.cs:79)"
S1_SRC = "engine/src/Scanner/Compliance/S1/S1Analyzer.cs:1007"
SEV = r"^\w+"

# Contract 1.1 discriminators: concept -> dimension -> [conditions]. A dimension listed here gets one rule object per
# condition ({"rule": "^D$", "messages": [...]} / {"rule": "^D$", "properties": [...]}); the concept's other
# dimensions keep the plain dimension-id rule.
DISCRIM = OrderedDict()
for cid, types in D13_TYPES.items():
    DISCRIM.setdefault(cid, OrderedDict())["D13"] = [dict(messages=[r"^Leaked secret: (?:" + "|".join(re.escape(t) for t in types) + r"):"], source=D13_SRC)]
D28_OWN = {"hardcoded-credential": ["0002"], "committed-private-key": ["0001", "0003", "0004"]}
for cid, rules in D28_RULES.items():
    msgs = [r"^Secret: (?:" + "|".join(rules) + r"):"]
    if cid in D28_OWN:
        msgs.append(SEV + r" secret: WD-SECRET-(?:" + "|".join(D28_OWN[cid]) + r"):")
    DISCRIM.setdefault(cid, OrderedDict())["D28"] = [dict(messages=msgs, source=D28_SRC)]
DISCRIM["hardcoded-credential"]["D29"] = [dict(messages=[SEV + r": (?:watchdog-)?static-cloud-credential-in-workflow:"], source=D29_SRC)]
DISCRIM["hardcoded-cryptographic-key"]["D29"] = [dict(messages=[SEV + r": (?:watchdog-)?hardcoded-cookie-signing-secret(?:-[a-z]+)?:"], source=D29_SRC)]
DISCRIM["hardcoded-password"]["D29"] = [dict(messages=[SEV + r": (?:watchdog-)?hardcoded-[a-z0-9-]*password[a-z0-9-]*:"], source=D29_SRC + "; no check id at rubric-2026.10.1 matches, so D29 currently evidences no hardcoded-password result")]
DISCRIM["hardcoded-credential"]["D31"] = [dict(messages=[SEV + r" IaC: DS-0031:"], source=D31_SRC)]
DISCRIM["hardcoded-cryptographic-key"]["S1"] = [dict(messages=[r"^Cryptographic key material is a compile-time constant"], source=S1_SRC)]
DISCRIM["secret-in-version-history"] = OrderedDict(D28=[
    dict(properties=["commitSha"], source="engine/src/CodeHealth.Reporting/Sarif/SarifReportRenderer.cs:136-139 (commitSha stamped only on history-anchored findings)"),
    dict(messages=[SEV + r" secret: WD-SECRET-0003:"], source=D28_SRC + " (0003 walks the object database: a key blob deleted from the tree)")])
DISCRIM["dependencies-not-locked"] = OrderedDict(SC1=[dict(messages=[r"^(?:NuGet|JavaScript|Go) dependencies are not locked:"],
    source="engine/src/Scanner/SupplyChain/SC1/SupplyChainHygieneAnalyzer.cs:505")])
FAMILY = {c: "hardcoded-secret" for c in ("hardcoded-credential", "hardcoded-password", "hardcoded-cryptographic-key", "committed-private-key")}
IGNORE = [OrderedDict(rule=r"^D28$", message=r"^Rotate the exposed credentials",
                      reason="D28's repository-level roll-up of its located history rows (engine/src/Scanner/Security/D28/SecretsHistoryAnalyzer.cs:392), not a separate finding")]

mapping = OrderedDict()
mapping["scanner"] = "watchdog"
mapping["version"] = cat["rubricVersion"]
mapping["notes"] = [
    "SARIF ruleId format: the ruleId of EVERY Watchdog SARIF result is the bare dimension / meta-dimension id (\"D13\", \"X18\", \"AX6\", \"DM4\", …) with NO sub-rule suffix. Source: engine/src/CodeHealth.Reporting/Sarif/SarifReportRenderer.cs:115 (dimension results: [\"ruleId\"] = r.Id.Value) and :208 (meta-dimension results: [\"ruleId\"] = m.Id); one SARIF rule per dimension with id = dimension id (:36 and :96); results only for Measured/Flag dimensions and non-Info findings (FindingSurface.cs, engine/src/CodeHealth.Core/Dimensions/FindingSurface.cs).",
    "Hence every regex in this file is an exact, anchored match on dimension ids: ^(?:D13|D28)$. The contract's optional sub-rule form (^D13[/.:-]) never occurs and is not used.",
    "The sub-rule lives in the RESULT MESSAGE, not the ruleId: message.text = \"{Finding.Title}: {Finding.Detail}\" (SarifReportRenderer.cs:117). Title formats: D13 \"Leaked secret: {secret type}\" (engine/src/Scanner/Security/D13/SecretScanningAnalyzer.cs:108); D28 \"Secret: {gitleaks rule id}\" (engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:266); D29 \"{severity}: {semgrep check id}\" (ScanParsers.cs:822-823); D31 \"{severity} IaC: {trivy id}\" (ScanParsers.cs:914). fingerprints.json carries the same title plus a `detector` field.",
    "Per-result CWE taxa are present on security results (SarifReportRenderer.cs:154-168), but D13 stamps the dimension-wide pair CWE-798+CWE-259 on every row regardless of secret type (SecretScanningAnalyzer.cs:44, SecurityCweMap.cs:36), so CWE cannot discriminate D13 concepts.",
    "Contract 1.1: where one dimension maps to several concepts the message decides. The secret concepts (D13, D28, D29, D31, S1), secret-in-version-history (D28: properties.commitSha, or WD-SECRET-0003) and dependencies-not-locked (SC1) carry per-rule `messages` / `properties` conditions, each with a `source` naming the engine line its title format comes from. Other multi-concept dimensions (D29's injection/crypto checks, D31's container checks, S1's posture cards, D17 …) are NOT yet discriminated: a result of theirs is still offered to every concept the dimension maps to — discriminate a concept before a benchmark repository scores it.",
    "The four hardcoded-secret concepts form the family `hardcoded-secret`: a scanner that reports the right site under a sibling secret type (gitleaks generic-api-key on a planted password) is credited at plants and charged at traps (CONTRACT.md, Concept families).",
    "D28's repository-level \"Rotate the exposed credentials\" row is a roll-up of its located rows and is listed under `ignore` (outcome summary, in no metric).",
    "Location: physicalLocation.artifactLocation.uri = Finding.FilePath (repo-relative) and region.startLine = LineNumber, with any non-positive or missing line written as 1 (SarifReportRenderer.cs:331-355). A file-level finding therefore matches only entries within lineTolerance of line 1; a repository-level finding has an empty locations array.",
    "Runtime cards (AX*1) and X31 are mapped for completeness although they are out of scope for v1 (see coverage/matrix.json).",
]
mapping["concepts"] = OrderedDict()
for cid in concept_ids:
    ds = by_concept[cid]
    disc = DISCRIM.get(cid, {})
    for did in disc:
        assert did in ds, (cid, did, "discriminated dimension not mapped to the concept in dims.py")
    plain = [d for d in ds if d not in disc]
    rules = [rule_for(plain)] if plain else []
    for did, conds in disc.items():
        for cond in conds:
            r = OrderedDict(rule=rule_for([did]))
            for k in ("messages", "properties", "source"):
                if k in cond:
                    r[k] = cond[k]
            rules.append(r)
    spec = OrderedDict(rules=rules, dimensions=ds)
    if cid in FAMILY:
        spec["family"] = FAMILY[cid]
    mapping["concepts"][cid] = spec
mapping["ruleDimension"] = [OrderedDict(rule=r"^([A-Z]+[0-9]+)$", dimension="$1")]
mapping["ignore"] = IGNORE

# ---------------- coverage/matrix.json ----------------
def labels_for(kind, thematic, located=False):
    if kind == "finding":
        return ["must-fire", "must-not-fire", "clean"] if thematic else ["clean"]
    if kind == "metric":
        if thematic:
            return ["score-band", "must-fire"] if located else ["score-band"]
        return ["score-band", "clean"] if located else ["score-band"]
    return ["score-band"]

def kind_basis(did, kind):
    plan_post = set("C1 C2 C3 C4 C5 P1 P2 P3 P4 P5 P6 P7 P8 P9 P10 P11 P12 M1 M2 M3 D36 D37 D40 D41 D42 PF1 R5 R6 S1 SC1".split())
    plan_metric = set("D1 D2 D4 D5 D6 D8 D9 D15 D16 D26 D27 D34 D35 D39 R1 R10 AX10".split())
    plan_judged = set("D19 D20 D21 D22 D24 D25 M4 DM8 ED5 ES3 LA1 LA2 LA3 LA4 LA5 LA6".split())
    if did in plan_post or did in plan_metric or did in plan_judged:
        return "plan"
    if kind == "runtime":
        return "plan (AX*1 runtime tier)"
    if kind == "finding":
        return "plan (default: locatable defects)"
    return "assigned (not in the plan's lists)"

rows = []
for x in dims:
    did = x["id"]
    d = D[did]
    lm = langm.get(did)
    kind = d["k"]
    if did == "P9":
        pass
    row = OrderedDict()
    row["id"] = did
    row["name"] = x["name"]
    row["lens"] = x["lens"]
    row["lensLabel"] = lenses.get(x["lens"], x["lens"])
    row["family"] = x["family"]
    row["category"] = x.get("category")
    row["evaluator"] = x["evaluator"]
    row["kind"] = kind
    row["kindBasis"] = kind_basis(did, kind)
    row["whatItMeasures"] = x["whatItMeasures"]
    row["method"] = methods.get(did)
    row["languages"] = OrderedDict(
        csharp=d["cs"], typescript=d["ts"], basis=d["lb"],
        matrix=OrderedDict(basis=lm["Basis"], CSharp=lm["Languages"]["CSharp"], Ts=lm["Languages"]["Ts"]) if lm else None)
    row["edition"] = editions.get(did)
    absence = "CleanScan" if did in clean_scan else "EvidenceRequired" if did in evidence_req else None
    row["absencePolicy"] = OrderedDict(
        absenceClass=absence,
        sampledLlm=did in sampled_llm,
        scoringPolarity="reward" if did in reward else "deduction",
        catalogPolarity=x.get("scoringPolarity"))
    assert row["absencePolicy"]["scoringPolarity"] == x.get("scoringPolarity"), did
    row["concepts"] = d["c"]
    row["requires"] = d.get("req", [])
    if "oos" in d:
        row["status"] = "out-of-scope"
        row["reason"] = d["oos"]
        row["coverage"] = []
    else:
        row["status"] = "in-scope"
        cov = []
        # baseline-clean repos first
        b = d.get("b")
        for base, rel in ((CB, d["cs"]), (TB, d["ts"])):
            if rel in ("yes", "partial"):
                if b and b.startswith("na:"):
                    cov.append(OrderedDict(repo=base, phase=PHASE[base], labels=["not-applicable"], note=b[3:]))
                else:
                    cov.append(OrderedDict(repo=base, phase=PHASE[base], labels=labels_for(kind, False, d.get("loc", False))))
            else:
                cov.append(OrderedDict(repo=base, phase=PHASE[base], labels=["not-applicable"],
                                       note=("dimension does not exist for this repository's language" if base == CB else "C#-only dimension: must stay silent on a TypeScript repository")))
        for repo in d.get("r", []):
            cov.append(OrderedDict(repo=repo, phase=PHASE[repo], labels=labels_for(kind, True, d.get("loc", False))))
        row["coverage"] = cov
        assert any(cv["labels"] != ["not-applicable"] for cv in cov), did
    row["phase1"] = sorted({cv["repo"] for cv in row["coverage"] if cv["phase"] == 1})
    rows.append(row)

assert len(rows) == 165
matrix = OrderedDict(
    version="1.0",
    rubricVersion=cat["rubricVersion"],
    generatedFrom=OrderedDict(
        catalog="kennel.canine.dev/engine/rubrics/rubric-catalog-snapshot.json",
        languages="kennel.canine.dev/engine/docs/dimension-language-matrix.json (its Basis is 'undeclared'/'unknown' for most ids, so most rows carry an assessed basis instead — see each row's languages.basis)",
        editions="kennel.canine.dev/engine/src/Core/Edition/DimensionEditions.cs",
        absence="kennel.canine.dev/engine/src/CodeHealth.Core/Scoring/AbsencePolicy.cs",
        methods="kennel.canine.dev/engine/src/CodeHealth.Reporting/Dimensions/DimensionMethods.cs",
        plan="kennel.canine.dev/docs/plans/scanner-benchmark-repos.md",
        localScanCensus="'measured on N local TS scans' = count of sidecar.json under ~/Hentet/kennel (scans since 2026-09-25, rubric 2026.09.15-2026.09.18) where the dimension was Measured; indicative only"),
    phase1Repos=[CB, CS],
    labelKinds=["must-fire", "must-not-fire", "clean", "not-applicable", "score-band"],
    rows=rows)

os.makedirs(f"{OUT}/mappings", exist_ok=True)
os.makedirs(f"{OUT}/coverage", exist_ok=True)
def dump(obj, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")
dump(taxonomy, f"{OUT}/taxonomy.json")
dump(mapping, f"{OUT}/mappings/watchdog.json")
dump(matrix, f"{OUT}/coverage/matrix.json")
ins = sum(r["status"] == "in-scope" for r in rows)
print("concepts", len(C), "rows", len(rows), "in-scope", ins, "out-of-scope", len(rows) - ins)
from collections import Counter
print(Counter(r["kind"] for r in rows))
print(Counter(c["cwe"] is not None for c in C))

"""Contract 1.1 message discriminators for the Watchdog mapping (curated; read by build.py).

Watchdog's SARIF ruleId is the bare dimension id, and message.text = "{Finding.Title}: {Finding.Detail}"
(engine/src/CodeHealth.Reporting/Sarif/SarifReportRenderer.cs:117), so wherever one dimension maps to several concepts
the finding TITLE decides which concept a result evidences. SPEC holds, per discriminated dimension:

  concepts  {concept: [condition]} — EVERY concept the dimension maps to in dims.py, each with at least one condition:
            dict(messages=[regex], properties=[name]?, source="engine file:line the title format comes from").
            `messages=[]` (and no properties) records that no title of this dimension evidences the concept at this
            rubric; build.py then emits no rule for the pair and lists it under the mapping's `unevidenced`.
  off       [dict(message=regex, source=why)] — titles the dimension really emits that denote none of its concepts.
            A result matching only these maps to no concept (scored `uncovered`, or FP inside a "*" clean region).

Every title the dimension emits must match exactly one concept condition or one `off` regex; tests/test_watchdog_mapping.py
pins real message shapes. Regexes are case-insensitive searches over message.text and anchored at the start.
"""
import re
from collections import OrderedDict

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
SEV = r"^\w+"


D28_OWN = {"hardcoded-credential": ["0002"], "committed-private-key": ["0001", "0003", "0004"]}
SC1_SRC = "engine/src/Scanner/SupplyChain/SC1/SupplyChainHygieneAnalyzer.cs:505,514,523"

SPEC = OrderedDict()
SPEC["D13"] = dict(concepts=OrderedDict(
    (cid, [dict(messages=[r"^Leaked secret: (?:" + "|".join(re.escape(t) for t in types) + r"):"], source=D13_SRC)])
    for cid, types in D13_TYPES.items()), off=[])
SPEC["D28"] = dict(concepts=OrderedDict(), off=[])
for cid, rules in D28_RULES.items():
    msgs = [r"^Secret: (?:" + "|".join(rules) + r"):"]
    if cid in D28_OWN:
        msgs.append(SEV + r" secret: WD-SECRET-(?:" + "|".join(D28_OWN[cid]) + r"):")
    SPEC["D28"]["concepts"][cid] = [dict(messages=msgs, source=D28_SRC)]
SPEC["D28"]["concepts"]["secret-in-version-history"] = [
    dict(properties=["commitSha"], source="engine/src/CodeHealth.Reporting/Sarif/SarifReportRenderer.cs:136-139 (commitSha stamped only on history-anchored findings)"),
    dict(messages=[SEV + r" secret: WD-SECRET-0003:"], source=D28_SRC + " (0003 walks the object database: a key blob deleted from the tree)")]
SPEC["SC1"] = dict(concepts=OrderedDict([("dependencies-not-locked", [
    dict(messages=[r"^(?:NuGet|JavaScript|Go module|Go) dependencies are not locked:"], source=SC1_SRC)])]), off=[])

# ---- D31: IaC findings ("{severity} IaC: {rule id}: {detail}") -------------------------------------------------------
# Contract 1.3 split: the two coarse concepts container-excessive-privilege and iac-misconfiguration are UMBRELLAS
# (taxonomy/mapping `parent`) over precise concepts. Each rule id belongs to exactly one concept; an id an umbrella
# claimed before the split and no precise concept takes stays on the umbrella itself (its residue). The umbrella lists
# below are the pre-split definitions, kept verbatim so an entry naming an umbrella matches exactly what it matched
# before (build.py asserts that the children partition them).
D31_SRC = ('engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:914 (title "{severity} IaC: {trivy ID}"); '
           'engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:1919 (title "{severity} IaC: {checkov check_id}")')


def _iac_id(i):
    """The title-id regex of one IaC rule id: trivy ids tolerate the AVD- prefix and any zero padding."""
    m = re.fullmatch(r"(DS|KSV)-0*(\d+)", i)
    if m:
        return r"(?:AVD-)?" + m.group(1) + r"-?0*" + m.group(2) + ":"
    return re.escape(i) + ":"


def _iac_alt(ids):
    return "|".join(_iac_id(i) for i in ids)


def _ksv(*ns):
    return ["KSV-%04d" % n for n in ns]


CEP_ALL = (["DS-0002"] + _ksv(1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 14, 17, 20, 21, 22, 23, 24, 25, 26, 27, 29, 30, 103, 104,
                              105, 106, 117, 118)
           + ["CKV_DOCKER_3", "CKV_DOCKER_8"] + ["CKV_K8S_%d" % n for n in (16, 17, 18, 19, 20, 22, 23, 25, 26, 27, 28,
                                                                             29, 30, 31, 37, 39, 40)]
           + ["WD-DOCKER-0006", "WD-DOCKER-0015", "WD-COMPOSE-0001", "WD-COMPOSE-0003", "WD-K8S-0001", "WD-K8S-0003"])
LIMITS = _ksv(11, 18, 39, 40) + ["CKV_K8S_11", "CKV_K8S_13"]
MUTABLE = ["DS-0001", "KSV-0013", "CKV_DOCKER_7", "CKV_K8S_14", "CKV_K8S_43", "WD-DOCKER-0003", "WD-COMPOSE-0002"]
DOWNLOAD = ["WD-DOCKER-0001", "WD-DOCKER-0014"] + ["CKV2_DOCKER_%d" % n for n in (7, 8, 9, 10, 11)]
CERT = ["WD-DOCKER-0009"] + ["CKV2_DOCKER_%d" % n for n in (2, 3, 4, 5, 6, 12, 13, 14, 15, 16)]
SECRETS = ["DS-0031", "KSV-0109", "WD-K8S-0002", "WD-WRANGLER-0001"]
D31_OFF = (["DS-%04d" % n for n in (5, 6, 7, 8, 9, 11, 12, 13, 14, 15, 16, 17, 19, 20, 21, 22, 23, 24, 25, 29)]
           + ["CKV_DOCKER_%d" % n for n in (4, 5, 6, 9, 10, 11)] + ["WD-DOCKER-0008"])

# Ids one rule id carries for two concepts: the detail decides. {id: [(concept, detail regex after "id: ")]}
D31_SPLIT = {
    "WD-COMPOSE-0003": [
        ("privileged-container", r"Line \d+ gives service `[^`]*` every isolation mechanism"),
        ("host-namespace-sharing", r"Line \d+ gives service `[^`]*` the host's (?:NETWORK|PID|IPC) namespace")],
    "WD-K8S-0004": [("automounted-service-account-token", r"This pod (?:spec|template) sets")],
}
D31_SPLIT_SRC = {
    "WD-COMPOSE-0003": "engine/src/Scanner/Security/D31/Scanners/ComposeHostNamespaceScan.cs:92-95,229-230 (one id for "
                       "network_mode/pid/ipc: host and privileged: true; the detail names which)",
    "WD-K8S-0004": "engine/src/Scanner/Security/D31/Scanners/AutomountedServiceAccountTokenScan.cs:358-363 (\"This pod "
                   "spec sets neither `automountServiceAccountToken` …\" / \"This pod template sets "
                   "`automountServiceAccountToken: true` …\"); the same id is claimed by UnresolvableImageReferenceScan.cs:56,232 "
                   "(\"This manifest deploys a container image whose tag is an unsubstituted placeholder\"), which stays on "
                   "iac-misconfiguration",
}

# Precise concepts: (concept, umbrella, ids, why) — ids from the vendor catalogs (trivy KSV/DS, checkov CKV) and the
# engine's own WD- scans; each is a check of exactly the fact the concept names.
D31_PRECISE = [
    ("container-runs-as-root", "container-excessive-privilege",
     ["DS-0002"] + _ksv(12, 20, 21, 29, 105) + ["CKV_DOCKER_3", "CKV_DOCKER_8", "CKV_K8S_23", "CKV_K8S_40",
                                                 "WD-DOCKER-0006"],
     "DS-0002 image user root, KSV-0012 runAsNonRoot unset, KSV-0020/0021 UID/GID <= 10000, KSV-0029 root GID, KSV-0105 "
     "runAsUser 0; CKV_DOCKER_3 no user created, CKV_DOCKER_8 last USER root, CKV_K8S_23 root containers, CKV_K8S_40 "
     "high UID; WD-DOCKER-0006 final stage without unprivileged USER (ContainerRuntimeHardeningScan.cs:136)"),
    ("privileged-container", "container-excessive-privilege",
     ["KSV-0017", "KSV-0103", "CKV_K8S_16", "WD-K8S-0001"],
     "KSV-0017 privileged, KSV-0103 Windows HostProcess (the privileged equivalent), CKV_K8S_16 privileged; "
     "WD-K8S-0001 privileged nameless workload (Shared/Scanners/NamelessWorkloadPrivilegedScan.cs:237); "
     "WD-COMPOSE-0003 privileged: true (see the split)"),
    ("host-namespace-sharing", "container-excessive-privilege",
     _ksv(8, 9, 10) + ["CKV_K8S_17", "CKV_K8S_18", "CKV_K8S_19"],
     "KSV-0008/0009/0010 host IPC/network/PID, CKV_K8S_17/18/19 host PID/IPC/network; WD-COMPOSE-0003 "
     "network_mode/pid/ipc: host (see the split)"),
    ("host-path-mount", "container-excessive-privilege",
     _ksv(6, 23) + ["CKV_K8S_27", "WD-COMPOSE-0001", "WD-K8S-0003"],
     "KSV-0006 docker.sock hostPath, KSV-0023 hostPath volumes, CKV_K8S_27 docker daemon socket; WD-COMPOSE-0001 "
     "runtime socket bind mount (Shared/Scanners/ComposeRuntimeSocketMountScan.cs:163), WD-K8S-0003 hostPath "
     "PersistentVolume (D31/Scanners/HostPathPersistentVolumeScan.cs:237)"),
    ("container-privilege-escalation-allowed", "container-excessive-privilege",
     ["KSV-0001", "CKV_K8S_20", "WD-DOCKER-0015"],
     "KSV-0001 / CKV_K8S_20 allowPrivilegeEscalation not false; WD-DOCKER-0015 setuid bit granted in the image "
     "(D31/Scanners/SetuidBinaryGrantScan.cs:195)"),
    ("container-excess-capabilities", "container-excessive-privilege",
     _ksv(3, 4, 5, 22, 106) + ["CKV_K8S_25", "CKV_K8S_28", "CKV_K8S_37", "CKV_K8S_39"],
     "KSV-0003 default capabilities not dropped, KSV-0004 unused capabilities kept, KSV-0005 SYS_ADMIN, KSV-0022 "
     "non-default capabilities added, KSV-0106 capabilities beyond NET_BIND_SERVICE; CKV_K8S_25 added capability, "
     "CKV_K8S_28 NET_RAW, CKV_K8S_37 capabilities assigned, CKV_K8S_39 SYS_ADMIN"),
    ("container-writable-root-filesystem", "container-excessive-privilege",
     ["KSV-0014", "CKV_K8S_22"],
     "KSV-0014 / CKV_K8S_22 readOnlyRootFilesystem not true"),
    ("container-confinement-profile-unset", "container-excessive-privilege",
     _ksv(2, 30, 104) + ["CKV_K8S_31"],
     "KSV-0002 AppArmor profile, KSV-0030 seccomp RuntimeDefault, KSV-0104 seccomp disabled, CKV_K8S_31 seccomp "
     "profile"),
    ("container-security-context-missing", "container-excessive-privilege",
     ["KSV-0118", "CKV_K8S_29", "CKV_K8S_30"],
     "KSV-0118 default (empty) security context, CKV_K8S_29 pod and container security context, CKV_K8S_30 "
     "container security context"),
    ("missing-health-probes", "iac-misconfiguration",
     ["CKV_K8S_8", "CKV_K8S_9"],
     "CKV_K8S_8 liveness probe, CKV_K8S_9 readiness probe (Kubernetes workloads)"),
    ("missing-image-healthcheck", "iac-misconfiguration",
     ["DS-0026", "CKV_DOCKER_2", "WD-DOCKER-0007"],
     "DS-0026 / CKV_DOCKER_2 no Dockerfile HEALTHCHECK; WD-DOCKER-0007 no HEALTHCHECK on an image that declares a "
     "listening port (ContainerRuntimeHardeningScan.cs:154)"),
    ("automounted-service-account-token", "iac-misconfiguration",
     ["KSV-0036", "CKV_K8S_38"],
     "KSV-0036 service account token mounted, CKV_K8S_38 service account tokens only where necessary; WD-K8S-0004 "
     "automount row (see the split)"),
    ("overly-permissive-rbac", "iac-misconfiguration",
     _ksv(*range(41, 57), 111, 113, 114, 115) + ["CKV_K8S_49", "CKV_K8S_155", "CKV_K8S_156", "CKV_K8S_157",
                                                 "CKV_K8S_158"] + ["CKV2_K8S_%d" % n for n in (1, 2, 3, 4, 5)],
     "KSV-0041…0056 RBAC grants (secrets, pod logs, impersonation, wildcard verbs/resources, workloads, configmaps, "
     "RBAC, bindings, exec/attach, networking), KSV-0111 cluster-admin binding, KSV-0113 namespace secrets, KSV-0114 "
     "webhook configurations, KSV-0115 EKS aws-auth; CKV_K8S_49 wildcards, CKV_K8S_155-158 webhooks/CSR/bind/escalate, "
     "CKV2_K8S_1-5 binding escalation, nodes/proxy and exec, impersonate, services/status, read all secrets"),
    ("image-not-from-allowed-registry", "iac-misconfiguration",
     ["KSV-0125"],
     "KSV-0125 image from a registry outside the trusted list"),
    ("container-missing-resource-requests", "iac-misconfiguration",
     _ksv(15, 16) + ["CKV_K8S_10", "CKV_K8S_12"],
     "KSV-0015 / CKV_K8S_10 CPU requests, KSV-0016 / CKV_K8S_12 memory requests (requests, not limits: "
     "container-missing-resource-limits is the limits concept)"),
]

_split_ids = set(D31_SPLIT)
_precise_ids = [i for _, _, ids, _ in D31_PRECISE for i in ids]
assert len(_precise_ids) == len(set(_precise_ids)), "a D31 id is claimed by two precise concepts"
for _c, _u, _ids, _ in D31_PRECISE:
    if _u == "container-excessive-privilege":
        assert set(_ids) <= set(CEP_ALL), (_c, set(_ids) - set(CEP_ALL))
    else:  # iac-misconfiguration children: ids the pre-split catch-all held (claimed by no other concept, not off)
        assert not set(_ids) & set(CEP_ALL + LIMITS + MUTABLE + DOWNLOAD + CERT + SECRETS + D31_OFF), _c
CEP_RESIDUE = [i for i in CEP_ALL if i not in _precise_ids and i not in _split_ids]
# every id the umbrellas (or other concepts) claim, for the catch-all's negative lookahead
_D31_CLAIMED = (CEP_ALL + LIMITS + MUTABLE + DOWNLOAD + CERT + SECRETS + D31_OFF
                + [i for i in _precise_ids if i not in CEP_ALL])


def _iac(ids, extra=()):
    alts = [_iac_alt(ids)] if ids else []
    alts += list(extra)
    return r"^\w+ IaC: (?:" + "|".join(alts) + ")"


def _split_alts(concept):
    return [re.escape(i) + ": " + rx for i, pairs in D31_SPLIT.items() for c, rx in pairs if c == concept]


def _split_src(concept):
    return "; ".join(D31_SPLIT_SRC[i] for i, pairs in D31_SPLIT.items() for c, _ in pairs if c == concept)


D31_CONCEPTS = OrderedDict()
for _c, _u, _ids, _why in D31_PRECISE:
    _src = D31_SRC + "; " + _why + ((" — " + _split_src(_c)) if _split_alts(_c) else "")
    D31_CONCEPTS[_c] = [dict(messages=[_iac(_ids, _split_alts(_c))], source=_src)]
# the umbrella container-excessive-privilege: the pre-split ids no precise concept takes, and a WD-COMPOSE-0003 detail
# that neither split variant names
D31_CONCEPTS["container-excessive-privilege"] = [dict(
    messages=[_iac(CEP_RESIDUE, [r"WD\-COMPOSE\-0003: (?!" + "|".join(rx for _, rx in D31_SPLIT["WD-COMPOSE-0003"])
                                 + ")"])],
    source=D31_SRC + "; umbrella residue (contract 1.3 parent of the precise container-privilege concepts): the "
           "pre-split privilege ids no precise concept takes — KSV-0024 / CKV_K8S_26 host ports, KSV-0025 custom "
           "SELinux options, KSV-0026 unsafe sysctls, KSV-0027 /proc mount, KSV-0117 privileged ports — from the vendor "
           "catalogs")]
D31_CONCEPTS["container-missing-resource-limits"] = [dict(
    messages=[_iac(LIMITS)],
    source=D31_SRC + "; KSV-0011 CPU / KSV-0018 memory not limited, KSV-0039 LimitRange / KSV-0040 ResourceQuota "
           "(namespace-scoped, aggregated in engine/src/Scanner/Security/D31/Scanners/NamespaceScopedRuleAggregator.cs); "
           "CKV_K8S_11/13 CPU/memory limits. Requests (KSV-0015/0016, CKV_K8S_10/12) are NOT limits: "
           "container-missing-resource-requests")]
D31_CONCEPTS["mutable-image-reference"] = [dict(
    messages=[_iac(MUTABLE)],
    source=D31_SRC + "; DS-0001 ':latest' tag, KSV-0013 image tag latest, CKV_DOCKER_7, CKV_K8S_14/43; WD-DOCKER-0003 "
           "FROM by tag engine/src/Scanner/Security/D31/Scanners/MutableBaseImageScan.cs:55; WD-COMPOSE-0002 compose "
           "image by tag D31/Scanners/ComposeMutableServiceImageScan.cs:49")]
D31_CONCEPTS["download-without-integrity-check"] = [dict(
    messages=[_iac(DOWNLOAD)],
    source="WD-DOCKER-0001 curl|sh / unverified installer engine/src/Scanner/Security/Shared/Scanners/"
           "UnverifiedRemoteInstallerScan.cs:121; WD-DOCKER-0014 trust anchor fetched and never verified "
           "engine/src/Scanner/Security/D31/Scanners/UnverifiedTrustAnchorScan.cs:57; " + D31_SRC + " CKV2_DOCKER_7-11 "
           "(apk --allow-untrusted, apt --allow-unauthenticated, yum nogpgcheck, rpm --nosignature, apt --force-yes: "
           "package signature checking off)")]
D31_CONCEPTS["improper-certificate-validation"] = [dict(
    messages=[_iac(CERT)],
    source="WD-DOCKER-0009 build-time fetch with certificate validation off (curl -k / wget --no-check-certificate) "
           "engine/src/Scanner/Security/D31/Scanners/InsecureTransportFetchScan.cs:50; " + D31_SRC + " CKV2_DOCKER_2-6,"
           "12-16 (curl/wget/pip/npm/git/yum TLS verification disabled, PYTHONHTTPSVERIFY, NODE_TLS_REJECT_UNAUTHORIZED); "
           "no census row yet")]
D31_CONCEPTS["hardcoded-credential"] = [dict(
    messages=[_iac(SECRETS)],
    source=D31_SRC + "; DS-0031 secrets in ENV/ARG (engine/src/Scanner/Security/D31/Scanners/DockerfileShapeRuleFilter.cs:79), "
           "KSV-0109 ConfigMap with secrets; WD-K8S-0002 literal values in a committed kind: Secret "
           "engine/src/Scanner/Security/Shared/Scanners/CommittedSecretManifestScan.cs:81; WD-WRANGLER-0001 "
           "credential-named literal in wrangler vars Shared/Scanners/WranglerPlaintextVarScan.cs:61")]
D31_CONCEPTS["iac-misconfiguration"] = [dict(
    messages=[r"^\w+ IaC: (?!(?:" + _iac_alt(_D31_CLAIMED) + "|"
              + "|".join(re.escape(i) + ": " + rx for i, pairs in D31_SPLIT.items() if i not in CEP_ALL
                         for _, rx in pairs) + "))[A-Za-z0-9_-]+:"],
    source=D31_SRC + "; umbrella residue (contract 1.3 parent of the precise IaC configuration concepts): every IaC id "
           "not claimed by a more specific concept or by `off` — cloud checks (AWS-/AZU-/GCP-/CKV_AWS/CKV2_*), "
           "namespace placement (CKV_K8S_21, KSV-0037, KSV-0110), image pull policy (CKV_K8S_15), secrets as env "
           "vars (CKV_K8S_35), NGINX snippet annotations (CKV_K8S_153), DS-0004 port 22, DS-0010 sudo, KSV-01010 "
           "sensitive (non-secret) ConfigMap content, CKV2_DOCKER_17 chpasswd, and WD-DOCKER-0002 build-time key "
           "material (D31/Scanners/BuildTimeKeyMaterialScan.cs:62), -0004 unpinned toolchain install "
           "(UnpinnedToolchainInstallScan.cs:110), -0005 mutable git clone (MutableGitCloneScan.cs:49), -0010 unscoped "
           "COPY . (UnscopedBuildContextCopyScan.cs:55), -0011 safe.directory '*' (GitOwnershipCheckDisabledScan.cs:50), "
           "-0012 world-writable owned path (WorldWritableOwnedPathScan.cs:64), -0013 EOL base image "
           "(EndOfLifeBaseImageScan.cs:64), -0016 PEP 668 guard off (PythonInstallGuardDisabledScan.cs:59), -0017 "
           "browser sandbox off (BrowserSandboxDisabledScan.cs:62), WD-K8S-0004 unsubstituted image placeholder "
           "(UnresolvableImageReferenceScan.cs:232)")]
D31_SPEC = dict(
    concepts=D31_CONCEPTS,
    off=[dict(message=_iac(D31_OFF),
              source=D31_SRC + "; Dockerfile lint / image-size / build-hygiene rules with no security consequence: "
                     "DS-0005 ADD vs COPY, -0006 COPY --from self, -0007 multiple ENTRYPOINT, -0008 port out of range, "
                     "-0009 relative WORKDIR, -0011 COPY multi-arg, -0012 duplicate alias, -0013 RUN cd, -0014 "
                     "wget+curl, -0015/-0016/-0019/-0020 package cache cleanup "
                     "(engine/src/Scanner/Security/D31/Scanners/DockerfileShapeRuleFilter.cs:114-121), -0017 update "
                     "alone, -0021 apt-get -y, -0022 MAINTAINER, -0023 multiple HEALTHCHECK, -0024 dist-upgrade, -0025 "
                     "apk --no-cache, -0029 --no-install-recommends; CKV_DOCKER_4/5/6/9/10/11 (checkov twins); "
                     "WD-DOCKER-0008 no-op tool shim (engine/src/Scanner/Security/D31/Scanners/NoOpToolShimScan.cs:55, "
                     "CWE-754: a test/build tool neutered, a gate-honesty defect, not an IaC security misconfiguration)")])
PRECISE_PARENT = {c: u for c, u, _, _ in D31_PRECISE}


# Per-dimension tables: titles read from the analyzers named in each source, checked against the distinct messages of
# ~8.5k local Watchdog SARIF outputs (every distinct message of each dimension lands on exactly one concept or one off regex).
TABLE = {
 "D3": dict(
  concepts=OrderedDict([
   ("god-class", [
    dict(messages=["^(?:ClassTooLong|TooManyMethods|TooManyFields|TooManyFunctions): "],
        source='engine/src/Scanner/CodeShape/D3/CodeShape/GodClassAnalyzer.cs:553 (TitleOf: "{DisplayReason ?? Reason}: {name}"); reasons engine/src/Core/ShapeContracts/GodClassFinding.cs (FileTooLong, ClassTooLong, TooManyMethods, MethodTooLong, TooManyFields); GodClassAnalyzer.cs:533 names ClassTooLong/TooManyMethods/TooManyFields the type (god-class) reasons; TooManyFunctions is TooManyMethods on a module pseudo-type (engine/src/Core/CodeShape/NeutralGodClassScanner.cs:398,430)'),
   ]),
   ("oversized-source-file", [
    dict(messages=["^FileTooLong: "],
        source='engine/src/Scanner/CodeShape/D3/CodeShape/GodClassAnalyzer.cs:553 (TitleOf: "{DisplayReason ?? Reason}: {name}"); reasons engine/src/Core/ShapeContracts/GodClassFinding.cs (FileTooLong, ClassTooLong, TooManyMethods, MethodTooLong, TooManyFields); FileTooLong is about a file (GodClassAnalyzer.cs:523-525)'),
   ]),
   ("long-method", [
    dict(messages=["^(?:MethodTooLong|FunctionTooLong): "],
        source='engine/src/Scanner/CodeShape/D3/CodeShape/GodClassAnalyzer.cs:553 (TitleOf: "{DisplayReason ?? Reason}: {name}"); reasons engine/src/Core/ShapeContracts/GodClassFinding.cs (FileTooLong, ClassTooLong, TooManyMethods, MethodTooLong, TooManyFields); MethodTooLong is about a member, not a type (GodClassAnalyzer.cs:523-525, :547); FunctionTooLong is its display name for free functions (engine/src/Core/CodeShape/NeutralMethodLengthScanner.cs:534,543)'),
   ]),
  ]),
  off=[
  ]),
 "D5": dict(
  concepts=OrderedDict([
   ("module-dependency-cycle", [
    dict(messages=["^Circular dependency: "],
        source='engine/src/Scanner/Architecture/D5/CouplingAnalyzer.cs:398 and ModuleGraphCoupling.cs:543 (title "Circular dependency")'),
   ]),
   ("unstable-dependency", [
    dict(messages=["^Unstable project "],
        source='engine/src/Scanner/Architecture/D5/CouplingAnalyzer.cs:405 and ModuleGraphCoupling.cs:551 (title "Unstable project {name}")'),
   ]),
   ("layer-dependency-violation", [
    dict(messages=["^Layer violation: "],
        source='engine/src/Scanner/Architecture/D5/CouplingAnalyzer.cs:411 (title "Layer violation: {from} → {to}")'),
   ]),
   ("module-off-main-sequence", [
    dict(messages=["^Off the main sequence: "],
        source='engine/src/Scanner/Architecture/D5/MainSequenceFinding.cs:64 (title "Off the main sequence: {project}"; zone of pain / zone of uselessness)'),
   ]),
  ]),
  off=[
  ]),
 "D7": dict(
  concepts=OrderedDict([
   ("layer-dependency-violation", [
    dict(messages=["^ADR rule violated: "],
        source="engine/src/Scanner/Architecture/D7/ArchitecturalIntegrityAnalyzer.cs:445 (a reference the repository's own ADR forbids from a scope)"),
   ]),
   ("architecture-rules-unenforced", [
    dict(messages=["^ADR enforcement could be stronger: ", "^Classify ADR enforcement: ", "^Broken enforcement_link: "],
        source="engine/src/Scanner/Architecture/D7/ArchitecturalIntegrityAnalyzer.cs:460 (enforceable ADR with no analyzer/test), :495 (ADR without an enforcement classification), :529 (enforcement_link that resolves to nothing)"),
   ]),
   ("module-dependency-cycle", [
    dict(messages=["^Circular dependency: "],
        source="engine/src/Scanner/Architecture/D7/ArchitecturalIntegrityAnalyzer.cs:539"),
   ]),
  ]),
  off=[
   dict(message="^ADR parse warning: ",
        source="engine/src/Scanner/Architecture/D7/ArchitecturalIntegrityAnalyzer.cs:545 — a parse diagnostic about the ADR file, not an architecture defect"),
  ]),
 "D10": dict(
  concepts=OrderedDict([
   ("test-without-assertion", [
    dict(messages=["^No assertions: ", r"^No assertions \(empty test\): ", "^No direct assertions: ", "^Assertions commented out: ", "^Test project verifies nothing: "],
        source='engine/src/Scanner/Testing/D10/TestQualityAnalyzer.cs:536 (No assertions), :523 (empty test), :516 (No direct assertions), :471 (Assertions commented out), :569 (Test project verifies nothing). "No assertions (declared)" (:493) is Info and never reaches SARIF'),
   ]),
   ("skipped-test-without-reason", [
    dict(messages=["^Skipped test: ", "^Tests excluded from compilation: "],
        source='engine/src/Scanner/Testing/D10/TestQualityAnalyzer.cs:450 (Skipped test: undocumented skip; the documented form "Skipped (documented)" :449 is Info), :359 (test file dropped from the build by <Compile Remove>, a skip nothing records)'),
   ]),
   ("excessive-mocking", [
    dict(messages=[],
        source='engine/src/Scanner/Testing/D10/TestQualityAnalyzer.cs emits no mock-dominance row at rubric-2026.10.1 ("Mock framework:" :406 is an Info inventory line, never in SARIF)'),
   ]),
   ("flaky-test", [
    dict(messages=["^Fixed-sleep synchronisation: ", "^Depends on a live external host: "],
        source="engine/src/Scanner/Testing/D10/TestQualityAnalyzer.cs:371 (test ordered against background work by a fixed sleep), :381 (test fetches a third-party host while it runs) — the two static causes of non-deterministic tests"),
   ]),
   ("test-failure-swallowed", [
    dict(messages=["^Test cannot fail: "],
        source="engine/src/Scanner/Testing/D10/TestQualityAnalyzer.cs:345 (a test that asserts, inside a catch-all that discards the failure), :482 (the same with no assertion: replaces the zero-assertion row)"),
   ]),
  ]),
  off=[
   dict(message="^Snapshot tests auto-approve: ",
        source="engine/src/Scanner/Testing/D10/TestQualityAnalyzer.cs:396 — a snapshot harness configured to accept its own output; no concept denotes it"),
  ]),
 "D12": dict(
  concepts=OrderedDict([
   ("vulnerable-dependency", [
    dict(messages=["^Vulnerable: "],
        source="engine/src/Scanner/Dependencies/D12/DependencyHygieneAnalyzer.cs:446"),
   ]),
   ("outdated-dependency", [
    dict(messages=[r"^Outdated(?: \([^)]*\))?: ", "^Dependency pinned to a stale untagged commit: "],
        source="engine/src/Scanner/Dependencies/D12/DependencyHygieneAnalyzer.cs:441,428,1851,1913,2469,2850,3040 (Outdated rows, Info) and :3113 (Go pseudo-version pin far behind the module's releases)"),
   ]),
   ("deprecated-dependency", [
    dict(messages=["^Deprecated: ", "^Deprecated module: ", "^Discontinued package: ", "^Abandoned package: ", "^Retired release: ", "^Yanked release: "],
        source="engine/src/Scanner/Dependencies/D12/DependencyHygieneAnalyzer.cs:451 (NuGet/npm deprecated), :2625 (Go deprecated module), :1974 (Dart discontinued), :2037 (Composer abandoned), :2244,2351 (Hex retired), :2106,2181 (Cargo/PyPI yanked) — all publisher-marked withdrawals"),
   ]),
   ("prerelease-dependency", [
    dict(messages=["^Prerelease dependency: "],
        source="engine/src/Scanner/Dependencies/D12/DependencyHygieneAnalyzer.cs:462"),
   ]),
   ("dependencies-not-locked", [
    dict(messages=[r"^No dependency lockfile committed \(", r"^No Package\.resolved committed \(", r"^No go\.sum committed \(", r"^No Gemfile\.lock committed by an application", "^Dependency not covered by the (?:lockfile|committed resolution): ", "^Floating (?:npm|git|source|branch) dependency: ", "^UPM dependency `[^`]+` is a git source with no revision", "^Dependency pinning: "],
        source='engine/src/Scanner/Dependencies/D12/DependencyHygieneAnalyzer.cs:3090-3196 (pinning-discipline titles: no lockfile :3102,3111,3143,3177; declaration outside the lockfile :3145,3179; dependency naming no releasable version :3093,3104,3147,3181; fallback "Dependency pinning") and :2985 (UPM git source with no revision)'),
   ]),
  ]),
  off=[
   dict(message="^Unbounded dependency requirement: ",
        source="engine/src/Scanner/Dependencies/D12/DependencyHygieneAnalyzer.cs:3183,3196 — a requirement with no upper bound beside a lockfile: upgrade risk, not an unlocked build"),
   dict(message="^One package at two majors across the workspace: ",
        source="engine/src/Scanner/Dependencies/D12/DependencyHygieneAnalyzer.cs:3095 — version skew, no concept"),
   dict(message="^(?:Dependency hygiene not measured|Gradle deprecation and maintenance status not graded|Maven deprecation and maintenance status not graded)",
        source="engine/src/Scanner/Dependencies/D12/DependencyHygieneAnalyzer.cs:365,2745,2820 and DependencyHygieneAnalyzer.NuGetReadNothing.cs:175 — measurement disclosures"),
  ]),
 "PF3": dict(
  concepts=OrderedDict([
   ("blocking-on-async-code", [
    dict(messages=["^Sync-over-async blocking: "],
        source="engine/src/Scanner/ModelAware/PF3/AsyncLatencyHygieneAnalyzer.cs:83,154"),
   ]),
   ("missing-configure-await", [
    dict(messages=[r"^Awaits without ConfigureAwait\(false\): "],
        source="engine/src/Scanner/ModelAware/PF3/AsyncLatencyHygieneAnalyzer.cs:182"),
   ]),
  ]),
  off=[
  ]),
 "R1": dict(
  concepts=OrderedDict([
   ("untyped-javascript-share", [
    dict(messages=["^Type Safety"],
        source="engine/src/Scanner/Frontend/R1/TypeSafetyDimension.cs:39 via engine/src/Scanner/Frontend/Frontend.Shared/FrontendCards.cs:39,89 (one location-less row titled with the dimension name when the typed-share score is below 7)"),
   ]),
   ("unchecked-any-external-data", [
    dict(messages=[],
        source="engine/src/Scanner/Frontend/R1 measures the typed-file share and tsconfig strictness only; no row names an `any` cast at rubric-2026.10.1"),
   ]),
  ]),
  off=[
  ]),
 "R2": dict(
  concepts=OrderedDict([
   ("high-cyclomatic-complexity", [
    dict(messages=[r"^Complex function .* \(cyclomatic \d+, cognitive \d+\): "],
        source="engine/src/Scanner/Frontend/R2/ComplexityDimensionBuilder.cs:18-21 (row raised only when cyclomatic > 10)"),
   ]),
   ("high-cognitive-complexity", [
    dict(messages=[],
        source="engine/src/Scanner/Frontend/R2/ComplexityDimensionBuilder.cs:18 — every R2 row is raised on the cyclomatic bar alone (cognitive is printed, never thresholded), so no R2 row evidences high cognitive complexity"),
   ]),
  ]),
  off=[
   dict(message="^Cyclomatic Complexity: P95 cyclomatic",
        source="engine/src/Scanner/Frontend/R2/ComplexityDimensionBuilder.cs:16 — the dimension's own summary line (seen as a result in an older engine's SARIF), not a function"),
  ]),
 "R8": dict(
  concepts=OrderedDict([
   ("unused-dependency", [
    dict(messages=["^Unused dependency '"],
        source="engine/src/Scanner/Frontend/R8/DependencyHygieneDimensionBuilder.cs:96"),
   ]),
   ("undeclared-dependency", [
    dict(messages=["^Unlisted import '"],
        source="engine/src/Scanner/Frontend/R8/DependencyHygieneDimensionBuilder.cs:87"),
   ]),
   ("misplaced-dev-dependency", [
    dict(messages=["^(?:Type|Test)-only dependency '[^']+' in production deps"],
        source="engine/src/Scanner/Frontend/R8/DependencyHygieneDimensionBuilder.cs:134,140"),
   ]),
  ]),
  off=[
  ]),
 "X1": dict(
  concepts=OrderedDict([
   ("async-void-method", [
    dict(messages=["^async void method: "],
        source="engine/src/Scanner/Defects/Defects.Shared/CSharpCards.cs:1023"),
   ]),
   ("blocking-on-async-code", [
    dict(messages=[r"^Sync-over-async \(deadlock risk\)", "^Blocking wait while holding a `lock`", "^Blocking `[^`]+` inside an `async(?: def| method)?`"],
        source="engine/src/Scanner/Defects/X1/AsyncCorrectnessAnalyzer.cs:222/215 (Sync-over-async), :224/218 (blocking wait under a lock), :270/83 (SemaphoreSlim.Wait in an async method), :127 (blocking sleep inside async def)"),
   ]),
   ("floating-promise", [
    dict(messages=["^`async` callback passed to `forEach`", "^`async` Promise executor", "^(?:Task|Future) from `[^`]+` is not kept", "^Future started here is not kept"],
        source="engine/src/Scanner/Defects/X1/AsyncCorrectnessAnalyzer.cs:123,125,137 (async callback passed to forEach: the Promise each call returns is dropped), :126,176 (async Promise executor: a rejection inside it is never observed), :129-131 (dropped task/future, Python/Ruby/Scala). A bare unawaited call is not detected at this rubric"),
   ]),
  ]),
  off=[
   dict(message="^`async` callback passed to `(?!forEach`)",
        source="engine/src/Scanner/Defects/X1/AsyncCorrectnessAnalyzer.cs:124,132,148 — an async React effect / Flutter setState callback: a framework-contract defect (the return value is read as a cleanup / the rebuild runs early), not a dropped promise"),
   dict(message="^`[^`]+` inside an `async def`",
        source="engine/src/Scanner/Defects/X1/AsyncCorrectnessAnalyzer.cs:128 — nested event loop, no concept"),
  ]),
 "X3": dict(
  concepts=OrderedDict([
   ("empty-catch-block", [
    dict(messages=[r"^Swallowed exception \((?:empty catch|caught, then discarded)\)"],
        source="engine/src/Scanner/Defects/X3/ExceptionHandlingAnalyzer.cs:95,100,129,147"),
   ]),
   ("pointless-catch-rethrow", [
    dict(messages=[],
        source="engine/src/Scanner/Defects/X3/ExceptionHandlingAnalyzer.cs emits no catch-that-only-rethrows row at rubric-2026.10.1 (the `throw ex;` row :161 fires on any rethrow of the caught variable, whatever else the catch does)"),
   ]),
   ("rethrow-resets-stack-trace", [
    dict(messages=[r"^Rethrow loses stack trace \(`throw ex;`\)"],
        source="engine/src/Scanner/Defects/X3/ExceptionHandlingAnalyzer.cs:161"),
   ]),
  ]),
  off=[
   dict(message="^Unguarded deserialized result under a catch list that cannot catch it",
        source="engine/src/Scanner/Defects/X3/ExceptionHandlingAnalyzer.cs:254 — a null dereference after deserialization, not an exception-handling concept"),
  ]),
 "X5": dict(
  concepts=OrderedDict([
   ("nullable-analysis-disabled", [
    dict(messages=["^Nullable reference types not enabled everywhere", "^Strict null checking is not enabled everywhere", "^Java packages are not null-marked everywhere", "^PHP static analysis does not check null everywhere", "^Sound null safety is not on in every Dart package", "^Ruby's type checker does not check nil everywhere", "^Scala's null is not held to the type system everywhere"],
        source="engine/src/Scanner/Defects/X5/NullableReferenceTypesAnalyzer.cs:1873 (C# NRT), :1444 (TS strictNullChecks), :1526 (Java), :1582 (PHP), :1642 (Dart), :1699 (Ruby), :1758 (Scala)"),
   ]),
   ("null-forgiving-suppression", [
    dict(messages=[r"^Null-forgiving operator \(`!`\) suppressions reduce", r"^(?:Null|Nil) assertions(?: \(`!`\))? reduce", "^Nullness suppressions reduce", "^Baselined and suppressed nullness errors reduce"],
        source="engine/src/Scanner/Defects/X5/NullableReferenceTypesAnalyzer.cs:1905 (C# `!`), :1453 (TS `!`), :1649 (Dart), :1708 (Ruby), :1767 (Scala), :1533 (Java), :1591 (PHP)"),
   ]),
   ("null-dereference", [
    dict(messages=["^Symbol treated as nullable, then dereferenced unguarded", "^Null guard scopes only part of the work it protects", "^Null guard proves the local; the guarded body dereferences the field"],
        source="engine/src/Scanner/Defects/X5/NullableReferenceTypesAnalyzer.cs:370,447 (dereference after ?./as admitted null), :783 (dereference after the guard's block closed), :788 (guard on the local, dereference of the field)"),
   ]),
  ]),
  off=[
   dict(message="^Null-tolerant access on a value the branch has already proved null",
        source="engine/src/Scanner/Defects/X5/NullableReferenceTypesAnalyzer.cs:781 — `?.` on a value proved null: dead logic, no dereference"),
  ]),
 "S1": dict(
  concepts=OrderedDict([
   ("security-response-headers", [
    dict(messages=["^No security response headers detected:"],
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:884 (.NET card); engine/src/Scanner/Compliance/S1/S1Analyzer.ServerRows.cs:103 (foreign server card); engine/src/Scanner/Compliance/Compliance.Prework/CompliancePrework.cs:5282 AddForeignHostedHeadersRow (static/foreign-hosted surface)"),
   ]),
   ("https-enforcement", [
    dict(messages=["^No app-layer HTTPS enforcement detected:"],
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:890; engine/src/Scanner/Compliance/S1/S1Analyzer.ServerRows.cs:95"),
   ]),
   ("insecure-cookie-flags", [
    dict(messages=["^Secure cookie flags not detected:"],
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:918; engine/src/Scanner/Compliance/S1/S1Analyzer.ServerRows.cs:122"),
   ]),
   ("inbound-input-validation", [
    dict(messages=["^No inbound (?:model|request) validation detected:"],
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:902 (model, .NET); engine/src/Scanner/Compliance/S1/S1Analyzer.ServerRows.cs:114 (request, foreign server)"),
   ]),
   ("weak-cryptographic-algorithm", [
    dict(messages=["^(?:Weak cipher|Obsolete TLS/SSL protocol version enabled|Ciphertext is encrypted but not authenticated):"],
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:825 Weak cipher (DES/3DES/RC2/bare Rijndael), engine/src/Scanner/Compliance/S1/S1Analyzer.JavaScript.cs:285; engine/src/Scanner/Compliance/S1/S1Analyzer.cs:579 + engine/src/Scanner/Compliance/S1/S1Analyzer.JavaScript.cs:261 obsolete SSL/TLS version selected explicitly (a deprecated cryptographic protocol, CWE-327); engine/src/Scanner/Compliance/S1/S1Analyzer.cs:671 SymmetricAlgorithm CBC/ECB with no MAC or AEAD anywhere in the type (risky mode use: malleable / padding oracle)"),
   ]),
   ("weak-hash-algorithm", [
    dict(messages=["^(?:Weak hash algorithm|Weak hash is the integrity check):"],
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:629 + engine/src/Scanner/Compliance/S1/S1Analyzer.JavaScript.cs:274 MD5/SHA1 constructed; engine/src/Scanner/Compliance/S1/S1Analyzer.cs:649 MD5/SHA1 digest compared against an expected value as the integrity gate"),
   ]),
   ("hardcoded-cryptographic-key", [
    dict(messages=["^Cryptographic key material is a compile-time constant: (?!(?:`[^`]*`|The value) is the key-derivation salt(?: and is a compile-time constant|, and its shipped DEFAULT))", "^The encryption IV is the same for every message: This encryption's initialisation vector is a compile-time constant"],
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:1007 (title) + :79-97 (detail names the role; salt-only rows excluded, see insufficient-password-hashing); engine/src/Scanner/Compliance/S1/S1Analyzer.cs:748 static IV whose origin is 'a compile-time constant' (engine/src/Scanner/Compliance/Compliance.Prework/CompliancePrework.cs:2564) — a literal IV is in this concept's description"),
   ]),
   ("improper-certificate-validation", [
    dict(messages=["^TLS certificate validation disabled:"],
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:564 (ServerCertificateCustomValidationCallback accepts all); engine/src/Scanner/Compliance/S1/S1Analyzer.JavaScript.cs:247 (rejectUnauthorized: false, NODE_TLS_REJECT_UNAUTHORIZED); Scala/Ruby/Dart arms feed the same signal"),
   ]),
   ("token-signature-or-expiry-not-validated", [
    dict(messages=["^Token validation disabled: `(?:[A-Za-z]+`, `)*(?:ValidateIssuerSigningKey|RequireSignedTokens|ValidateLifetime)(?: = false)?`"],
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:858 title; detail engine/src/Scanner/Compliance/Compliance.Prework/CompliancePrework.cs:5195-5227: the disabled switches in severity order, either '`X = false` means…' or '`A`, `B` are all set to `false`, which means…'. Lands here only when a SIGNATURE switch (ValidateIssuerSigningKey, RequireSignedTokens) or the LIFETIME switch is among them; audience/issuer-only rows are off-concept"),
   ]),
   ("sensitive-data-in-url", [
    dict(messages=["^(?:Password accepted from the URL query string|Request payload sent in the URL query string):"],
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:538 (password-named parameter read off Request.Query); engine/src/Scanner/Compliance/S1/S1Analyzer.cs:551 (body-less POST carrying sensitively-named parameters in the query string)"),
   ]),
   ("sensitive-data-in-logs", [
    dict(messages=["^Credential material is serialised into the log:"],
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:806 (log call serialises a whole object whose type emits credential members)"),
   ]),
   ("missing-subresource-integrity", [
    dict(messages=["^Third-party script without Subresource Integrity:"],
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:963 (AddUnverifiedRemoteScriptRow; shared by the JS/TS card, engine/src/Scanner/Compliance/S1/S1Analyzer.JavaScript.cs:292)"),
   ]),
   ("insufficient-password-hashing", [
    dict(messages=["^(?:Password hashing without a KDF|Password stored in plaintext by default|Password key derivation is priced too cheaply):", "^Cryptographic key material is a compile-time constant: (?:`[^`]*`|The value) is the key-derivation salt(?: and is a compile-time constant|, and its shipped DEFAULT)"],
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:510 (password-hash field, no KDF anywhere); engine/src/Scanner/Compliance/S1/S1Analyzer.cs:524 (password-format setting defaults to plaintext); engine/src/Scanner/Compliance/S1/S1Analyzer.cs:781 (PBKDF2/scrypt/bcrypt cost below OWASP floor); engine/src/Scanner/Compliance/S1/S1Analyzer.cs:1007 rows whose only role is the key-derivation salt (constant salt, CWE-760)"),
   ]),
   ("cleartext-transmission", [
    dict(messages=["^OIDC metadata fetched over HTTP:"],
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:839 RequireHttpsMetadata = false — RequireHttpsMetadata = false: the identity provider's signing metadata is fetched over plaintext HTTP (CWE-319)"),
   ]),
  ]),
  off=[
   dict(message="^Middleware order:",
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:896 UseAuthorization before UseAuthentication — a pipeline-order defect; no S1 concept (missing-authorization is an endpoint with no check, not a misordered one)"),
   dict(message="^Password hash compared with `==`:",
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:594 non-constant-time compare (CWE-208); no concept"),
   dict(message="^(?:The cipher transform runs in the wrong direction|The crypto stream is used against the mode it was opened with):",
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:695 / :721 encryptor/decryptor or CryptoStreamMode contradictions — functional correctness defects, not a weak primitive"),
   dict(message="^The encryption IV is the same for every message: This encryption's initialisation vector is derived from ",
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:748 with origin 'derived from `kdf`, the same key derivation as the key' (engine/src/Scanner/Compliance/Compliance.Prework/CompliancePrework.cs:2571) — a predictable/static IV (CWE-329), not a literal key"),
   dict(message="^Information-disclosure response header set:",
        source="engine/src/Scanner/Compliance/Compliance.Prework/CompliancePrework.cs:5266 Server/X-Powered-By set explicitly — information exposure (CWE-200); security-response-headers is the presence of the protective headers"),
   dict(message="^Token validation disabled: `(?:ValidateAudience|ValidateIssuer)(?:`, `(?:ValidateAudience|ValidateIssuer))*(?: = false)?`(?: are| means)",
        source="engine/src/Scanner/Compliance/S1/S1Analyzer.cs:858 / engine/src/Scanner/Compliance/Compliance.Prework/CompliancePrework.cs:5209-5222 with only ValidateAudience/ValidateIssuer off — the signature and lifetime are still verified, so token-signature-or-expiry-not-validated does not denote it"),
  ]),
 "D17": dict(
  concepts=OrderedDict([
   ("technical-debt-marker", [
    dict(messages=[r"^(?:TodoComment|FixmeComment|HackComment|XxxComment)(?: repeated (?:across \d+ files|\d+ times in (?:one file|\d+ files)))?:", r"^Whole file has no live code — \d+ debt markers? inside it: [^(]*\((?:\d+ (?:Todo|Fixme|Hack|Xxx)Comment(?:, )?)+\)"],
        source="engine/src/Core/ExplicitDebt/DebtMarker.cs:6-18 kinds; title engine/src/Scanner/ExplicitDebt/D17/ExplicitDebtAnalyzer.cs:1179 (marker.Kind), fold engine/src/Scanner/ExplicitDebt/D17/ExplicitDebtAnalyzer.cs:339; whole-file fold engine/src/Scanner/ExplicitDebt/D17/ExplicitDebtAnalyzer.cs:665 when its breakdown holds only task comments (no commented-out code)"),
   ]),
   ("suppressed-diagnostic", [
    dict(messages=[r"^(?:BareSuppressMessage|BarePragmaDisable|FileScopedPragmaDisable|NoWarnInCsproj|AnalyzerSeverityNone|BlanketAnalyzerSeverityNone|DisabledAnalyzers|DuplicateNoWarn|DuplicateAnalyzerSeverity|IneffectivePragmaPair)(?: repeated (?:across \d+ files|\d+ times in (?:one file|\d+ files)))?:", r"^NoWarnInCsproj — (?:known-vulnerability alert suppressed|\d+ warning codes suppressed in one element):"],
        source="engine/src/Core/ExplicitDebt/DebtMarker.cs kinds BareSuppressMessage, BarePragmaDisable, FileScopedPragmaDisable, NoWarnInCsproj, AnalyzerSeverityNone, BlanketAnalyzerSeverityNone, DisabledAnalyzers (EnableNETAnalyzers/RunAnalyzers=false); DuplicateNoWarn / DuplicateAnalyzerSeverity REPLACE the second suppression row of the same id (DebtMarker.cs doc) and IneffectivePragmaPair is a disable/restore pair — all are the suppression line itself; titles engine/src/Scanner/ExplicitDebt/D17/ExplicitDebtAnalyzer.cs:1179, :299, :355"),
   ]),
   ("commented-out-code", [
    dict(messages=[r"^(?:CommentedOutCode)(?: repeated (?:across \d+ files|\d+ times in (?:one file|\d+ files)))?:", r"^Whole file has no live code — \d+ debt markers? inside it: [^(]*\([^)]*\bCommentedOutCode\b"],
        source="engine/src/Core/ExplicitDebt/DebtMarker.cs CommentedOutCode (D-152 consecutive commented-code lines, also commented-out config blocks); whole-file fold engine/src/Scanner/ExplicitDebt/D17/ExplicitDebtAnalyzer.cs:665 when its breakdown includes CommentedOutCode"),
   ]),
   ("empty-catch-block", [
    dict(messages=[r"^(?:EmptyCatchBlock|OnErrorResumeSwallow)(?: repeated (?:across \d+ files|\d+ times in (?:one file|\d+ files)))?:"],
        source="engine/src/Core/ExplicitDebt/DebtMarker.cs EmptyCatchBlock and OnErrorResumeSwallow (VB 'On Error Resume Next' with no reset/Err check — the documented VB twin of an empty catch)"),
   ]),
   ("unused-code", [
    dict(messages=[r"^(?:WriteOnlyPrivateField|ObsoleteWithoutCallers)(?: repeated (?:across \d+ files|\d+ times in (?:one file|\d+ files)))?:", "^Dead code: "],
        source="engine/src/Scanner/ExplicitDebt/D17/ExplicitDebtAnalyzer.cs:388 Dead code (Roslyn SymbolFinder: no reference); engine/src/Core/ExplicitDebt/DebtMarker.cs WriteOnlyPrivateField (private field assigned, read nowhere — dead state) and ObsoleteWithoutCallers ('a dead-code candidate')"),
   ]),
   ("unreachable-code", [
    dict(messages=[r"^(?:DeadPreprocessorBranch)(?: repeated (?:across \d+ files|\d+ times in (?:one file|\d+ files)))?:"],
        source="engine/src/Core/ExplicitDebt/DebtMarker.cs DeadPreprocessorBranch: #if on a symbol no build configuration defines — a conditional-compilation region that can never compile (exactly unreachable-code's description)"),
   ]),
   ("obsolete-symbol-still-used", [
    dict(messages=[r"^(?:ObsoleteWithCallers)(?: repeated (?:across \d+ files|\d+ times in (?:one file|\d+ files)))?:"],
        source="engine/src/Core/ExplicitDebt/DebtMarker.cs:65 ObsoleteWithCallers; engine/src/Core/ExplicitDebt/RoslynExplicitDebtCollector.cs:4588 (callerCount > 0)"),
   ]),
  ]),
  off=[
   dict(message=r"^(?:InvertedExistenceGuard|InvertedNullGuard|DiscardedPureResult|DeadLoopAccumulator)(?: repeated (?:across \d+ files|\d+ times in (?:one file|\d+ files)))?:",
        source="engine/src/Core/ExplicitDebt/DebtMarker.cs: logic defects (no-op guarded call, deref inside the proved-null branch, discarded string result, loop accumulator reset before test) — live code whose EFFECT is dead; no D17 concept denotes them"),
   dict(message=r"^(?:ContradictedWarningsAsErrors|ShadowedAnalyzerSeverity|DemotedWarningsAsErrors)(?: repeated (?:across \d+ files|\d+ times in (?:one file|\d+ files)))?:",
        source="engine/src/Core/ExplicitDebt/DebtMarker.cs: dead or relaxed build-gate configuration (WarningsAsErrors entry defeated by NoWarn, editorconfig severity overridden later in the same section, TreatWarningsAsErrors switched back to false) — no warning or rule is disabled by the reported line"),
   dict(message=r"^(?:CoverageExclusion)(?: repeated (?:across \d+ files|\d+ times in (?:one file|\d+ files)))?:",
        source="engine/src/Core/ExplicitDebt/DebtMarker.cs: [ExcludeFromCodeCoverage] on production code — coverage-measurement debt, not a diagnostic suppression"),
  ]),
 "IC1": dict(
  concepts=OrderedDict([
   ("incomplete-implementation", [
    dict(messages=[r"^(?:Hollow method — returns a constant without doing the work|Fake-async — async method never awaits|Empty method body(?: — does nothing with its inputs)?|Skeleton type — most members are unfinished|Markup wires an event to an empty handler|Guard cannot change the result — returns what the code already falls through to|Comparison is always (?:true|false) — nothing compares (?:unequal|equal) to NaN|Both branches are identical — the condition decides nothing|Both branches open with the same statements — the condition does not decide them|Member throws (?:NotSupportedException|UnsupportedError)|Method throws [\w.]+|Method raises NotImplementedError with a reason):"],
        source="engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.Phases.cs:284-297 (empty-with-params, hollow, fake-async, NotSupported, empty void); engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.Phases.cs:209 + engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.{JavaScript,Java,Dart,Ruby,Scala}.cs skeleton type; engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.cs:3439 empty markup handler, :3354 inert guard, :3489 NaN comparison, :3595-3596 identical branches; NotSupported/UnsupportedError/UnsupportedOperationException and Ruby's NotImplementedError-with-a-reason are the engine's 'Soft' throw-only shape (engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.{JavaScript,Java,Dart,Ruby,Scala}.cs: Dart:195, Ruby:185, Scala:164) — a stub by shape, NOT a NotImplementedException placeholder"),
   ]),
   ("unreachable-code", [
    dict(messages=["^(?:Dead branch — condition is always false|Dead `#if false` region|Condition was already decided — an earlier guard makes this test constant):"],
        source="engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.Phases.cs:323 + engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.{JavaScript,Java,Dart,Ruby,Scala}.cs literal-false branch; engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.Phases.cs:455 #if false region; engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.cs:3681 (detail :3679: 'its else … is unreachable' / 'everything it guards is unreachable')"),
   ]),
   ("not-implemented-placeholder", [
    dict(messages=['^Unfinished stub — (?:throws NotImplementedException|throws a "not implemented" exception|throws UnimplementedError|raises NotImplementedError|body is \\?\\?\\? / NotImplementedError):', "^Placeholder data left in code:"],
        source="engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.Phases.cs:274-282 (NotImplementedException method/property, informal 'not implemented' exception), Dart:192, Ruby:182, Scala:161; engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.Phases.cs:512-518 placeholder value / placeholder e-mail — the concept's 'NotImplementedException throws or placeholder literals'"),
   ]),
   ("commented-out-code", [
    dict(messages=["^Commented-out code:"],
        source="engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.Phases.cs:476, :499"),
   ]),
   ("suppressed-diagnostic", [
    dict(messages=["^Blanket warning suppression:"],
        source="engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.Phases.cs:464 (#pragma warning disable with no codes) + engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.{JavaScript,Java,Dart,Ruby,Scala}.cs (bare eslint-disable / @ts-nocheck, scalastyle:off / @nowarn, …); no census message yet"),
   ]),
   ("skipped-test-without-reason", [
    dict(messages=["^Disabled test: A test is skipped/ignored —"],
        source="engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.Phases.cs:562-565 (reason empty) + engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.{JavaScript,Java,Dart,Ruby,Scala}.cs disabled-test arms; with a reason the row is off-concept"),
   ]),
  ]),
  off=[
   dict(message='^Disabled test: A test is skipped \\("',
        source="engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.Phases.cs:564 skip WITH a stated reason (opt-in suite) — skipped-test-without-reason requires no documented reason"),
   dict(message="^Skipped test marks a known-real bug:",
        source="engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.Phases.cs:556 skip whose reason says flaky/broken — reason documented; a known-bug marker, no IC1 concept"),
   dict(message="^Bound check compiled out of the shipping build:",
        source="engine/src/Scanner/Incompleteness/IC1/IncompletenessAnalyzer.cs:835 only a Debug.Assert establishes the length before indexing (CWE-617/129); not an incompleteness shape and not index-access-outside-bounds-guard (no emptiness test guards a sibling branch)"),
  ]),
 "D31": D31_SPEC,
 "D36": dict(
  concepts=OrderedDict([
   ("build-provenance-and-signing", [
    dict(messages=[r"^(?:No\ build\ provenance|No\ SBOM|No\ artifact\ signing|No\ checksums\ published\ for\ release\ artifacts|Packages\ are\ published\ outside\ CI|Release\ artifacts\ are\ built\ outside\ CI|Release\ publish\ overrides\ the\ uncommitted\-changes\ check):"],
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:2816 No build provenance, :2833 No SBOM, :2910 No artifact signing; engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.ReleaseChecksums.cs:69 (no digest for release assets: the artifact cannot be verified); engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.PublishTrigger.cs:454 / .ReleaseTrigger.cs:241 (release built/published from a workstation — the engine's own detail: 'the gap the signing, provenance and SBOM rows all presuppose'); engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:2650 (cargo publish --allow-dirty: the published artifact is not the committed source)"),
   ]),
   ("unpinned-ci-action", [
    dict(messages=[r"^(?:Unpinned\ build\ actions):"],
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:2468 (GitHub Actions `uses:` by floating ref instead of commit SHA)"),
   ]),
   ("mutable-image-reference", [
    dict(messages=[r"^(?:CI\ runs\ a\ third\-party\ container\ image\ from\ a\ mutable\ tag):"],
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:2571 (a `run:` step executes `docker run image:tag` — a runtime image pulled by a mutable tag, not a `uses:` action reference, so mutable-image-reference rather than unpinned-ci-action)"),
   ]),
   ("download-without-integrity-check", [
    dict(messages=[r"^(?:CI\ installs\ an\ unverified\ third\-party\ binary|CI\ verifies\ a\ third\-party\ binary\ against\ a\ checksum\ from\ the\ same\ origin):"],
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:2527-2530 (a run: step downloads a binary onto PATH / into the build with no, or a same-origin and therefore ineffective, checksum — 'unverified installer download in … CI')"),
   ]),
   ("security-tooling-in-ci", [
    dict(messages=[r"^(?:No\ dependency\ advisory\ monitoring|Dependency\ advisory\ scan\ runs\ only\ on\ code\ events|Dependency\ scanning\ workflow\ never\ runs\ automatically):"],
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:10057, :8786, :8802 (dependency-update / advisory automation absent or not scheduled)"),
   ]),
   ("dependencies-not-locked", [
    dict(messages=[r"^(?:Release\ job\ installs\ an\ unrecorded\ dependency\ closure):"],
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.ReleaseInstallLock.cs:159 (release job resolves dependencies with no lockfile committed anywhere in the tree); no census row yet"),
   ]),
   ("ci-secret-exposure", [
    dict(messages=[r"^(?:Secret\ exported\ as\ workflow\-level\ env|Secret\ handed\ to\ the\ step\ that\ runs\ a\ pull\ request's\ code):"],
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:8659 (secret promoted to workflow-wide env), :8674 (secret given to the step running PR code)"),
   ]),
   ("ci-token-excessive-permissions", [
    dict(messages=[r"^(?:Workflow\ token\ permissions\ not\ restricted|PR\-triggered\ workflow\ without\ a\ permissions\ block|Fork\-triggerable\ workflow\ runs\ with\ an\ unscoped\ write\ token|Base\-context\ workflow\ trigger\ runs\ with\ an\ unscoped\ token|Workflow\ holding\ a\ long\-lived\ secret\ is\ unscoped|Release\-publishing\ job\ runs\ with\ an\ unscoped\ token|Job\-level\ write\ token\ spans\ steps\ that\ do\ not\ need\ it|PR\-triggered\ workflow\ grants\ a\ write\-scoped\ token|Workflow\ token\ grant\ is\ wider\ than\ its\ jobs\ use):"],
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:8490, :8505, :8520, :8538, :8566, :8584, :8708, :8728, :8748 (GITHUB_TOKEN left at the default scope or granted wider than the job uses)"),
   ]),
   ("secret-in-process-arguments", [
    dict(messages=[r"^(?:Secret\ passed\ as\ a\ command\-line\ argument):"],
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:8694"),
   ]),
  ]),
  off=[
   dict(message="^Job token omits the `?contents`? scope its checkout needs:",
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:8768 (UNDER-scoped token: checkout will fail — a correctness defect, the opposite of excess permission)"),
   dict(message=r"^(?:Dependency\ source\ pinned\ to\ a\ moving\ git\ ref):",
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:2493 (Cargo git dependency at a branch/tag in the manifest; not 'no lockfile' — no existing concept)"),
   dict(message=r"^(?:Build\ toolchain\ pinned\ to\ two\ different\ Go\ versions):",
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:2629 (toolchain drift)"),
   dict(message=r"^(?:Release\ publish\ runs\ through\ a\ build\ or\ test\ step\ that\ cannot\ fail):",
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:2672 (continue-on-error on a release build/test step; gate honesty, not provenance)"),
   dict(message=r"^(?:Packaging\ script\ can\ name\ the\ release\ artifact\ with\ an\ empty\ version):",
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:2697"),
   dict(message=r"^(?:Release\ publish\ has\ no\ approval\ gate):",
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:8605 (release governance)"),
   dict(message=r"^(?:npm\ publish\ authenticates\ with\ a\ long\-lived\ registry\ token):",
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.NpmRegistryAuth.cs:360 (publish credential type; trusted publishing is an enabler of provenance, not provenance itself)"),
   dict(message=r"^(?:CODEOWNERS\ assigns\ no\ owner\ to\ any\ path):",
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:10262 (review ownership)"),
   dict(message=r"^(?:Branch\ protection\ requires\ a\ status\ check\ that\ cannot\ report):",
        source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:10587"),
  ]),
 "D29": dict(
  concepts=OrderedDict([
   ("sql-injection", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?quoted\-identifier\-interpolation\-not\-doubled\-csharp|(?:watchdog-)?quoted\-identifier\-interpolation\-not\-doubled\-go|(?:watchdog-)?quoted\-interpolation\-into\-sql\-literal\-elixir|(?:watchdog-)?quoted\-interpolation\-into\-sql\-literal\-fsharp|(?:watchdog-)?quoted\-interpolation\-into\-sql\-literal\-rust|(?:watchdog-)?quoted\-interpolation\-into\-sql\-literal\-vb|(?:watchdog-)?formatted\-sql\-statement\-inline\-go|(?:watchdog-)?prisma\-raw\-query\-unsafe\-api\-ts|pyramid\-sqlalchemy\-sql\-injection|laravel\-api\-route\-sql\-injection|sql\-injection\-db\-cursor\-execute|sql\-injection\-using\-extra\-where|find\-sql\-string\-concatenation|tainted\-sql\-from\-http\-request|doctrine\-orm\-dangerous\-query|(?:express\-)?sequelize\-injection|gorm\-dangerous\-method\-usage|sql\-injection\-using\-rawsql|extends\-custom\-expression|jdbc\-sql\-formatted\-string|custom\-expression\-as\-sql|laravel\-unsafe\-validator|sqlalchemy\-sql\-injection|sql\-injection\-using\-raw|string\-formatted\-query|avoid\-query\-set\-extra|avoid\-sqlalchemy\-text|laravel\-sql\-injection|formatted\-sql\-string|tainted\-slick\-sqli|tainted\-sql\-string|activerecord\-sqli|sqlalchemy\-sqli|node\-knex\-sqli|sequelize\-sqli|avoid\-raw\-sql|database\-sqli|psycopg\-sqli|pymssql\-sqli|pymysql\-sqli|ruby\-pg\-sqli|tainted\-sqli|csharp\-sqli|mysql2\-sqli|sequel\-sqli|spring\-sqli|mysql\-sqli|check\-sql|knex\-sqli|pg\-sqli):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("command-injection", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?interpolated\-value\-into\-windows\-raw\-command\-line\-rust|(?:watchdog-)?quoted\-interpolation\-into\-process\-arguments\-csharp|(?:watchdog-)?computed\-navigation\-target\-shell\-executed\-csharp|(?:watchdog-)?quoted\-interpolation\-into\-shell\-command\-kotlin|(?:watchdog-)?shell\-argv\-flattened\-into\-command\-string|(?:watchdog-)?posix\-quoting\-into\-windows\-shell\-rust|(?:watchdog-)?request\-value\-to\-process\-start\-csharp|(?:watchdog-)?markdown\-embedded\-command\-exec\-rust|dangerous\-subprocess\-use\-tainted\-env\-args|command\-injection\-formatted\-runtime\-call|dangerous\-asyncio\-shell\-tainted\-env\-args|dangerous\-spawn\-process\-tainted\-env\-args|dangerous\-asyncio\-exec\-tainted\-env\-args|dangerous\-system\-call\-tainted\-env\-args|dangerous\-os\-exec\-tainted\-env\-args|dangerous\-asyncio\-create\-exec|formatted\-string\-bashoperator|tainted\-cmd\-from\-http\-request|command\-injection\-os\-system|avoid\-tainted\-shell\-call|dangerous\-subprocess\-use|dangerous\-asyncio\-shell|dangerous\-spawn\-process|dangerous\-asyncio\-exec|tainted\-system\-command|dangerous\-system\-call|paramiko\-exec\-command|subprocess\-shell\-true|detect\-child\-process|subprocess\-injection|os\-system\-injection|dangerous\-exec\-cmd|deno\-dangerous\-run|dangerous\-os\-exec|spawn\-git\-clone|dangerous\-exec|tainted\-exec):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("code-injection", [
    dict(messages=[r"^\w+: (?:dangerous\-subinterpreters\-run\-string\-tainted\-env\-args|dangerous\-testcapi\-run\-in\-subinterp\-tainted\-env\-args|dangerous\-interactive\-code\-run\-tainted\-env\-args|(?:watchdog-)?assembled\-code\-string\-evaluated\-ts|dangerous\-subinterpreters\-run\-string|dangerous\-testcapi\-run\-in\-subinterp|check\-unsafe\-reflection\-methods|(?:express\-)?insecure\-template\-usage|dangerous\-interactive\-code\-run|(?:express\-)?sandbox\-code\-injection|globals\-misuse\-code\-execution|detect\-eval\-with\-expression|dangerous\-template\-string|vm\-runincontext\-injection|razor\-template\-injection|check\-unsafe\-reflection|script\-engine\-injection|user\-eval\-format\-string|user\-exec\-format\-string|render\-template\-string|(?:express\-)?vm2\-injection|(?:express\-)?vm\-injection|dangerous\-execution|code\-string\-concat|tainted\-code\-exec|tainted\-callable|require\-request|eval\-injection|exec\-injection|spel\-injection|eval\-detected|exec\-detected|el\-injection|listen\-eval|assert\-use|ruby\-eval|user\-eval|user\-exec|bad\-send):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("path-traversal", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?request\-param\-to\-file\-read\-sink\-scala|(?:watchdog-)?request\-param\-to\-fs\-delete\-sink\-ts|avoid_send_file_without_path_sanitization|(?:watchdog-)?request\-param\-to\-fs\-read\-sink\-ts|check\-dynamic\-render\-local\-file\-include|path\-traversal\-inside\-zip\-extraction|(?:express\-)?path\-join\-resolve\-traversal|check\-render\-local\-file\-include|httpservlet\-path\-traversal|avoid\-render\-dynamic\-path|avoid\-tainted\-file\-access|request\-data\-fileresponse|path\-traversal\-file\-name|(?:watchdog-)?zip\-slip\-csharp|avoid\-tainted\-ftp\-call|filepath\-clean\-misuse|jax\-rs\-path\-traversal|alias\-path\-traversal|(?:express\-)?res\-sendfile|res\-render\-injection|(?:watchdog-)?zip\-slip\-go|path\-traversal\-open|unsafe\-path\-combine|tainted\-file\-path|check\-send\-file|file\-disclosure):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("xml-external-entity", [
    dict(messages=[r"^\w+: (?:documentbuilderfactory\-external\-parameter\-entities\-true|documentbuilderfactory\-external\-general\-entities\-true|documentbuilderfactory\-disallow\-doctype\-decl\-missing|documentbuilderfactory\-disallow\-doctype\-decl\-false|(?:watchdog-)?xmltextreader\-dtd\-entity\-expansion\-csharp|(?:watchdog-)?xmldocument\-dtd\-entity\-expansion\-csharp|saxparserfactory\-disallow\-doctype\-decl\-missing|xmlinputfactory\-external\-entities\-enabled|xmlreadersettings\-unsafe\-parser\-override|transformerfactory\-dtds\-not\-disabled|xmldocument\-unsafe\-parser\-override|xmltextreader\-unsafe\-defaults|xmlinputfactory\-possible\-xxe|documentbuilder\-dtd\-enabled|xmlinputfactory\-dtd\-enabled|documentbuilderfactory\-xxe|(?:express\-)?xml2json\-xxe\-event|use\-defused\-xml\-parse|(?:express\-)?libxml\-noent|(?:express\-)?xml2json\-xxe|use\-defused\-xmlrpc|(?:express\-)?expat\-xxe|sax\-dtd\-enabled|use\-defused\-xml|xml2json\-xxe|expat\-xxe|sax\-xxe):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("insecure-deserialization", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?unsafe\-binary\-to\-term\-socket\-erlang|(?:watchdog-)?binaryformatter\-constructed\-fsharp|(?:express\-)?third\-party\-object\-deserialization|insecure\-binaryformatter\-deserialization|insecure\-netdatacontract\-deserialization|server\-dangerous\-object\-deserialization|(?:watchdog-)?binaryformatter\-constructed\-vb|insecure\-soapformatter\-deserialization|insecure\-losformatter\-deserialization|go\-unsafe\-deserialization\-interface|insecure\-fspickler\-deserialization|avoid\-insecure\-deserialization|jackson\-unsafe\-deserialization|tainted\-pickle\-deserialization|insecure\-jms\-deserialization|insecure\-deserialization|tainted\-deserialization|object\-deserialization|cookie\-serialization|multiprocessing\-recv|avoid\-unsafe\-ruamel|bad\-deserialization|avoid\-pyyaml\-load|avoid\-cPickle|marshal\-usage|avoid\-pickle|avoid\-shelve|xml\-decoder|avoid\-dill):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("cross-site-scripting", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?react\-dangerouslysetinnerhtml\-typed\-props\-ts|(?:watchdog-)?react\-hoc\-wrapped\-dangerouslysetinnerhtml\-ts|(?:watchdog-)?formatted\-attribute\-marked\-safe\-gotemplate|(?:watchdog-)?markup\-joined\-to\-unescaped\-html\-value\-ruby|(?:watchdog-)?react\-dangerouslysetinnerhtml\-template\-ts|(?:watchdog-)?template\-var\-in\-dedented\-script\-block|(?:watchdog-)?vue\-vhtml\-unsanitised\-response\-markup|(?:watchdog-)?ejs\-raw\-output\-in\-express\-view|(?:watchdog-)?unrestricted\-href\-scheme\-razor|wip\-xss\-using\-responsewriter\-and\-printf|(?:watchdog-)?angular\-input\-to\-innerhtml\-ts|reflected\-data\-httpresponsebadrequest|(?:watchdog-)?react\-style\-css\-injection\-ts|response\-contains\-unsanitized\-input|template\-var\-unescaped\-with\-safeseq|template\-blocktranslate\-no\-escape|directly\-returned\-format\-string|template\-translate\-as\-no\-escape|detect\-angular\-trust\-as\-method|detect\-disable\-mustache\-escape|pyramid\-direct\-use\-of\-response|incorrect\-autoescape\-disabled|(?:react\-)?dangerouslysetinnerhtml|unknown\-value\-with\-script\-tag|xssrequestwrapper\-is\-insecure|detect\-angular\-element\-taint|(?:react\-)?markdown\-insecure\-html|template\-unescaped\-with\-safe|unescaped\-template\-extension|xss\-from\-unescaped\-url\-param|(?:angular\-)?bypasssecuritytrust|detect\-angular\-sce\-disabled|missing\-autoescape\-disabled|reflected\-data\-httpresponse|(?:react\-)?unsanitized\-property|servletresponse\-writer\-xss|unescaped\-data\-in\-htmlattr|xss\-send\-mail\-html\-message|formatted\-template\-string|no\-direct\-response\-writer|(?:react\-)?unsanitized\-method|mako\-templates\-detected|template\-autoescape\-off|context\-autoescape\-off|unquoted\-attribute\-var|direct\-response\-write|global\-autoescape\-off|tainted\-html\-response|unescaped\-data\-in\-url|unescaped\-data\-in\-js|tainted\-html\-string|xss\-html\-email\-body|var\-in\-script\-tag|avoid\-mark\-safe|printed\-request|raw\-html\-concat|raw\-html\-format|echoed\-request|avoid\-link\-to|var\-in\-href):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("regex-denial-of-service", [
    dict(messages=[r"^\w+: (?:regular\-expression\-dos\-infinite\-timeout|regular\-expression\-dos|check\-regex\-dos):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("ldap-injection", [
    dict(messages=[r"^\w+: (?:tainted\-ldapi\-from\-http\-request|ldap\-injection):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("xpath-injection", [
    dict(messages=[r"^\w+: (?:tainted\-xpath\-from\-http\-request|xpath\-injection):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("server-side-request-forgery", [
    dict(messages=[r"^\w+: (?:chrome\-remote\-interface\-compilescript\-injection|dynamic\-urllib\-use\-detected|(?:express\-)?puppeteer\-injection|avoid\-tainted\-http\-request|(?:express\-)?phantom\-injection|ssrf\-injection\-requests|ssrf\-injection\-urllib|(?:watchdog-)?ssrf\-csharp|dynamic\-proxy\-host|tainted\-filename|tainted\-url\-host|(?:watchdog-)?ssrf\-go|(?:watchdog-)?ssrf\-js|io\-source\-ssrf|ssrf\-requests|wp\-ssrf\-audit|(?:express\-)?ssrf):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("open-redirect", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?open\-redirect\-request\-accessor\-js|(?:watchdog-)?open\-redirect\-default\-operand\-js|(?:watchdog-)?open\-redirect\-location\-header\-js|spring\-unvalidated\-redirect|unknown\-value\-in\-redirect|redirect\-to\-request\-uri|(?:express\-)?open\-redirect|unvalidated\-redirect|check\-redirect\-to|js\-open\-redirect|avoid\-redirect|open\-redirect):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("weak-cryptographic-algorithm", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?handrolled\-secret\-prefix\-mac\-go|crypto\-mode\-without\-authentication|insecure\-cipher\-algorithm\-blowfish|avoid\-implementing\-custom\-digests|defaulthttpclient\-is\-deprecated|no\-static\-initialization\-vector|use_deprecated_cipher_algorithm|use_weak_rsa_encryption_padding|blowfish\-insufficient\-key\-size|insecure\-cipher\-algorithm\-arc4|insecure\-cipher\-algorithm\-idea|insecure\-cipher\-algorithm\-des|insecure\-cipher\-algorithm\-rc2|insecure\-cipher\-algorithm\-rc4|insecure\-cipher\-algorithm\-xor|ssl\-wrap\-socket\-is\-deprecated|insufficient\-dsa\-key\-size|insufficient\-rsa\-key\-size|insecure\-cipher\-mode\-ecb|insufficient\-ec\-key\-size|tls\-with\-insecure\-cipher|missing\-ssl\-minversion|openssl\-cbc\-static\-iv|desede\-is\-deprecated|insecure\-ssl\-version|missing\-ssl\-version|use\-of\-weak\-rsa\-key|cbc\-padding\-oracle|ssl\-v3\-is\-insecure|use\-of\-default\-aes|des\-is\-deprecated|gcm\-no\-tag\-length|weak\-ssl\-context|weak\-ssl\-version|gcm\-nonce\-reuse|rsa\-padding\-set|use\-of\-blowfish|no\-null\-cipher|rsa\-no\-padding|use\-of\-aes\-ecb|aead\-no\-final|use_ecb_mode|ecb\-cipher|use\-of\-DES|use\-of\-rc2|use\-of\-rc4):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("weak-hash-algorithm", [
    dict(messages=[r"^\w+: (?:insecure\-hash\-algorithm\-sha1|insecure\-hash\-algorithm\-md2|insecure\-hash\-algorithm\-md4|insecure\-hash\-algorithm\-md5|use\-of\-md5\-digest\-utils|insecure\-hash\-function|md5\-used\-as\-password|unsafe\-argon2\-config|weak\-hashes\-sha1|weak\-hashes\-md5|use\-of\-sha224|sha224\-hash|use\-of\-sha1|use\-of\-md5):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("insecure-randomness", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?weak\-random\-credential\-go|use_weak_rng_for_keygeneration|detect\-pseudoRandomBytes|insecure\-uuid\-version|math\-random\-used|weak\-random):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("missing-authorization", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?supabase\-rls\-anon\-insert\-sql|(?:watchdog-)?supabase\-rls\-anon\-write\-sql|(?:watchdog-)?supabase\-rls\-disabled\-sql|missing\-or\-broken\-authorization|(?:watchdog-)?authz\-fails\-open\-ts|check\-unscoped\-find):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665); engine-native ids (same title format): engine/src/Scanner/Security/D29/Scanners/SupabaseRlsOpenPolicyScan.cs:68-74,155'),
   ]),
   ("mass-assignment", [
    dict(messages=[r"^\w+: (?:mass\-assignment\-protection\-disabled|mass\-assignment\-vuln|mass\-assignment|create\-with):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("error-information-exposure", [
    dict(messages=[r"^\w+: (?:stacktrace\-disclosure):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("improper-certificate-validation", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?csr\-extension\-passthrough\-go|(?:watchdog-)?inverted\-tls\-verify\-flag\-go|(?:watchdog-)?insecure\-skip\-verify\-go|X509\-subject\-name\-validation|insecure\-hostname\-verifier|disabled\-cert\-validation|httpsconnection\-detected|insecure\-smtp\-connection|curl\-ssl\-verifypeer\-off|skip\-tls\-verify\-cluster|skip\-tls\-verify\-service|insecure\-trust\-manager|unverified\-ssl\-context|ssl\-mode\-no\-verify):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("token-signature-or-expiry-not-validated", [
    dict(messages=[r"^\w+: (?:jwt\-tokenvalidationparameters\-no\-expiry\-validation|java\-jwt\-decode\-without\-verify|jwt\-go\-parse\-unverified|unsigned\-security\-token|jwt\-go\-none\-algorithm|unverified\-jwt\-decode|jwt\-python\-none\-alg|jwt\-simple\-noverify|java\-jwt\-none\-alg|jwt\-none\-alg):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("hardcoded-password", [
    dict(messages=[r"^\w+: (?:rds\-insecure\-password\-storage\-in\-source\-code|detected\-username\-and\-password\-in\-uri|hardcoded\-password\-default\-argument|hardcoded\-http\-auth\-in\-controller|build\-gradle\-password\-hardcoded):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("hardcoded-cryptographic-key", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?hardcoded\-cookie\-signing\-secret\-ts|check\-rails\-session\-secret\-handling|avoid_hardcoded_config_SECRET_KEY|(?:express\-)?session\-hardcoded\-secret|hardcoded\-secret\-rsa\-passphrase|(?:express\-)?jwt\-hardcoded\-secret|jwt\-python\-hardcoded\-secret|scala\-jwt\-hardcoded\-secret|java\-jwt\-hardcoded\-secret|hardcoded\-jwt\-secret|jwt\-scala\-hardcode|hardcoded\-jwt\-key|empty\-aes\-key):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("hardcoded-credential", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?static\-cloud\-credential\-in\-workflow|(?:watchdog-)?secret\-env\-literal\-fallback\-ts|aws\-lambda\-environment\-credentials|detected\-stripe\-restricted\-api\-key|aws\-provider\-static\-credentials|hardcoded\-passport\-secret|google\-maps\-apikeyleak|secrets\-in\-config\-file|hardcoded\-token|check\-secrets):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("sensitive-data-in-logs", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?credential\-written\-to\-log\-ts|python\-logger\-credential\-disclosure):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("ci-workflow-injection", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?network\-fetched\-value\-laundered\-through\-step\-output|(?:watchdog-)?untrusted\-context\-laundered\-through\-job\-environment|(?:watchdog-)?untrusted\-context\-laundered\-through\-step\-output|(?:watchdog-)?untrusted\-context\-into\-quoted\-github\-script|(?:watchdog-)?workflow\-run\-artifact\-into\-privileged\-value|(?:watchdog-)?fixed\-delimiter\-untrusted\-workflow\-output|(?:watchdog-)?untrusted\-context\-into\-action\-shell\-input|(?:watchdog-)?untrusted\-context\-laundered\-across\-jobs|(?:watchdog-)?manifest\-metadata\-into\-workflow\-output|argo\-workflow\-parameter\-command\-injection|(?:watchdog-)?release\-tag\-name\-into\-run\-shell|allowed\-unsecure\-commands|github\-script\-injection|run\-shell\-injection):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("ci-secret-exposure", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?checkout\-credential\-persisted\-in\-privileged\-job|(?:watchdog-)?comment\-command\-checks\-out\-and\-builds\-fork\-code|(?:watchdog-)?comment\-command\-builds\-fork\-code\-with\-secrets|(?:watchdog-)?privileged\-trigger\-secret\-to\-unpinned\-action|(?:watchdog-)?secret\-into\-unpinned\-action|(?:watchdog-)?secret\-promoted\-to\-job\-env|pull\-request\-target\-code\-checkout|workflow\-run\-target\-code\-checkout|gha\-workflow\-env\-secret|secrets\-inherit):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("unpinned-ci-action", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?anchored\-mutable\-docker\-action\-tag|(?:watchdog-)?mutable\-reusable\-workflow\-ref|(?:watchdog-)?mutable\-circleci\-orb\-version|(?:watchdog-)?anchored\-mutable\-action\-tag|(?:watchdog-)?mutable\-docker\-action\-tag|github\-actions\-mutable\-action\-tag):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("download-without-integrity-check", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?external\-repo\-checkout\-built\-unpinned|(?:watchdog-)?expression\-blinded\-fetch\-exec\-in\-run|(?:watchdog-)?unverified\-shell\-installer\-download|(?:watchdog-)?unpinned\-git\-source\-install\-in\-run|(?:watchdog-)?powershell\-fetch\-exec\-in\-appveyor|(?:watchdog-)?powershell\-fetch\-exec\-in\-script|(?:watchdog-)?unverified\-powershell\-download|(?:watchdog-)?mutable\-ref\-fetch\-exec\-in\-run|(?:watchdog-)?substituted\-fetch\-exec\-in\-run|(?:watchdog-)?powershell\-fetch\-exec\-in\-run|(?:watchdog-)?unverified\-appveyor\-download|(?:watchdog-)?unverified\-download\-in\-make|(?:watchdog-)?unverified\-download\-in\-run|(?:watchdog-)?fetch\-exec\-pipe\-in\-make|gha\-curl\-pipe\-shell|curl\-eval):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("end-of-life-platform", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?eol\-dotnet\-runtime\-in\-workflow|(?:watchdog-)?eol\-python\-runtime\-in\-workflow|(?:watchdog-)?eol\-action\-major\-in\-workflow|(?:watchdog-)?eol\-go\-toolchain\-in\-workflow|(?:watchdog-)?eol\-node\-runtime\-in\-workflow):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("insecure-cookie-flags", [
    dict(messages=[r"^\w+: (?:pyramid\-authtkt\-cookie\-httponly\-unsafe\-default|pyramid\-authtkt\-cookie\-httponly\-unsafe\-value|pyramid\-authtkt\-cookie\-secure\-unsafe\-default|pyramid\-authtkt\-cookie\-secure\-unsafe\-value|pyramid\-set\-cookie\-httponly\-unsafe\-default|pyramid\-set\-cookie\-samesite\-unsafe\-default|pyramid\-set\-cookie\-httponly\-unsafe\-value|pyramid\-set\-cookie\-samesite\-unsafe\-value|pyramid\-set\-cookie\-secure\-unsafe\-default|pyramid\-set\-cookie\-secure\-unsafe\-value|(?:express\-)?cookie\-session\-no\-httponly|(?:express\-)?cookie\-session\-no\-secure|pyramid\-authtkt\-cookie\-samesite|session\-cookie\-missing\-httponly|conf\-insecure\-cookie\-settings|session\-cookie\-missing\-secure|session\-cookie\-samesitenone|cookie\-missing\-secure\-flag|(?:django\-)?secure\-set\-cookie|cookie\-missing\-httponly|cookie\-missing\-secure|secure\-set\-cookie):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("iac-misconfiguration", [
    dict(messages=[r"^\w+: (?:aws\-ec2\-launch\-template\-metadata\-service\-v1\-enabled|aws\-elasticsearch\-nodetonode\-encryption\-not\-enabled|gcp\-sql\-database\-ssl\-insecure\-value\-postgres\-mysql|aws\-insecure\-cloudfront\-distribution\-tls\-version|azure\-appservice\-detailed\-errormessages\-enabled|aws\-lambda\-permission\-unrestricted\-source\-arn|gcp\-sql\-database\-ssl\-insecure\-value\-sqlserver|aws\-insecure\-redshift\-ssl\-configuration|aws\-sqs\-queue\-policy\-wildcard\-principal|aws\-elasticsearch\-insecure\-tls\-version|aws\-cloudwatch\-log\-group\-no\-retention|aws\-config\-aggregator\-not\-all\-regions|aws\-ecr\-repository\-wildcard\-principal|aws\-efs\-filesystem\-encrypted\-with\-cmk|awscdk\-bucket\-grantpublicaccessmethod|aws\-insecure\-api\-gateway\-tls\-version|aws\-ebs\-snapshot\-encrypted\-with\-cmk|aws\-lambda\-x\-ray\-tracing\-not\-active|azure\-mssql\-service\-mintls\-version|insecure\-load\-balancer\-tls\-version|appservice\-authentication\-enabled|aws\-codebuild\-project\-unencrypted|appservice\-use\-secure\-tls\-policy|aws\-documentdb\-auditing\-disabled|aws\-subnet\-has\-public\-ip\-address|azure\-appservice\-min\-tls\-version|aws\-glacier\-vault\-any\-principal|awscdk\-codebuild\-project\-public|unrestricted\-github\-oidc\-policy|appservice\-require\-client\-cert|aws\-dynamodb\-table\-unencrypted|aws\-kinesis\-stream\-unencrypted|aws\-kms\-key\-wildcard\-principal|azure\-mysql\-encryption\-enabled|aws\-iam\-admin\-policy\-ssoadmin|storage\-use\-secure\-tls\-policy|appservice\-enable\-https\-only|azure\-key\-no\-expiration\-date|gcp\-sql\-database\-require\-ssl|aws\-rds\-backup\-no\-retention|awscdk\-sqs\-unencryptedqueue|azure\-appservice\-https\-only|eks\-public\-endpoint\-enabled|aws\-db\-instance\-no\-logging|aws\-ebs\-volume\-unencrypted|aws\-ecr\-mutable\-image\-tags|azure\-mysql\-mintls\-version|public\-s3\-policy\-statement|aws\-cdk\-bucket\-enforcessl|gcp\-cloud\-storage\-logging|gcp\-dns\-key\-specs\-rsasha1|awscdk\-bucket\-encryption|appservice\-enable\-http2|gcp\-sql\-public\-database|aws\-ec2\-has\-public\-ip|s3\-unencrypted\-bucket|storage\-enforce\-https|aws\-iam\-admin\-policy|aws\-provisioner\-exec|wildcard\-assume\-role|aws\-ebs\-unencrypted|aws\-kms\-no\-rotation|ec2\-imdsv1\-optional|s3\-public\-rw\-bucket|public\-s3\-bucket):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("overly-permissive-rbac", [
    dict(messages=[r"^\w+: (?:legacy\-api\-clusterrole\-excessive\-permissions):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665); a ClusterRole granting legacy-API wildcard permissions'),
   ]),
   ("nosql-injection", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?value\-interpolated\-into\-predicate\-format\-swift|dynamodb\-filter\-injection|dynamodb\-request\-object):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; CWE-943 by each rule\'s own metadata (NoSQL filter / request object built from the event or request; NSPredicate format string)'),
   ]),
   ("prototype-pollution", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?prototype\-lookup\-request\-key\-js):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; engine/rulesets/semgrep/watchdog-sast.yml watchdog-prototype-lookup-request-key-js: a request value used as a bracket-lookup key, CWE-1321 by its own metadata'),
   ]),
   ("log-injection", [
    dict(messages=[r"^\w+: (?:crlf\-injection\-logs):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665); registry java.lang.security.audit.crlf-injection-logs (baked in p/security-audit and p/owasp-top-ten): untrusted data put into a logger without neutralising CR/LF, so an attacker can forge log entries — CWE-117 by its own message (its metadata cites the parent CWE-93)'),
   ]),
   ("container-excessive-privilege", [
    dict(messages=[r"^\w+: (?:no\-sudo\-in\-dockerfile):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665); umbrella residue (contract 1.3 parent): a Dockerfile that runs sudo — privilege, but none of the precise container concepts'),
   ]),
   ("container-security-context-missing", [
    dict(messages=[r"^\w+: (?:allow\-privilege\-escalation\-no\-securitycontext):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665); the container declares no securityContext at all'),
   ]),
   ("host-path-mount", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?docker\-socket\-mount\-in\-run):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665); a CI step bind-mounts the Docker socket into a container (engine/rulesets/semgrep/watchdog-sast.yml)'),
   ]),
   ("container-privilege-escalation-allowed", [
    dict(messages=[r"^\w+: (?:allow\-privilege\-escalation\-true|allow\-privilege\-escalation):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665); allowPrivilegeEscalation true or not set to false'),
   ]),
   ("container-runs-as-root", [
    dict(messages=[r"^\w+: (?:run\-as\-non\-root\-unsafe\-value|missing\-user\-entrypoint|last\-user\-is\-root|missing\-user):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665); runAsNonRoot false, no USER before ENTRYPOINT/CMD, last USER root, no USER'),
   ]),
   ("container-confinement-profile-unset", [
    dict(messages=[r"^\w+: (?:seccomp\-confinement\-disabled):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665); seccomp unconfined'),
   ]),
   ("privileged-container", [
    dict(messages=[r"^\w+: (?:privileged\-service):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665); docker-compose service with privileged: true'),
   ]),
   ("mutable-image-reference", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?mutable\-circleci\-executor\-image|(?:watchdog-)?mutable\-service\-container\-image|(?:watchdog-)?mutable\-job\-container\-image):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("unbounded-allocation-from-untrusted-length", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?unbounded\-alloc\-from\-wire\-length\-go):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("unsynchronized-shared-state", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?unsynchronised\-counter\-in\-http\-handler\-go|(?:watchdog-)?accessor\-mutates\-shared\-state\-go):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("unreachable-code", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?dead\-branch\-from\-retested\-contains\-guard\-go|WD\-RUBY\-RESCUE\-ORDER\-0001):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665); engine-native ids (same title format): engine/src/Core/Languages/Ruby/Security/RubyUnreachableRescueClauseScan.cs:82,462'),
   ]),
   ("unused-code", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?dead\-private\-field\-dart|WD\-RUBY\-DUPLICATE\-METHOD\-0001):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665); engine-native ids (same title format): engine/src/Core/Languages/Ruby/Security/RubyDuplicateMethodDefinitionScan.cs:71,359'),
   ]),
   ("silent-error-fallback", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?error\-swallowed\-as\-success\-go):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("redundant-condition-operand", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?inert\-affix\-guard\-conjunct\-rust):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("missing-subresource-integrity", [
    dict(messages=[r"^\w+: (?:use\-SRI\-for\-CDNs):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("secret-in-process-arguments", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?secret\-in\-argv\-csharp|(?:watchdog-)?secret\-in\-argv\-go|(?:watchdog-)?secret\-in\-argv\-ts|(?:watchdog-)?secret\-interpolated\-into\-run):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665); watchdog-secret-interpolated-into-run (engine/rulesets/semgrep/watchdog-sast.yml:10303, metadata CWE-214 first, CWE-532) is HERE, not ci-secret-exposure: a secret expanded by `${{ }}` into a run script lands verbatim in the script file and in the argument vector of the commands it launches (its own message: "a `ps` listing of the commands it launches"); no untrusted code receives it, which is what ci-secret-exposure denotes'),
   ]),
   ("cleartext-transmission", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?cleartext\-subresource\-markup|request\-session\-http\-in\-with\-context|grpc\-client\-insecure\-connection|grpc\-nodejs\-insecure\-connection|grpc\-server\-insecure\-connection|http\-not\-https\-connection|request\-session\-with\-http|(?:react\-)?insecure\-request|httpget\-http\-request|plaintext\-http\-link|require\-encryption|unencrypted\-socket|insecure\-redirect|no\-auth\-over\-http|request\-with\-http|force\-ssl\-false|telnetlib|use\-tls):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("dependency-release-cooldown-missing", [
    dict(messages=[r"^\w+: (?:poetry\-missing\-solver\-min\-release\-age|renovate\-missing\-minimum\-release\-age|bundler\-gemfile\-missing\-cooldown|bun\-missing\-minimum\-release\-age|npm\-missing\-minimum\-release\-age|uv\-missing\-dependency\-cooldown|yarn\-missing\-minimal\-age\-gate|dependabot\-missing\-cooldown|pnpm\-minimum\-release\-age):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
   ("sensitive-data-in-token-payload", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?card\-verification\-value\-in\-claims\-csharp|(?:watchdog-)?payment\-card\-in\-jwt\-payload\-csharp|(?:watchdog-)?credential\-in\-jwt\-payload\-csharp|(?:watchdog-)?credential\-in\-jwt\-payload\-python|(?:watchdog-)?credential\-in\-jwt\-payload\-scala|(?:watchdog-)?credential\-in\-jwt\-payload\-java|(?:watchdog-)?credential\-in\-jwt\-payload\-go|(?:watchdog-)?credential\-in\-jwt\-payload\-ts):"],
        source='engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61; a registry id led by react-/angular-/vue-/jquery-/express-/django-/flask-/rails- loses that prefix when the repo does not declare the framework (engine/src/Scanner/Security/D29/Scanners/ForeignFrameworkAdvice.cs:177-232, applied at StaticAnalysisAnalyzer.cs:665)'),
   ]),
  ]),
  off=[
   dict(message=r"^\w+: (?:(?:watchdog-)?global\-tilde\-expansion\-bound\-home\-rust|(?:watchdog-)?git\-ref\-parsed\-by\-fixed\-field\-index|(?:watchdog-)?empty\-glob\-character\-class\-rust|(?:watchdog-)?map\-order\-in\-rendered\-text\-go|(?:watchdog-)?map\-order\-in\-joined\-slice\-go|(?:watchdog-)?global\-tilde\-expansion\-rust|missing\-self\-transfer\-check\-ercx|insecure\-use\-string\-copy\-fn|system\-wildcard\-detected|check\-validation\-regex|detect\-buffer\-noassert|insecure\-use\-strcat\-fn|insecure\-use\-strtok\-fn|insecure\-use\-scanf\-fn|insecure\-use\-gets\-fn|bad\-hexa\-conversion|use\-of\-unsafe\-block|bash_reverse_shell|divide\-by\-zero|use\-after\-free|double\-free):",
        source='memory-safety, unsafe C/Go primitives, wildcard shell args, reverse-shell IOC, Solidity, Ruby anchor regex and other non-security correctness defects (CWE-119/242/415/416/676/704/369/155/185/330-map-order/41): no catalogue concept; engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61'),
   dict(message=r"^\w+: (?:http\-response\-splitting|insecure\-use\-printf\-fn|csv\-writer\-injection|request\-data\-write|header\-injection|twiml\-injection):",
        source='header / CSV / TwiML / printf-format injection - no matching injection concept (CWE-113/1236/91/134; log injection is the log-injection concept, NoSQL and predicate-format injection the nosql-injection concept); engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61'),
   dict(message=r"^\w+: (?:(?:watchdog-)?decompression\-bomb\-zip\-entry\-go|potential\-dos\-via\-decompression\-bomb|(?:watchdog-)?http\-server\-no\-timeouts\-go|random\-fd\-exhaustion):",
        source='resource exhaustion (decompression bomb, missing server timeouts, fd exhaustion) - no catalogue concept; engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61'),
   dict(message=r"^\w+: (?:spring\-actuator\-dangerous\-endpoints\-enabled\-yaml|spring\-actuator\-dangerous\-endpoints\-enabled|spring\-actuator\-fully\-enabled\-yaml|(?:express\-)?check\-directory\-listing|http\-listener\-wildcard\-bindings|avoid_hardcoded_config_TESTING|spring\-actuator\-fully\-enabled|avoid\-bind\-to\-all\-interfaces|avoid_hardcoded_config_DEBUG|avoid_using_app_run_directly|avoid_app_run_with_bad_host|avoid_hardcoded_config_ENV|open\-directory\-listing|fs\-directory\-listing|insecure\-module\-used|pprof\-debug\-exposure|exported_activity|debug\-enabled|url\-rewriting|scalac\-debug|phpinfo\-use):",
        source='debug mode / management endpoint / directory listing / bind-all exposure (CWE-489/200/548/668/706): no catalogue concept; engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61'),
   dict(message=r"^\w+: (?:avoid\-ssh\-insecure\-ignore\-host\-key|paramiko\-implicit\-trust\-host\-key|(?:flask\-)?url\-for\-external\-true|use\-of\-basic\-authentication|check\-http\-verb\-confusion|anonymous\-ldap\-bind|check\-before\-filter|request\-host\-used|filter\-skipping):",
        source='authentication / access posture without a missing-authorization endpoint (anonymous LDAP bind, basic auth, Rails filter allowlist, verb confusion, host header, SSH host-key trust); engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61'),
   dict(message=r"^\w+: (?:(?:watchdog-)?module\-specifier\-built\-from\-environment\-ts|dynamic\-httptrace\-clienttrace|tainted\-object\-instantiation|ldap\-entry\-poisoning|extract\-user\-data|reflect\-makefunc):",
        source='unsafe reflection / dynamic dispatch (CWE-470/913) - not evaluation of code; the prototype key lookup is the prototype-pollution concept; engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61'),
   dict(message=r"^\w+: (?:(?:watchdog-)?recursive\-ownership\-change\-rooted\-at\-caller\-chosen\-directory|(?:watchdog-)?world\-writable\-directory\-for\-restricted\-file\-go|overly\-permissive\-file\-permission|(?:watchdog-)?archive\-entry\-mode\-go|insecure\-file\-permissions|bad\-tmp\-file\-creation):",
        source='file permissions / ownership / temp files (CWE-276/732/377): no catalogue concept; engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61'),
   dict(message=r"^\w+: (?:cors\-misconfiguration|all\-origins\-allowed|permissive\-cors|wildcard\-cors):",
        source='permissive CORS policy (CWE-942/346/183): no catalogue concept; engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61'),
   dict(message=r"^\w+: (?:(?:watchdog-)?postmessage\-opener\-source\-guard\-without\-origin\-ts|(?:watchdog-)?postmessage\-embedded\-frame\-unverified\-sender\-ts|(?:watchdog-)?postmessage\-inline\-handler\-dynamic\-dispatch\-ts|(?:watchdog-)?postmessage\-named\-handler\-dynamic\-dispatch\-js|pyramid\-csrf\-origin\-check\-disabled\-globally|detect\-no\-csrf\-before\-method\-override|pyramid\-csrf\-check\-disabled\-globally|pyramid\-csrf\-origin\-check\-disabled|wildcard\-postmessage\-configuration|websocket\-missing\-origin\-check|unrestricted\-request\-mapping|conf\-csrf\-headers\-bypass|(?:flask\-)?wtf\-csrf\-disabled|missing\-csrf\-protection|spring\-csrf\-disabled|no\-csrf\-exempt):",
        source='CSRF / origin protection disabled (CWE-352/346/940): no catalogue concept; engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61'),
   dict(message=r"^\w+: (?:(?:watchdog-)?password\-verified\-by\-decrypting\-stored\-value\-ts|(?:watchdog-)?credential\-compared\-in\-query\-predicate\-go|(?:watchdog-)?cookie\-deletion\-without\-expiry\-go|(?:watchdog-)?secret\-env\-nonsecret\-fallback\-ts|(?:watchdog-)?hex\-digest\-compared\-loosely\-php|(?:express\-)?cookie\-session\-default\-name|(?:express\-)?cookie\-session\-no\-expires|tainted\-session\-from\-http\-request|(?:express\-)?cookie\-session\-no\-domain|(?:express\-)?cookie\-session\-no\-path|tainted\-env\-from\-http\-request|use\-none\-for\-password\-default|(?:watchdog-)?optional\-mac\-key\-go|avoid\-session\-manipulation|hashids\-with\-django\-secret|hashids\-with\-flask\-secret|(?:express\-)?jwt\-not\-revoked|password\-empty\-string|unvalidated\-password|tainted\-session):",
        source='credential handling weaknesses that are not a hard-coded secret: reversible/plaintext password storage, weak secret fallback, password policy, revocation, session/cookie hygiene beyond Secure/HttpOnly/SameSite; engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61'),
   dict(message=r"^\w+: (?:possible\-nginx\-h2c\-smuggling|dynamic\-proxy\-scheme|header\-redefinition|missing\-internal):",
        source='nginx / server configuration (header redefinition, h2c smuggling, internal location, proxy scheme): not IaC in the catalogue\'s sense and no specific concept; engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61'),
   dict(message=r"^\w+: (?:(?:watchdog-)?electron\-openexternal\-bridged\-unvalidated|(?:watchdog-)?electron\-ipc\-bridge\-channel\-passthrough|(?:watchdog-)?electron\-navigation\-prefix\-allowlist\-ts|(?:watchdog-)?electron\-navigation\-inert\-guard\-ts|(?:watchdog-)?electron\-node\-integration\-ts|x\-frame\-options\-misconfiguration|visualforce\-page\-api\-version|csp\-header\-attribute):",
        source='Electron / browser hardening (CWE-1188/749/1385/451/1021): no catalogue concept; engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61'),
   dict(message=r"^\w+: (?:swift\-user\-defaults):",
        source='sensitive data in unprotected mobile device storage (iOS UserDefaults, CWE-311/922) - the browser-storage concept is D32\'s and names browser storage; engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61'),
   dict(message=r"^\w+: (?:(?:watchdog-)?unbounded\-tag\-trigger\-publish\-without\-environment|(?:watchdog-)?force\-moved\-release\-pointer\-tag\-in\-workflow|(?:watchdog-)?mutable\-container\-tag\-published\-in\-workflow|(?:watchdog-)?comment\-approval\-gate\-without\-author\-check|(?:watchdog-)?floating\-toolchain\-version\-in\-setup\-action|(?:watchdog-)?unpinned\-package\-install\-in\-run|(?:watchdog-)?floating\-release\-tool\-version|(?:watchdog-)?unbounded\-go\-toolchain\-range|(?:watchdog-)?nonfatal\-integrity\-check\-go|(?:watchdog-)?archived\-action\-dependency|pnpm\-block\-exotic\-sub\-dependencies|openai\-consequential\-action\-false|detect\-shai\-hulud\-backdoor|pnpm\-trust\-policy):",
        source='CI posture that is neither injection, secret exposure, action pinning nor remote-exec: unpinned package/tool versions, archived action, tag-moving, mutable tag publishing, ungated publish, comment approval gate, malicious-workflow IOC, LLM action flag, pnpm trust policy; engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61'),
   dict(message=r"^\w+: (?:(?:watchdog-)?field\-round\-trip\-writes\-back\-to\-different\-field\-js|(?:watchdog-)?error\-reported\-then\-nil\-interface\-dereferenced\-go|(?:watchdog-)?sorted\-singleton\-excluded\-by\-off\-by\-one\-guard\-go|(?:watchdog-)?closed\-channel\-arm\-continues\-the\-select\-loop\-go|(?:watchdog-)?broad\-rescue\-guard\-not\-keyed\-on\-exception\-ruby|(?:watchdog-)?redundant\-re\-defaulting\-of\-normalised\-value\-js|(?:watchdog-)?instance\-field\-assigned\-as\-bare\-identifier\-js|(?:watchdog-)?diagnostics\-gated\-on\-nested\-error\-checks\-go|(?:watchdog-)?regex\-match\-index\-beyond\-capture\-groups\-js|(?:watchdog-)?class\-method\-called\-as\-bare\-identifier\-js|(?:watchdog-)?expiry\-sweep\-exits\-after\-first\-removal\-go|(?:watchdog-)?presized\-slice\-hole\-from\-skipped\-index\-go|(?:watchdog-)?fold\-step\-error\-discarded\-by\-continue\-go|(?:watchdog-)?deferred\-close\-in\-archive\-entry\-loop\-go|(?:watchdog-)?inverted\-error\-classification\-helper\-go|(?:watchdog-)?parameter\-overwritten\-before\-return\-go|(?:watchdog-)?blocking\-send\-in\-nil\-context\-guard\-go|(?:watchdog-)?discarded\-close\-error\-written\-file\-go|(?:watchdog-)?lock\-acquisition\-failure\-not\-gated\-go|(?:watchdog-)?error\-logged\-then\-zero\-value\-used\-go|(?:watchdog-)?error\-overwritten\-before\-any\-test\-go|(?:watchdog-)?paired\-walk\-bounded\-by\-one\-length\-go|(?:watchdog-)?captured\-parameter\-written\-back\-go|(?:watchdog-)?tally\-divided\-by\-foreign\-length\-go|(?:watchdog-)?loop\-carried\-error\-overwritten\-go|(?:watchdog-)?nil\-agreement\-guard\-then\-deref\-go|(?:watchdog-)?unchecked\-catch\-binding\-deref\-ts|(?:watchdog-)?discarded\-close\-flush\-error\-go|(?:watchdog-)?unbound\-identifier\-assigned\-js|(?:watchdog-)?string\-keyed\-context\-value\-go|(?:watchdog-)?unchecked\-map\-lookup\-deref\-go|(?:watchdog-)?unchecked\-document\-assert\-go|(?:watchdog-)?splice\-from\-ranged\-slice\-go|(?:watchdog-)?usize\-underflow\-panic\-rust|(?:watchdog-)?fabricated\-array\-bound\-go|(?:watchdog-)?discarded\-write\-error\-go):",
        source='engine-authored correctness checks (nil/err handling, bounds, dead stores, unbound identifiers, map order, catch-binding derefs ...; CWE-125/129/193/248/252/391/457/476/563/665/667/694/703/772/1164): real defects that no D29 concept denotes; engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61'),
   dict(message=r"^\w+: (?:(?:watchdog-)?shell\-quoted\-argument\-in\-argv\-exec\-ruby|(?:watchdog-)?unencoded\-segment\-appended\-to\-url\-ruby|(?:watchdog-)?html\-entity\-in\-rendered\-dart\-literal|(?:watchdog-)?backtick\-only\-escape):",
        source='incomplete / wrong escaping that is a correctness defect, not an exploitable sink (CWE-116/838); engine/src/Scanner/Security/Shared/Scanners/ScanParsers.cs:794,823 (title = "{severity}: {semgrep check_id after its last \'.\'}"); check ids enumerated from the analyzer image\'s baked packs (engine/docker/analyzer/Dockerfile:570-571 bakes p/security-audit + p/owasp-top-ten; :595 copies engine/rulesets/semgrep/watchdog-sast.yml), all three passed by engine/src/Scanner/Security/D29/StaticAnalysisAnalyzer.cs:55-61'),
   dict(message=r"^\w+: (?:WD\-RUBY\-ARGUMENT\-MUTATED\-0001):",
        source="engine/src/Core/Languages/Ruby/Security/RubyArgumentMutatedScan.cs:76,787: engine-native correctness check (WD-RUBY-ARGUMENT-MUTATED-0001); no D29 concept denotes it"),
   dict(message=r"^\w+: (?:WD\-RUBY\-RESCUE\-DISCARDS\-CAUGHT\-0001):",
        source="engine/src/Core/Languages/Ruby/Security/RubyRescueDiscardsCaughtErrorScan.cs:98,428: engine-native correctness check (WD-RUBY-RESCUE-DISCARDS-CAUGHT-0001); no D29 concept denotes it"),
   dict(message=r"^\w+: (?:(?:watchdog-)?identifier\-read\-out\-of\-scope\-js):",
        source="engine/src/Scanner/Security/D29/Scanners/JsSiblingScopeReadScan.cs:61,636: engine-native correctness check (watchdog-identifier-read-out-of-scope-js); no D29 concept denotes it"),
  ]),
 "D32": dict(
  concepts=OrderedDict([
   ("sensitive-data-in-logs", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?sensitive\-personal\-data\-in\-log\-elixir|(?:watchdog-)?sensitive\-personal\-data\-in\-log\-erlang|(?:watchdog-)?sensitive\-personal\-data\-in\-log\-fsharp|(?:watchdog-)?sensitive\-personal\-data\-in\-log\-dart|(?:watchdog-)?sensitive\-personal\-data\-in\-log\-rust|(?:watchdog-)?sensitive\-personal\-data\-in\-log\-vb|(?:watchdog-)?sensitive\-personal\-data\-in\-log|(?:watchdog-)?personal\-data\-in\-log\-elixir|(?:watchdog-)?personal\-data\-in\-log\-erlang|(?:watchdog-)?personal\-data\-in\-log\-fsharp|(?:watchdog-)?personal\-data\-in\-log\-dart|(?:watchdog-)?personal\-data\-in\-log\-rust|(?:watchdog-)?personal\-data\-in\-log\-vb|(?:watchdog-)?personal\-data\-in\-log):"],
        source='engine/src/Scanner/Security/D32/DataComplianceAnalyzer.cs:30-32,68 (semgrep --config p/gdpr = engine/rulesets/semgrep/gdpr.yml, baked by engine/docker/analyzer/Dockerfile:595, parsed by the same ScanParsers.SemgrepResult) -> title "{severity}: {check id}" (ScanParsers.cs:794,823); ids from engine/rulesets/semgrep/gdpr.yml:138-674'),
   ]),
   ("sensitive-data-in-url", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?personal\-data\-in\-url\-regex\-lens|(?:watchdog-)?personal\-data\-in\-url\-dart|(?:watchdog-)?personal\-data\-in\-url):"],
        source='engine/src/Scanner/Security/D32/DataComplianceAnalyzer.cs:30-32,68 (semgrep --config p/gdpr = engine/rulesets/semgrep/gdpr.yml, baked by engine/docker/analyzer/Dockerfile:595, parsed by the same ScanParsers.SemgrepResult) -> title "{severity}: {check id}" (ScanParsers.cs:794,823); ids from engine/rulesets/semgrep/gdpr.yml:138-674'),
   ]),
   ("sensitive-data-in-browser-storage", [
    dict(messages=[r"^\w+: (?:(?:watchdog-)?personal\-data\-in\-browser\-storage):"],
        source='engine/src/Scanner/Security/D32/DataComplianceAnalyzer.cs:30-32,68 (semgrep --config p/gdpr = engine/rulesets/semgrep/gdpr.yml, baked by engine/docker/analyzer/Dockerfile:595, parsed by the same ScanParsers.SemgrepResult) -> title "{severity}: {check id}" (ScanParsers.cs:794,823); ids from engine/rulesets/semgrep/gdpr.yml:138-674'),
   ]),
  ]),
  off=[
  ]),
}

for _d, _s in TABLE.items():
    assert _d not in SPEC, _d
    SPEC[_d] = _s

FAMILY = {c: "hardcoded-secret" for c in ("hardcoded-credential", "hardcoded-password", "hardcoded-cryptographic-key", "committed-private-key")}
# A weak digest used on a password and a password stored without an adequate KDF are one defect seen from two rules
# (an MD5 password hash is both): a scanner reporting the site under the sibling is credited at plants and charged at
# traps (CONTRACT.md, Concept families). ci-secret-exposure and secret-in-process-arguments are NOT a family: the
# taxonomy makes them disjoint (untrusted code receives the secret vs. the process list / script text shows it), and the
# one rule that blurred them (watchdog-secret-interpolated-into-run) is mapped to the concept its CWE-214 names.
FAMILY.update({c: "weak-password-hashing" for c in ("weak-hash-algorithm", "insufficient-password-hashing")})
IGNORE = [OrderedDict(rule=r"^D28$", message=r"^Rotate the exposed credentials",
                      reason="D28's repository-level roll-up of its located history rows (engine/src/Scanner/Security/D28/SecretsHistoryAnalyzer.cs:392), not a separate finding")]

# Contract 1.3 `locationFromMessage`: D36's workflow rows carry NO SARIF location (a posture row, one per pattern, not
# per site) although their detail names the sites. The first site named becomes the location (D36 prints at most three,
# FirstThree, SupplyChainProvenanceAnalyzer.cs:8818). Only a result with no SARIF location is relocated. A basename
# ("release.yml:7") suffix-matches every file of that name, so two workflows of one name in different directories
# would both match it — no frozen key has that.
D36_SITE_SRC = ("engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:8583,8603,8658,8673,8707,8726,"
                "8747,8765,8785,8801 (\"{Path.GetFileName(file)}:{line} (…)\" sites in the detail of the token, secret, "
                "release-gate and advisory-schedule rows; result written without a location, "
                "engine/src/CodeHealth.Reporting/Sarif/SarifReportRenderer.cs:331-355)")
LOCATION_FROM_MESSAGE = [
    OrderedDict(rule=r"^D36$", message=r"^Secret passed as a command-line argument:",
                pattern=r"logs a command line\): (?P<file>[^\s:;]+): ",
                source="engine/src/Scanner/SecurityPosture/D36/SupplyChainProvenanceAnalyzer.cs:8690-8697 (detail "
                       "lists \"{relative path}: {command line}\" sites, :8946) — the file, no line"),
    OrderedDict(rule=r"^D36$", pattern=r"(?<![\w./-])(?P<file>[\w./-]+\.(?:ya?ml|toml|json)):(?P<line>\d+)\b",
                source=D36_SITE_SRC),
]

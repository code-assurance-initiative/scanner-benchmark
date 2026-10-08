"""Build mappings/semgrep.json: Semgrep Community Edition rule ids -> the benchmark's concepts.

    python3 mappings/semgrep-build/build.py [--check]

Semgrep ships no mapping to this taxonomy. This one was authored by the operator of PILOT-2026-10 for the rule set
`p/default` (Semgrep 1.179.0; the rule ids the registry served on 2026-10-08), from each rule's id, CWE tag and
description — NOT from where its results landed in any answer key. A rule is mapped to a concept only when what the
rule detects is what the concept denotes; a rule that detects something the taxonomy has no concept for is recorded
under `offConcept` (its results map to no concept, so they are `uncovered`, never noise), and a concept no rule maps
is listed under `unmapped` (its plants are false negatives). Only rule families that can fire on the file types the
training set contains (C#, JS/TS, HTML, YAML Kubernetes / compose / GitHub Actions, Dockerfile, JSON, nginx and
language-agnostic secret patterns) are mapped; rules for other languages (Python, Java, Go, Ruby, PHP, Terraform, …)
map to no concept — on these units such a result would be `uncovered`.

Semgrep's SARIF ruleId is the full dotted rule id, whose last segment usually repeats the rule name
(`generic.secrets.security.detected-github-token.detected-github-token`). Each stem below matches the id with or
without that repeated segment; a stem ending in `.` matches every rule under it.

Dimensions: every concept is reported under ONE CAI rubric dimension, its "home" dimension, so that per-dimension
figures of different engines are taken over the same plants: the first dimension the CAI reference implementation's
mapping gives the concept, else the first non-D29 dimension of the Watchdog mapping, else its first (`home_dimensions`).
`--check` exits 1 when the committed mapping is not the build of this file.
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
OUT = os.path.join(ROOT, "mappings", "semgrep.json")

SEMGREP_VERSION = "1.179.0"
CONFIG = "p/default"

S = "generic.secrets.security."
JS = "javascript."
K8S = "yaml.kubernetes.security."
DC = "yaml.docker-compose.security."
GHA = "yaml.github-actions.security."

# concept -> rule-id stems
RULES = {
    "hardcoded-credential": [S + "detected-" + n for n in (
        "amazon-mws-auth-token", "artifactory-token", "aws-access-key-id-value", "aws-appsync-graphql-key",
        "aws-secret-access-key", "aws-session-token", "codeclimate", "facebook-access-token", "facebook-oauth",
        "generic-api-key", "generic-secret", "github-token", "google-oauth-access-token", "heroku-api-key",
        "hockeyapp", "jwt-token", "kolide-api-key", "mailchimp-api-key", "mailgun-api-key",
        "npm-registry-auth-token", "onfido-live-api-token", "outlook-team", "paypal-braintree-access-token",
        "picatic-api-key", "sauce-token", "sendgrid-api-key", "slack-token", "slack-webhook", "snyk-api-key",
        "softlayer-api-key", "sonarqube-docs-api-key", "square-access-token", "square-oauth-secret",
        "stripe-api-key", "stripe-restricted-api-key", "telegram-bot-api-key", "twilio-api-key")]
        + [S + "google-maps-apikeyleak"],
    "hardcoded-password": [S + "detected-" + n for n in ("artifactory-password", "ssh-password", "bcrypt-hash",
                                                         "etc-shadow")],
    "committed-private-key": [S + "detected-private-key", S + "detected-pgp-private-key-block"],
    "hardcoded-cryptographic-key": [
        JS + "express.security.audit.express-session-hardcoded-secret",
        JS + "express.security.express-jwt-hardcoded-secret",
        JS + "jose.security.jwt-hardcode.hardcoded-jwt-secret",
        JS + "jsonwebtoken.security.jwt-hardcode.hardcoded-jwt-secret",
        JS + "passport-jwt.security.passport-hardcode.hardcoded-passport-secret",
        JS + "lang.security.audit.hardcoded-hmac-key"],
    "sql-injection": [
        "csharp.lang.security.sqli.csharp-sqli",
        *(JS + f"aws-lambda.security.{n}-sqli" for n in ("knex", "mysql", "pg", "sequelize")),
        *(JS + f"lang.security.audit.sqli.node-{n}-sqli" for n in ("knex", "mssql", "mysql", "postgres")),
        JS + "sequelize.security.audit.sequelize-injection-express.express-sequelize-injection"],
    "nosql-injection": [JS + "aws-lambda.security.dynamodb-request-object"],
    "command-injection": [
        "csharp.lang.security.injections.os-command.os-command-injection",
        JS + "aws-lambda.security.detect-child-process", JS + "lang.security.detect-child-process",
        JS + "lang.security.audit.spawn-shell-true", JS + "lang.security.audit.dangerous-spawn-shell",
        JS + "lang.security.spawn-git-clone", JS + "shelljs.security.shelljs-exec-injection",
        JS + "deno.security.audit.deno-dangerous-run"],
    "code-injection": [
        "csharp.dotnet.security.razor-template-injection",
        JS + "browser.security.eval-detected", JS + "lang.security.detect-eval-with-expression",
        JS + "lang.security.audit.code-string-concat", JS + "aws-lambda.security.tainted-eval",
        JS + "aws-lambda.security.vm-runincontext-injection", JS + "express.security.express-vm-injection",
        JS + "express.security.express-vm2-injection",
        JS + "express.security.express-sandbox-injection.express-sandbox-code-injection",
        JS + "express.security.express-insecure-template-usage", JS + "express.security.require-request",
        JS + "sandbox.security.audit.sandbox-code-injection", JS + "vm2.security.audit.vm2-code-injection",
        JS + "vm2.security.audit.vm2-context-injection", JS + "thenify.security.audit.multiargs-code-execution",
        JS + "bluebird.security.audit.tofastproperties-code-execution",
        JS + "playwright.security.audit.playwright-addinitscript-code-injection",
        JS + "playwright.security.audit.playwright-evaluate-arg-injection",
        JS + "playwright.security.audit.playwright-evaluate-code-injection",
        JS + "puppeteer.security.audit.puppeteer-evaluate-arg-injection",
        JS + "puppeteer.security.audit.puppeteer-evaluate-code-injection",
        JS + "chrome-remote-interface.security.audit.chrome-remote-interface-compilescript-injection"],
    "server-side-request-forgery": [
        *(f"csharp.lang.security.ssrf.{n}.ssrf" for n in ("http-client", "rest-client", "web-client",
                                                          "web-request")),
        JS + "express.security.audit.express-ssrf", JS + "apollo.security.apollo-axios-ssrf",
        JS + "playwright.security.audit.playwright-goto-injection",
        JS + "playwright.security.audit.playwright-setcontent-injection",
        JS + "puppeteer.security.audit.puppeteer-goto-injection",
        JS + "puppeteer.security.audit.puppeteer-setcontent-injection",
        JS + "phantom.security.audit.phantom-injection", JS + "express.security.express-phantom-injection",
        JS + "express.security.express-puppeteer-injection",
        JS + "express.security.express-wkhtml-injection.express-wkhtmltoimage-injection",
        JS + "express.security.express-wkhtml-injection.express-wkhtmltopdf-injection",
        JS + "wkhtmltoimage.security.audit.wkhtmltoimage-injection",
        JS + "wkhtmltopdf.security.audit.wkhtmltopdf-injection",
        "generic.nginx.security.dynamic-proxy-host"],
    "path-traversal": [
        "csharp.lang.security.filesystem.unsafe-path-combine",
        JS + "lang.security.audit.path-traversal.path-join-resolve-traversal",
        JS + "express.security.audit.express-path-join-resolve-traversal",
        JS + "express.security.audit.express-res-sendfile", JS + "express.security.audit.res-render-injection",
        "generic.nginx.security.alias-path-traversal"],
    "cross-site-scripting": [
        JS + "angular.security.", "typescript.angular.security.audit.angular-domsanitizer.angular-bypasssecuritytrust",
        JS + "audit.detect-replaceall-sanitization", JS + "aws-lambda.security.tainted-html-response",
        JS + "aws-lambda.security.tainted-html-string", JS + "browser.security.raw-html-concat",
        JS + "express.security.audit.xss.", JS + "express.security.injection.raw-html-format",
        JS + "fbjs.security.audit.insecure-createnodesfrommarkup", JS + "lang.security.audit.unknown-value-with-script-tag",
        JS + "lang.security.detect-disable-mustache-escape", JS + "monaco-editor.security.audit.monaco-hover-htmlsupport",
        JS + "serialize-javascript.security.audit.unsafe-serialize-javascript",
        JS + "vue.security.audit.xss.templates.avoid-v-html",
        "typescript.react.security.audit.react-dangerouslysetinnerhtml",
        "typescript.react.security.audit.react-unsanitized-method", "typescript.react.security.react-markdown-insecure-html"],
    "xml-external-entity": [
        "csharp.lang.security.xxe.", JS + "express.security.audit.express-libxml-noent",
        JS + "express.security.audit.express-libxml-vm-noent", JS + "express.security.audit.express-xml2json-xxe-event",
        JS + "express.security.express-expat-xxe", JS + "express.security.express-xml2json-xxe",
        JS + "node-expat.security.audit.expat-xxe", JS + "sax.security.audit.sax-xxe",
        JS + "xml2json.security.audit.xml2json-xxe"],
    "insecure-deserialization": ["csharp.lang.security.insecure-deserialization.",
                                 JS + "express.security.audit.express-third-party-object-deserialization"],
    "open-redirect": [JS + "browser.security.open-redirect.js-open-redirect",
                      JS + "express.security.audit.express-open-redirect",
                      "typescript.nestjs.security.audit.nestjs-open-redirect"],
    "regex-denial-of-service": ["csharp.lang.security.regular-expression-dos.",
                                JS + "lang.security.audit.detect-non-literal-regexp"],
    "weak-cryptographic-algorithm": ["csharp.dotnet.security.use_ecb_mode"],
    "insecure-randomness": ["csharp.dotnet.security.use_weak_rng_for_keygeneration",
                            JS + "lang.security.detect-pseudorandombytes.detect-pseudoRandomBytes"],
    "insufficient-password-hashing": [JS + "lang.security.audit.md5-used-as-password",
                                      JS + "argon2.security.unsafe-argon2-config"],
    "token-signature-or-expiry-not-validated": [
        "csharp.lang.security.ad.jwt-tokenvalidationparameters-no-expiry-validation",
        JS + "jsonwebtoken.security.audit.jwt-decode-without-verify", JS + "jwt-simple.security.jwt-simple-noverify",
        JS + "jose.security.jwt-none-alg", JS + "jsonwebtoken.security.jwt-none-alg",
        "typescript.react.security.audit.react-jwt-decoded-property"],
    "improper-certificate-validation": [
        "csharp.lang.security.cryptography.x509-subject-name-validation.X509-subject-name-validation",
        "problem-based-packs.insecure-transport.js-node.bypass-tls-verification",
        JS + "sequelize.security.audit.sequelize-tls-disabled-cert-validation",
        K8S + "skip-tls-verify-cluster", K8S + "skip-tls-verify-service"],
    "cleartext-transmission": [
        *(f"problem-based-packs.insecure-transport.js-node.{n}" for n in (
            "ftp-request", "http-request", "rest-http-client-support", "telnet-request", "using-http-server")),
        JS + "lang.security.detect-insecure-websocket", "typescript.react.security.react-insecure-request",
        JS + "sequelize.security.audit.sequelize-enforce-tls", JS + "grpc.security.grpc-nodejs-insecure-connection",
        "html.security.plaintext-http-link", "generic.nginx.security.insecure-redirect",
        "typescript.aws-cdk.security.audit.awscdk-bucket-enforcessl.aws-cdk-bucket-enforcessl"],
    "insecure-cookie-flags": [
        JS + "express.security.audit.express-cookie-settings.express-cookie-session-no-httponly",
        JS + "express.security.audit.express-cookie-settings.express-cookie-session-no-secure",
        "csharp.dotnet.security.web-config-insecure-cookie-settings"],
    "security-response-headers": [JS + "express.security.x-frame-options-misconfiguration",
                                  "typescript.nestjs.security.audit.nestjs-header-xss-disabled",
                                  "generic.nginx.security.header-redefinition"],
    "error-information-exposure": ["csharp.lang.security.stacktrace-disclosure"],
    "mass-assignment": ["csharp.dotnet.security.audit.mass-assignment",
                        JS + "express.security.express-data-exfiltration", JS + "lang.security.insecure-object-assign"],
    "prototype-pollution": [JS + "lang.security.audit.prototype-pollution.prototype-pollution-loop",
                            JS + "express.security.audit.remote-property-injection"],
    "log-injection": [JS + "lang.security.audit.unsafe-formatstring"],
    "sensitive-data-in-browser-storage": ["typescript.react.security.audit.react-jwt-in-localstorage"],
    "sensitive-data-in-token-payload": [JS + "jose.security.audit.jose-exposed-data",
                                        JS + "jsonwebtoken.security.audit.jwt-exposed-data"],
    "missing-subresource-integrity": ["html.security.audit.missing-integrity",
                                      "generic.visualforce.security.ncino.html.usesriforcdns.use-SRI-for-CDNs"],
    "container-runs-as-root": [K8S + "run-as-non-root", "dockerfile.security.missing-user",
                               "dockerfile.security.missing-user-entrypoint", "dockerfile.security.last-user-is-root"],
    "privileged-container": [K8S + "privileged-container", DC + "privileged-service"],
    "container-privilege-escalation-allowed": [K8S + "allow-privilege-escalation",
                                               K8S + "allow-privilege-escalation-true", DC + "no-new-privileges"],
    "container-security-context-missing": [K8S + "allow-privilege-escalation-no-securitycontext"],
    "host-namespace-sharing": [K8S + "hostnetwork-pod", K8S + "hostpid-pod", K8S + "hostipc-pod"],
    "host-path-mount": [K8S + "exposing-docker-socket-hostpath", DC + "exposing-docker-socket-volume",
                        "dockerfile.security.dockerd-socket-mount.dockerfile-dockerd-socket-mount"],
    "container-confinement-profile-unset": [K8S + "seccomp-confinement-disabled", DC + "seccomp-confinement-disabled",
                                            DC + "selinux-separation-disabled"],
    "container-writable-root-filesystem": [DC + "writable-filesystem-service"],
    "overly-permissive-rbac": [K8S + "legacy-api-clusterrole-excessive-permissions"],
    "iac-misconfiguration": ["json.aws.security.public-s3-bucket", "json.aws.security.public-s3-policy-statement",
                             "json.aws.security.wildcard-assume-role",
                             "typescript.aws-cdk.security.awscdk-bucket-grantpublicaccessmethod",
                             "typescript.aws-cdk.security.awscdk-codebuild-project-public"],
    "unpinned-ci-action": [GHA + "github-actions-mutable-action-tag"],
    "ci-workflow-injection": [GHA + "run-shell-injection", GHA + "github-script-injection",
                              "yaml.argo.security.argo-workflow-parameter-command-injection"],
    "ci-secret-exposure": [GHA + "pull-request-target-code-checkout", GHA + "workflow-run-target-code-checkout",
                           GHA + "secrets-inherit", GHA + "gha-workflow-env-secret"],
    "download-without-integrity-check": [GHA + "curl-eval", GHA + "gha-curl-pipe-shell"],
}

# rules that can fire on these file types but detect something the taxonomy has no concept for
OFF_CONCEPT = [
    ("csharp.dotnet.security.mvc-missing-antiforgery", "CSRF (CWE-352): no CSRF concept in the taxonomy"),
    (JS + "express.security.audit.express-check-csurf-middleware-usage", "CSRF (CWE-352): no concept"),
    (JS + "lang.security.detect-no-csrf-before-method-override", "CSRF (CWE-352): no concept"),
    ("python.django.security.django-no-csrf-token", "CSRF in an HTML form (CWE-352): no concept"),
    (JS + "express.security.cors-misconfiguration", "CORS policy (CWE-346): no concept"),
    ("typescript.lang.security.audit.cors-regex-wildcard", "CORS policy (CWE-183): no concept"),
    ("typescript.nestjs.security.audit.nestjs-header-cors-any", "CORS policy (CWE-183): no concept"),
    ("csharp.dotnet.security.net-webconfig-debug", "debug compilation in web.config: no concept"),
    ("csharp.dotnet.security.net-webconfig-trace-enabled", "ASP.NET tracing enabled: no concept"),
    ("csharp.lang.security.http.http-listener-wildcard-bindings", "wildcard listener prefix (CWE-706): no concept"),
    ("csharp.lang.security.memory.memory-marshal-create-span", "out-of-bounds span (CWE-125): no concept"),
    (JS + "express.security.audit.express-cookie-settings.express-cookie-session-default-name",
     "cookie name / domain / path / expiry hardening: not the Secure/HttpOnly/SameSite flags of insecure-cookie-flags"),
    (JS + "express.security.audit.express-cookie-settings.express-cookie-session-no-domain", "as above"),
    (JS + "express.security.audit.express-cookie-settings.express-cookie-session-no-expires", "as above"),
    (JS + "express.security.audit.express-cookie-settings.express-cookie-session-no-path", "as above"),
    (JS + "express.security.audit.express-jwt-not-revoked", "token revocation: no concept"),
    (JS + "express.security.audit.express-check-directory-listing", "directory listing (CWE-548): no concept"),
    (JS + "express.security.audit.express-detect-notevil-usage", "unmaintained sandbox library: no concept"),
    (JS + "ajv.security.audit.ajv-allerrors-true", "validator resource use (CWE-400): no concept"),
    (JS + "lang.security.detect-buffer-noassert", "buffer bounds (CWE-119): no concept"),
    (JS + "lang.security.audit.incomplete-sanitization",
     "first-occurrence-only replace used for escaping: context-free, not a specific injection concept"),
    (JS + "intercom.security.audit.intercom-settings-user-identifier-without-user-hash", "no concept"),
    (JS + "node-crypto.security.aead-no-final", "AEAD misuse: not a deprecated primitive (weak-cryptographic-algorithm)"),
    (JS + "node-crypto.security.create-de-cipher-no-iv", "IV misuse: not a deprecated primitive"),
    (JS + "node-crypto.security.gcm-no-tag-length", "GCM tag length: not a deprecated primitive"),
    (JS + "sequelize.security.audit.sequelize-weak-tls-version", "old TLS version: not cleartext, not a primitive"),
    ("problem-based-packs.insecure-transport.js-node.disallow-old-tls-versions1", "old TLS version: as above"),
    ("problem-based-packs.insecure-transport.js-node.disallow-old-tls-versions2", "old TLS version: as above"),
    ("generic.nginx.security.insecure-ssl-version", "old TLS version: as above"),
    ("generic.nginx.security.missing-ssl-version", "old TLS version: as above"),
    ("generic.nginx.security.dynamic-proxy-scheme", "no concept"),
    ("generic.nginx.security.header-injection", "HTTP header injection (CWE-113): no concept"),
    ("generic.nginx.security.missing-internal", "no concept"),
    ("generic.nginx.security.possible-h2c-smuggling.possible-nginx-h2c-smuggling", "request smuggling (CWE-444): no concept"),
    ("dockerfile.security.no-sudo-in-dockerfile", "sudo in a build step: not one of the container-privilege concepts"),
    ("dockerfile.audit.dockerfile-pip-extra-index-url", "dependency confusion (CWE-427): no concept"),
    (GHA + "allowed-unsecure-commands", "deprecated set-env/add-path commands enabled: no concept"),
    (GHA + "detect-shai-hulud-backdoor", "a known backdoor workflow: no concept"),
    ("generic.unicode.security.bidi.contains-bidirectional-characters", "Trojan Source (bidi characters): no concept"),
    ("generic.ci.security.bash-reverse-shell.bash_reverse_shell", "reverse shell in CI: no concept"),
    ("yaml.kubernetes.security.env.flask-debugging-enabled", "Flask debug mode: no concept"),
    ("yaml.openapi.security.", "OpenAPI / plugin-manifest rules: no concept"),
    ("typescript.aws-cdk.security.audit.awscdk-bucket-encryption", "encryption at rest: data-encryption-controls is a "
     "repository posture, not a per-resource finding"),
    ("typescript.aws-cdk.security.audit.awscdk-sqs-unencryptedqueue", "as above"),
]

FAMILIES = {"hardcoded-secret": ["hardcoded-credential", "hardcoded-password", "hardcoded-cryptographic-key",
                                 "committed-private-key"],
            "untrusted-data-executed": ["code-injection", "insecure-deserialization"],
            "weak-password-hashing": ["weak-hash-algorithm", "insufficient-password-hashing"]}

UNMAPPED_REASON = {
    "secret-in-version-history": "Semgrep CE scans the working tree only, never git history",
    "vulnerable-dependency": "Semgrep CE (p/default) has no dependency/advisory scanning (Supply Chain is a separate, "
                             "non-CE product)",
    "weak-hash-algorithm": "p/default has no C#/JS rule for a weak hash outside password hashing (md5-used-as-password "
                           "maps to insufficient-password-hashing, its family sibling)",
}
DEFAULT_REASON = "no p/default rule detects this"


def stem_regex(stem):
    if stem.endswith("."):
        return "^" + re.escape(stem)
    last = stem.rsplit(".", 1)[-1]
    return "^" + re.escape(stem) + r"(?:\." + re.escape(last) + ")?$"


def home_dimensions(cai_reference, watchdog):
    """concept -> its ONE home CAI dimension: cai-reference's first, else Watchdog's first non-D29, else first."""
    out = {}
    for c in set(cai_reference["concepts"]) | set(watchdog["concepts"]):
        a = cai_reference["concepts"].get(c, {}).get("dimensions", [])
        b = watchdog["concepts"].get(c, {}).get("dimensions", [])
        if a:
            out[c] = a[0]
        elif b:
            out[c] = next((d for d in b if d != "D29"), b[0])
    return out


def build(taxonomy, cai_reference, watchdog):
    home = home_dimensions(cai_reference, watchdog)
    parents = {c["id"]: c["parent"] for c in taxonomy["concepts"] if c.get("parent")}
    fam = {c: f for f, cs in FAMILIES.items() for c in cs}
    ids = [c["id"] for c in taxonomy["concepts"]]
    unknown = sorted(set(RULES) - set(ids))
    if unknown:
        raise SystemExit(f"concepts not in the taxonomy: {unknown}")
    concepts, unmapped = {}, []
    for c in sorted(ids):
        spec = {"rules": [], "dimensions": []}
        if c in RULES:
            if c not in home:
                raise SystemExit(f"{c}: no home dimension")
            spec = {"rules": [stem_regex(s) for s in RULES[c]], "dimensions": [home[c]]}
        else:
            unmapped.append({"concept": c, "reason": UNMAPPED_REASON.get(c, DEFAULT_REASON)})
        if c in fam:
            spec["family"] = fam[c]
        if c in parents:
            spec["parent"] = parents[c]
        concepts[c] = spec
    return {
        "scanner": "semgrep",
        "version": f"semgrep-ce {SEMGREP_VERSION}, config {CONFIG}",
        "notes": [
            "Authored for PILOT-2026-10 by the pilot operator; Semgrep publishes no mapping to this taxonomy "
            "(mappings/semgrep-build/build.py holds the curated table and how it was decided).",
            "SARIF ruleId format: the full dotted Semgrep rule id, e.g. "
            "generic.secrets.security.detected-github-token.detected-github-token; one rule = one concept, so no "
            "message discrimination is needed.",
            f"Rule set: {CONFIG} as served by the Semgrep registry on 2026-10-08 (1074 rules); scan command "
            "`semgrep scan --config p/default --metrics=off --sarif`, default .semgrepignore (which skips test "
            "directories among others).",
            "Dimensions: each concept is reported under its home CAI rubric dimension (see build.py), not a Semgrep "
            "grouping — Semgrep has none that corresponds to the rubric.",
            "Rules for languages the training set does not contain (Python, Java, Go, Ruby, PHP, Terraform, …) "
            "are not mapped: on these units their results are `uncovered`.",
        ],
        "concepts": concepts,
        "unmapped": unmapped,
        "offConcept": [{"rule": stem_regex(s), "source": why} for s, why in OFF_CONCEPT],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--taxonomy", default=os.path.join(ROOT, "taxonomy.json"))
    ap.add_argument("--out", default=OUT)
    ap.add_argument("--check", action="store_true")
    a = ap.parse_args(argv)
    load = lambda p: json.load(open(p, encoding="utf-8"))  # noqa: E731
    doc = build(load(a.taxonomy), load(os.path.join(ROOT, "mappings", "cai-reference.json")),
                load(os.path.join(ROOT, "mappings", "watchdog.json")))
    text = json.dumps(doc, indent=2) + "\n"
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

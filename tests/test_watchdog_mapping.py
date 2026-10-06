"""Pins mappings/watchdog.json (contract 1.1) against message shapes taken verbatim from a real Watchdog scan
(bench-csharp-security-secrets, iteration 1): one dimension-level ruleId carries several concepts, so the message
must decide, and hygiene rows on a secret dimension must never land on a secret concept."""
import os
import unittest

from cai_bench.keyfile import load_json
from cai_bench.mapping import Mapping

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
M = Mapping(load_json(os.path.join(ROOT, "mappings", "watchdog.json")))
SECRET = {"hardcoded-credential", "hardcoded-password", "hardcoded-cryptographic-key", "committed-private-key",
          "secret-in-version-history"}
SHA = {"commitSha": "5cd6eab6232d8b88aec74c762c5c8da6f07f8ac1"}

CASES = [
    # (ruleId, message, properties, the secret concepts it must map to)
    ("D13", "Leaked secret: github-token: github-token detected. Treat the value as compromised", {}, {"hardcoded-credential"}),
    ("D13", "Leaked secret: high-entropy-secret: high-entropy-secret detected.", {}, {"hardcoded-credential"}),
    ("D13", "Leaked secret: http-authorization-credential: detected.", {}, {"hardcoded-credential"}),
    ("D13", "Leaked secret: aws-access-key: aws-access-key detected.", {}, {"hardcoded-credential"}),
    ("D13", "Leaked secret: hardcoded-credential: hardcoded-credential detected.", {}, {"hardcoded-password"}),
    ("D13", "Leaked secret: signing-key: signing-key detected.", {}, {"hardcoded-cryptographic-key"}),
    ("D13", "Leaked secret: hardcoded-crypto-key: detected.", {}, {"hardcoded-cryptographic-key"}),
    ("D13", "Leaked secret: private-key-blob: detected.", {}, {"committed-private-key"}),
    ("D13", "Leaked secret: private-key: detected.", {}, {"committed-private-key"}),
    ("D13", "Leaked secret: private-key-store: detected.", {}, {"committed-private-key"}),
    ("D28", "Secret: generic-api-key: gitleaks matched rule 'generic-api-key' here, in git history.", SHA,
     {"hardcoded-credential", "secret-in-version-history"}),
    ("D28", "Secret: aws-access-token: gitleaks matched rule 'aws-access-token' here", SHA,
     {"hardcoded-credential", "secret-in-version-history"}),
    ("D28", "Secret: hardcoded-crypto-key: gitleaks matched rule 'hardcoded-crypto-key' here", SHA,
     {"hardcoded-cryptographic-key", "secret-in-version-history"}),
    ("D28", "Secret: private-key: gitleaks matched rule 'private-key' here", SHA,
     {"committed-private-key", "secret-in-version-history"}),
    ("D28", "High secret: WD-SECRET-0004: `src/x/export-api.pfx` is a PKCS#12 archive that contains a key", {},
     {"committed-private-key"}),
    ("D28", "High secret: WD-SECRET-0001: `x.snk` is a private key store", {}, {"committed-private-key"}),
    ("S1", "Cryptographic key material is a compile-time constant: `Key` is the AEAD cipher key", {},
     {"hardcoded-cryptographic-key"}),
    # hygiene on secret dimensions: no secret concept
    ("D29", "High: dependabot-missing-cooldown: This Dependabot configuration does not set a cooldown period.", {}, set()),
    ("D31", "Medium IaC: WD-COMPOSE-0002: Line 19 runs service `db` from `postgres:17.6-alpine`", {}, set()),
    ("D31", "Low IaC: DS-0026: No HEALTHCHECK defined. Add HEALTHCHECK instruction in your Dockerfile.", {}, set()),
    ("S1", "MD5/SHA1 is constructed here, and both are collision-broken.", {}, set()),
]


class WatchdogMapping(unittest.TestCase):
    def test_real_messages_map_to_the_right_secret_concepts(self):
        for rule, msg, props, want in CASES:
            with self.subTest(rule=rule, msg=msg[:40]):
                self.assertEqual(set(M.concepts_of(rule, msg, props)) & SECRET, want)

    def test_rotate_roll_up_is_ignored(self):
        self.assertIsNotNone(M.ignored("D28", "Rotate the exposed credentials — git history can't be un-committed: …"))
        self.assertIsNone(M.ignored("D28", "Secret: generic-api-key: …"))

    def test_secret_concepts_are_one_family(self):
        self.assertEqual({M.family_of(c) for c in SECRET - {"secret-in-version-history"}}, {"hardcoded-secret"})
        self.assertIsNone(M.family_of("secret-in-version-history"))


if __name__ == "__main__":
    unittest.main()

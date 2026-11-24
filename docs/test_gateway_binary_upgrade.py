import tempfile
import unittest
from pathlib import Path
from gateway_binary_upgrade import digest, upgrade


class BinaryUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.live = self.root / "gateway"
        self.candidate = self.root / "candidate"
        self.policy = self.root / "policy.json"
        self.live.write_bytes(b"original binary")
        self.candidate.write_bytes(b"candidate binary")
        self.policy.write_bytes(b'{"version":1,"hosts":[]}')
        self.original = digest(self.live)
        self.expected = digest(self.candidate)
        self.policy_hash = digest(self.policy)
        self.calls = []

    def check(self, binary, policy):
        self.assertEqual(digest(binary), self.expected)
        self.assertEqual(digest(policy), self.policy_hash)

    def restart(self):
        self.calls.append(digest(self.live))

    def run_upgrade(self, preflight=None, restart=None, expected=None):
        return upgrade(self.live, self.candidate, self.policy,
                       expected or self.expected, preflight or self.check,
                       restart or self.restart)

    def test_success_and_rollback_backup(self):
        result = self.run_upgrade()
        self.assertTrue(result["changed"])
        self.assertEqual(digest(self.live), self.expected)
        self.assertEqual(digest(Path(result["backup"])), self.original)
        self.assertEqual(self.calls, [self.expected])
        self.assertEqual(digest(self.policy), self.policy_hash)
        self.assertFalse(self.run_upgrade()["changed"])

    def test_restart_failure_restores_original(self):
        def fail_once():
            self.restart()
            if len(self.calls) == 1:
                raise RuntimeError("simulated restart failure")
        with self.assertRaisesRegex(RuntimeError, "simulated"):
            self.run_upgrade(restart=fail_once)
        self.assertEqual(self.calls, [self.expected, self.original])
        self.assertEqual(digest(self.live), self.original)
        self.assertEqual(digest(self.policy), self.policy_hash)

    def test_preflight_failure_never_replaces(self):
        def reject(*_):
            raise RuntimeError("incompatible")
        with self.assertRaisesRegex(RuntimeError, "incompatible"):
            self.run_upgrade(preflight=reject)
        self.assertEqual(self.calls, [])
        self.assertEqual(digest(self.live), self.original)
        self.assertEqual(digest(self.policy), self.policy_hash)

    def test_wrong_checksum_never_replaces(self):
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.run_upgrade(expected="0" * 64)
        self.assertEqual(self.calls, [])
        self.assertEqual(digest(self.live), self.original)
        self.assertEqual(digest(self.policy), self.policy_hash)


if __name__ == "__main__":
    unittest.main()

import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock

from run import Deployment, HERE, validate_profile


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name)
        self.profile = json.loads((HERE / "profiles/9.5.4-basic.json").read_text())
        self.deployment = Deployment(self.profile, self.path, self.path)
        self.deployment.binaries = {"live": "/unused"}

    def test_profiles_require_immutable_images_packages_and_signatures(self):
        for path in (HERE / "profiles").glob("*.json"):
            validate_profile(json.loads(path.read_text()))
        for mutate in [
            lambda p: p["images"].update(ES_IMAGE="elasticsearch:latest"),
            lambda p: p["images"].pop("EPR_IMAGE"),
            lambda p: p["packages"].update(system="latest"),
            lambda p: p["package_sha256"].pop("system-2.24.0.zip.sig"),
        ]:
            profile = copy.deepcopy(self.profile)
            mutate(profile)
            with self.assertRaises(ValueError):
                validate_profile(profile)

    def test_zero_tests_and_ignored_tests_cannot_pass(self):
        for output in [
            "test result: ok. 0 passed; 0 failed; 0 ignored;",
            "test fixture ... ignored\ntest result: ok. 0 passed; 0 failed; 1 ignored;",
            "test another ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;",
        ]:
            self.deployment.command = Mock(return_value=subprocess.CompletedProcess([], 0, output))
            with self.assertRaisesRegex(RuntimeError, "did not run"):
                self.deployment.scenario("live", "fixture")
        self.deployment.command = Mock(return_value=subprocess.CompletedProcess([], 0,
            "test fixture ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored;"))
        self.deployment.scenario("live", "fixture")
        self.assertEqual(self.deployment.report["tests"][-1]["status"], "passed")

    def test_cleanup_still_runs_when_log_collection_times_out(self):
        self.deployment.compose = Mock(side_effect=[subprocess.TimeoutExpired("docker", 60),
                                                    subprocess.CompletedProcess([], 0, "removed")])
        self.deployment.command = Mock(return_value=subprocess.CompletedProcess([], 0, ""))
        with self.assertRaises(subprocess.TimeoutExpired):
            self.deployment.cleanup()
        self.assertEqual(self.deployment.compose.call_args_list[-1].args[0], "down")
        self.assertIn("--volumes", self.deployment.compose.call_args_list[-1].args)

    def test_cleanup_failures_and_residual_resources_fail(self):
        self.deployment.compose = Mock(return_value=subprocess.CompletedProcess([], 1, "failed"))
        with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
            self.deployment.cleanup()
        self.deployment.compose = Mock(return_value=subprocess.CompletedProcess([], 0, "removed"))
        self.deployment.command = Mock(return_value=subprocess.CompletedProcess([], 0, "leftover"))
        with self.assertRaisesRegex(RuntimeError, "remain"):
            self.deployment.cleanup()

    def test_saved_diagnostics_redact_known_and_labelled_credentials(self):
        secret = self.deployment.secret()
        text = f'{secret} Authorization: Basic abc= {{"api_key":"generated-by-agent"}}'
        redacted = self.deployment.redact(text)
        for value in [secret, "abc=", "generated-by-agent"]:
            self.assertNotIn(value, redacted)


if __name__ == "__main__":
    unittest.main()

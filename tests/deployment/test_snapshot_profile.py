import unittest

from run import validate_profile
from snapshot_profile import newest_profile, newest_snapshot, snapshot_profile


class SnapshotProfileTests(unittest.TestCase):
    def test_newest_snapshot_compares_numerically(self):
        versions = ["9.5.5", "9.4.9-SNAPSHOT", "9.10.0-SNAPSHOT", "9.9.0-SNAPSHOT", "10.0.0"]
        self.assertEqual(newest_snapshot(versions), "9.10.0-SNAPSHOT")
        with self.assertRaises(RuntimeError):
            newest_snapshot(["9.5.5"])

    def test_snapshot_profile_pins_stack_images_and_keeps_base_locks(self):
        base = newest_profile()
        profile = snapshot_profile("9.6.0-SNAPSHOT", base, resolve=lambda image, tag: "sha256:" + "a" * 64)
        validate_profile(profile)
        self.assertEqual(profile["version"], "9.6.0-SNAPSHOT")
        self.assertEqual(profile["images"]["KIBANA_IMAGE"], "docker.elastic.co/kibana/kibana@sha256:" + "a" * 64)
        self.assertEqual(profile["images"]["EPR_IMAGE"], base["images"]["EPR_IMAGE"])
        self.assertEqual(profile["package_sha256"], base["package_sha256"])
        self.assertNotEqual(base["version"], profile["version"])


if __name__ == "__main__":
    unittest.main()

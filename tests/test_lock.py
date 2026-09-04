import json
import re
import unittest
from pathlib import Path


class DependencyLockTests(unittest.TestCase):
    def test_every_download_is_https_and_pinned(self):
        document = json.loads((Path(__file__).resolve().parents[1] / "dependencies.lock.json").read_text())
        for name, item in document.items():
            specs = [item] if "url" in item else [item["amd64"], item["arm64"]]
            for spec in specs:
                self.assertTrue(spec["url"].startswith("https://"))
                self.assertRegex(spec["sha256"], r"^[0-9a-f]{64}$")
                self.assertNotIn("/latest/", spec["url"])
                self.assertNotIn("POLESNIESOVETI", spec["url"])

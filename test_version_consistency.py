#!/usr/bin/env python3
"""Release version consistency guard.

The release workflow derives the tag from ``__version__`` in BloodBash.py.
Packaging metadata and the README must agree, or published artifacts advertise
a version that does not match the tag.
"""
from __future__ import annotations

import re
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _source_version() -> str:
    text = (ROOT / "BloodBash.py").read_text(encoding="utf-8")
    match = re.search(r'^__version__\s*=\s*["\']([^"\']+)', text, re.MULTILINE)
    if not match:
        raise AssertionError("__version__ not found in BloodBash.py")
    return match.group(1)


class TestVersionConsistency(unittest.TestCase):
    def test_pyproject_matches_source(self):
        data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        self.assertEqual(data["project"]["version"], _source_version())

    def test_readme_app_version_matches_source(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        match = re.search(r"\|\s*\*\*App version\*\*\s*\|\s*\*\*v?([0-9][^*]*)\*\*", text)
        self.assertIsNotNone(match, msg="README App version row missing")
        self.assertEqual(match.group(1).strip(), _source_version())

    def test_readme_tag_pattern_uses_source_version(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        version = _source_version()
        self.assertIn(f"tag `v{version}-build.N`", text)

    def test_source_version_is_semver(self):
        self.assertRegex(_source_version(), r"^\d+\.\d+\.\d+$")


if __name__ == "__main__":
    unittest.main()

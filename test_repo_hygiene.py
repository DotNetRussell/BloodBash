#!/usr/bin/env python3
"""Repo hygiene guards: no committed connection secrets or run artifacts.

The DC34 CTF pack shipped a live WireGuard config at the repo root of DC34/.
Rotating that key is an operator action; this test keeps the secret from
coming back. Generated collector output belongs in the gitignored cache, so
the tracked tree must stay free of per-scenario console dumps.
"""
from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# Assignments that carry a real key material, not a placeholder.
PRIVATE_KEY_RE = re.compile(
    r"^\s*PrivateKey\s*=\s*(?P<value>\S+)\s*$", re.MULTILINE | re.IGNORECASE
)
PLACEHOLDER_MARKERS = ("<", "REPLACE", "YOUR_", "EXAMPLE", "PLACEHOLDER")

# Text files that must not be tracked (regenerate them instead).
FORBIDDEN_TRACKED_GLOBS = (
    re.compile(r"^ludus-env-data/collections/s\d+_bloodbash\.txt$"),
    re.compile(r"^ludus-env-data/run\d*_?results\.json$"),
    re.compile(r"^bloodbash\.(json|md|html|yaml|csv|db|dot)$"),
)


def _tracked_files() -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return [line for line in out.stdout.splitlines() if line.strip()]


def _is_placeholder(value: str) -> bool:
    upper = value.upper()
    return any(marker in upper for marker in PLACEHOLDER_MARKERS)


class TestRepoHygiene(unittest.TestCase):
    def test_no_private_key_in_tracked_files(self):
        offenders = []
        for rel in _tracked_files():
            path = ROOT / rel
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            if "PrivateKey" not in text:
                continue
            for match in PRIVATE_KEY_RE.finditer(text):
                if not _is_placeholder(match.group("value")):
                    offenders.append(rel)
                    break
        self.assertEqual(offenders, [], msg=f"Private keys committed in: {offenders}")

    def test_wireguard_template_is_placeholder_only(self):
        template = ROOT / "DC34" / "ludus-ss-lab.conf.example"
        self.assertTrue(template.is_file(), msg="DC34 WireGuard template is missing")
        match = PRIVATE_KEY_RE.search(template.read_text(encoding="utf-8"))
        self.assertIsNotNone(match, msg="template must show the PrivateKey field")
        self.assertTrue(
            _is_placeholder(match.group("value")),
            msg="template PrivateKey must be a placeholder",
        )

    def test_no_generated_run_artifacts_tracked(self):
        tracked = _tracked_files()
        offenders = [
            rel
            for rel in tracked
            if any(pattern.search(rel) for pattern in FORBIDDEN_TRACKED_GLOBS)
        ]
        self.assertEqual(
            offenders, [], msg=f"Generated artifacts tracked: {offenders}"
        )

    def test_generated_artifacts_are_ignored(self):
        samples = [
            "ludus-env-data/collections/s01_bloodbash.txt",
            "ludus-env-data/run_results.json",
            "ludus-env-data/collections/bloodbash-linux-x64",
        ]
        for rel in samples:
            result = subprocess.run(
                ["git", "check-ignore", "-q", rel],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                result.returncode,
                0,
                msg=f"{rel} should be gitignored (check-ignore exit {result.returncode})",
            )


if __name__ == "__main__":
    unittest.main()

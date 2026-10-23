#!/usr/bin/env python3
"""Tests for v1.5 reporting features: ATT&CK ids, SARIF, gates, baselines,
suppressions, explain, GraphML, tickets, snapshots, and plugin detectors."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import networkx as nx
from rich.console import Console

import BloodBash as bb


def _capture(fn, *args, **kwargs) -> str:
    buf = StringIO()
    con = Console(file=buf, width=120, force_terminal=False, legacy_windows=False)
    with patch.object(bb.console, "print", side_effect=con.print):
        fn(*args, **kwargs)
    return buf.getvalue()


def _graph():
    G = nx.MultiDiGraph()
    G.add_node("u", name="ALICE@C.L", type="User", props={"domain": "C.L"}, is_azure=False)
    G.add_node("g", name="DOMAIN ADMINS@C.L", type="Group", props={"domain": "C.L"}, is_azure=False)
    G.add_node("d", name="C.L", type="Domain", props={"domain": "C.L"}, is_azure=False)
    G.add_edge("u", "g", label="MemberOf")
    G.add_edge("u", "d", label="GetChanges")
    return G


class FindingsFixture(unittest.TestCase):
    def setUp(self):
        self.saved = list(bb.global_findings)
        bb.global_findings[:] = [
            (10, "DCSync", "ALICE can DCSync on C.L"),
            (9, "RBCD", "RBCD on HOST01"),
            (9, "ESC1-ESC8", "ESC1 on TEMPLATE"),
            (8, "Shadow Credentials", "ALICE has GenericAll on BOB"),
            (5, "Kerberoastable", "SVC_SQL has SPN"),
            (4, "Password Never Expires", "User X has PNE"),
        ]

    def tearDown(self):
        bb.global_findings[:] = self.saved


class TestAttackMapping(FindingsFixture):
    def test_core_categories_map(self):
        self.assertEqual(bb.attack_techniques_for("DCSync")[0]["id"], "T1003.006")
        self.assertEqual(bb.attack_techniques_for("Kerberoastable")[0]["id"], "T1558.003")
        self.assertEqual(bb.attack_techniques_for("AS-REP Roastable")[0]["id"], "T1558.004")
        self.assertEqual(bb.attack_techniques_for("ESC1-ESC8")[0]["id"], "T1649")
        self.assertEqual(bb.attack_techniques_for("Shadow Credentials")[0]["id"], "T1556.006")

    def test_unknown_category_returns_empty(self):
        self.assertEqual(bb.attack_techniques_for("Not A Category"), [])

    def test_findings_table_shows_attack_column(self):
        G = _graph()
        out = _capture(bb.print_prioritized_findings, True)
        self.assertIn("ATT&CK", out)
        self.assertIn("T1003.006", out)

    def test_each_mapped_category_has_name(self):
        for cat in ("Azure Privileged Roles", "Broad Principal ACL", "Trust Abuse"):
            for tech in bb.attack_techniques_for(cat):
                self.assertTrue(tech["id"].startswith("T"))
                self.assertTrue(tech["name"])


class TestSarif(FindingsFixture):
    def test_validate_sarif_shape(self):
        path = os.path.join(tempfile.mkdtemp(), "out.sarif")
        _capture(bb.export_sarif, _graph(), path)
        doc = json.loads(Path(path).read_text())
        self.assertEqual(doc["version"], "2.1.0")
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "BloodBash")
        self.assertTrue(run["results"])
        # Every category present in the report (or suppressed) has a rule
        expected_rules = {f[1] for f in bb.global_findings}
        rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertEqual(rule_ids, {f"BloodBash/{c}" for c in expected_rules})
        for result in run["results"]:
            self.assertIn("ruleId", result)
            self.assertIn(result["level"], ("error", "warning", "note"))
            self.assertTrue(result["message"]["text"])
            # every ruleId referenced must be declared
            ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
            self.assertIn(result["ruleId"], ids)
            self.assertTrue(result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])

    def test_severity_maps_to_level(self):
        path = os.path.join(tempfile.mkdtemp(), "out.sarif")
        _capture(bb.export_sarif, _graph(), path)
        run = json.loads(Path(path).read_text())["runs"][0]
        by_id = {r["ruleId"]: r for r in run["results"]}
        self.assertEqual(by_id["BloodBash/DCSync"]["level"], "error")
        self.assertIn(by_id["BloodBash/Kerberoastable"]["level"], ("note", "warning"))

    def test_sarif_has_attack_taxonomies(self):
        path = os.path.join(tempfile.mkdtemp(), "out.sarif")
        _capture(bb.export_sarif, _graph(), path)
        run = json.loads(Path(path).read_text())["runs"][0]
        taxonomies = {t["name"]: t for t in run["taxonomies"]}
        self.assertIn("ATT&CK", taxonomies)
        ids = {c["id"] for c in taxonomies["ATT&CK"]["taxa"]}
        self.assertIn("T1003.006", ids)

    def test_suppressed_results_are_marked(self):
        path = os.path.join(tempfile.mkdtemp(), "out.sarif")
        sup = bb.SuppressionSet(entries=[{"category": "Kerberoastable"}])
        _capture(bb.export_sarif, _graph(), path, suppressions=sup)
        run = json.loads(Path(path).read_text())["runs"][0]
        for result in run["results"]:
            if result["ruleId"] == "BloodBash/Kerberoastable":
                self.assertEqual(result.get("suppressions", [{}])[0].get("kind"), "external")


class TestSeverityGate(FindingsFixture):
    def test_gate_fails_on_high(self):
        self.assertEqual(bb.evaluate_findings_gate(threshold=8), 2)

    def test_gate_passes_when_threshold_above_max(self):
        self.assertEqual(bb.evaluate_findings_gate(threshold=11), 0)

    def test_gate_disabled(self):
        self.assertEqual(bb.evaluate_findings_gate(threshold=None), 0)

    def test_gate_ignores_suppressed(self):
        sup = bb.SuppressionSet(entries=[{"category": "DCSync", "reason": "accepted"}])
        self.assertEqual(bb.evaluate_findings_gate(threshold=10, suppressions=sup), 0)

    def test_cli_fail_on_severity(self):
        env = dict(os.environ, BLOODBASH_NO_CACHE="1", TQDM_DISABLE="1")
        r = subprocess.run(
            [sys.executable, "BloodBash.py", "testData/synthetic-corp-lab",
             "--all", "--fast", "--no-cache", "--fail-on-severity", "1"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(r.returncode, 2, msg=r.stdout[-500:])


class TestBaseline(FindingsFixture):
    def _baseline(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "base.json")
        _capture(bb.export_results, _graph(), output_prefix=os.path.join(d, "r"), format_type="json")
        Path(p).write_text(Path(os.path.join(d, "r.json")).read_text())
        return p

    def test_diff_marks_new_and_resolved(self):
        base = self._baseline()
        bb.global_findings[:] = [
            (10, "DCSync", "ALICE can DCSync on C.L"),
            (9, "GPO Abuse", "Weak GPO: NewOne"),
        ]
        diff = bb.diff_findings_against_baseline(base)
        self.assertEqual([f["details"] for f in diff["new"]], ["Weak GPO: NewOne"])
        self.assertEqual(len(diff["resolved"]), 5)
        self.assertTrue(diff["unchanged"])

    def test_baseline_can_suppress_known(self):
        base = self._baseline()
        sup = bb.SuppressionSet.from_baseline(base)
        remaining = [f for f in bb.global_findings if not sup.is_suppressed(f[1], f[2])]
        cats = {f[1] for f in remaining}
        self.assertNotIn("DCSync", cats)

    def test_cli_baseline_flag(self):
        base = self._baseline()
        env = dict(os.environ, BLOODBASH_NO_CACHE="1", TQDM_DISABLE="1")
        r = subprocess.run(
            [sys.executable, "BloodBash.py", "testData/synthetic-corp-lab",
             "--kerberoastable", "--no-cache", "--baseline", base],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(r.returncode, 0, msg=r.stdout[-500:] + r.stderr[-300:])
        self.assertIn("Baseline", r.stdout)

    def test_missing_baseline_is_an_error(self):
        with self.assertRaises(OSError):
            bb.diff_findings_against_baseline("/nonexistent/base.json")


class TestSuppressions(unittest.TestCase):
    def test_yaml_suppression_matches_category(self):
        p = Path(tempfile.mkdtemp()) / "sup.yaml"
        p.write_text(
            "suppressions:\n  - category: Kerberoastable\n    reason: service accounts\n"
        )
        sup = bb.load_suppressions(str(p))
        self.assertTrue(sup.is_suppressed("Kerberoastable", "SVC_SQL has SPN"))
        self.assertFalse(sup.is_suppressed("DCSync", "x"))

    def test_contains_match(self):
        p = Path(tempfile.mkdtemp()) / "sup.yaml"
        p.write_text("suppressions:\n  - contains: DC01\n")
        sup = bb.load_suppressions(str(p))
        self.assertTrue(sup.is_suppressed("LAPS", "LAPS not enabled on DC01.CORP.LOCAL"))
        self.assertFalse(sup.is_suppressed("LAPS", "33/34 computers do not have LAPS"))

    def test_expired_entry_is_ignored(self):
        p = Path(tempfile.mkdtemp()) / "sup.yaml"
        p.write_text(
            "suppressions:\n  - category: LAPS\n    expires: 2000-01-01\n"
        )
        sup = bb.load_suppressions(str(p))
        self.assertFalse(sup.is_suppressed("LAPS", "anything"))

    def test_future_expiry_applies(self):
        p = Path(tempfile.mkdtemp()) / "sup.yaml"
        p.write_text("suppressions:\n  - category: LAPS\n    expires: 2999-01-01\n")
        sup = bb.load_suppressions(str(p))
        self.assertTrue(sup.is_suppressed("LAPS", "anything"))

    def test_invalid_yaml_raises(self):
        p = Path(tempfile.mkdtemp()) / "sup.yaml"
        p.write_text("suppressions: not-a-list\n")
        with self.assertRaises(ValueError):
            bb.load_suppressions(str(p))


class TestExplain(unittest.TestCase):
    def test_explain_category_lists_examples_and_attack(self):
        saved = list(bb.global_findings)
        try:
            bb.global_findings[:] = [
                (10, "DCSync", "ALICE can DCSync on C.L"),
                (10, "DCSync", "BOB can DCSync on C.L"),
            ]
            out = _capture(bb.explain_finding, "DCSync", _graph())
            self.assertIn("T1003.006", out)
            self.assertIn("ALICE", out)
            self.assertIn("BOB", out)
            self.assertIn("2", out)
        finally:
            bb.global_findings[:] = saved

    def test_explain_accepts_index(self):
        saved = list(bb.global_findings)
        try:
            bb.global_findings[:] = [(10, "DCSync", "ALICE can DCSync on C.L")]
            out = _capture(bb.explain_finding, "1", _graph())
            self.assertIn("DCSync", out)
        finally:
            bb.global_findings[:] = saved

    def test_unknown_returns_error_text(self):
        out = _capture(bb.explain_finding, "Nope", _graph())
        self.assertIn("No finding", out)


class TestGraphML(unittest.TestCase):
    def test_export_graphml_roundtrip(self):
        path = os.path.join(tempfile.mkdtemp(), "g.graphml")
        _capture(bb.export_graphml, _graph(), path)
        H = nx.read_graphml(path)
        self.assertEqual(H.number_of_nodes(), 3)
        self.assertEqual(H.number_of_edges(), 2)

    def test_graphml_handles_non_scalar_props(self):
        G = _graph()
        G.nodes["u"]["props"] = {"groups": ["a", "b"], "nested": {"k": 1}}
        path = os.path.join(tempfile.mkdtemp(), "g.graphml")
        _capture(bb.export_graphml, G, path)
        nx.read_graphml(path)


class TestTickets(unittest.TestCase):
    def test_ticket_per_high_severity_finding(self):
        saved = list(bb.global_findings)
        try:
            bb.global_findings[:] = [
                (10, "DCSync", "ALICE can DCSync on C.L"),
                (9, "RBCD", "RBCD on HOST01"),
                (5, "Kerberoastable", "SVC has SPN"),
            ]
            d = tempfile.mkdtemp()
            files = bb.export_tickets(_graph(), d, min_score=9)
            self.assertEqual(len(files), 2)
            text = Path(files[0]).read_text()
            self.assertIn("# ", text)
            self.assertIn("T1003.006", text)
            self.assertIn("Remediation", text)
            self.assertIn("Severity", text)
        finally:
            bb.global_findings[:] = saved

    def test_filenames_are_filesystem_safe(self):
        saved = list(bb.global_findings)
        try:
            bb.global_findings[:] = [(10, "Bad/Cat:Name*?", "../../escape")]
            d = tempfile.mkdtemp()
            files = bb.export_tickets(_graph(), d, min_score=1)
            self.assertEqual(len(files), 1)
            self.assertEqual(Path(files[0]).parent.resolve(), Path(d).resolve())
        finally:
            bb.global_findings[:] = saved


class TestSnapshots(unittest.TestCase):
    def test_snapshot_save_and_list(self):
        cache = tempfile.mkdtemp()
        saved = list(bb.global_findings)
        try:
            bb.global_findings[:] = [(10, "DCSync", "ALICE can DCSync")]
            p = bb.save_findings_snapshot(_graph(), cache_dir=cache, label="run1")
            self.assertTrue(Path(p).is_file())
            snaps = bb.list_snapshots(cache_dir=cache)
            self.assertEqual(len(snaps), 1)
            self.assertEqual(snaps[0]["label"], "run1")
            trend = bb.compare_latest_two_snapshots(cache_dir=cache)
            self.assertIsNone(trend)  # only one snapshot
            bb.save_findings_snapshot(_graph(), cache_dir=cache, label="run2")
            trend = bb.compare_latest_two_snapshots(cache_dir=cache)
            self.assertIn("new", trend)
            self.assertIn("resolved", trend)
        finally:
            bb.global_findings[:] = saved


class TestPlugins(unittest.TestCase):
    def test_plugin_detector_is_loaded_and_run(self):
        d = Path(tempfile.mkdtemp())
        (d / "mycheck.py").write_text(
            "def run(G, add_finding):\n"
            "    add_finding('Plugin Check', 'from plugin', score=7)\n"
            "    return 1\n"
        )
        saved = list(bb.global_findings)
        try:
            bb.global_findings[:] = []
            loaded = bb.load_plugin_detectors(str(d))
            self.assertEqual(len(loaded), 1)
            count = bb.run_plugin_detectors(loaded, _graph())
            self.assertEqual(count, 1)
            self.assertEqual(bb.global_findings[0][1], "Plugin Check")
        finally:
            bb.global_findings[:] = saved

    def test_broken_plugin_does_not_abort(self):
        d = Path(tempfile.mkdtemp())
        (d / "broken.py").write_text("def run(G, add_finding):\n    raise RuntimeError('boom')\n")
        loaded = bb.load_plugin_detectors(str(d))
        with patch.object(bb.console, "print"):
            bb.run_plugin_detectors(loaded, _graph())

    def test_plugin_missing_run_is_skipped(self):
        d = Path(tempfile.mkdtemp())
        (d / "norun.py").write_text("x = 1\n")
        self.assertEqual(bb.load_plugin_detectors(str(d)), [])


if __name__ == "__main__":
    unittest.main()

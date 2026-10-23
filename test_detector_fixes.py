#!/usr/bin/env python3
"""Regression tests for the v1.5 detector, console, and export fixes."""
from __future__ import annotations

import csv
import json
import os
import re
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
    return re.sub(r"\x1b\[[0-9;]*m", "", buf.getvalue())


def _user(oid: str, name: str, **props):
    G = nx.MultiDiGraph()
    G.add_node(oid, name=name, type="User", props=props, is_azure=False)
    return G


class TestInventoryEnabled(unittest.TestCase):
    def test_string_false_is_disabled(self):
        G = _user("u", "A@C.L", enabled="false", pwdlastset=1000000000)
        self.assertFalse(bb.collect_password_age_rows(G)[0]["enabled"])
        self.assertFalse(bb.collect_stale_account_rows(G)[0]["enabled"])

    def test_uac_disabled_bit(self):
        G = _user("u", "A@C.L", useraccountcontrol=514, pwdlastset=1000000000)
        self.assertFalse(bb.collect_password_age_rows(G)[0]["enabled"])

    def test_matches_stats_dashboard(self):
        G = _user("u", "A@C.L", enabled="false", pwdlastset=1000000000)
        stats = bb.collect_domain_stats(G)
        self.assertEqual(stats["disabled_users"], 1)
        self.assertEqual(bb.collect_password_age_rows(G)[0]["enabled"], False)


class TestAdcsEnrollmentFlags(unittest.TestCase):
    def _template_graph(self, **props):
        G = nx.MultiDiGraph()
        base = {"enrolleesuppliessubject": True, "ekus": ["1.3.6.1.5.5.7.3.2"]}
        base.update(props)
        G.add_node("t", name="TPL@C.L", type="Certificate Template", props=base, is_azure=False)
        G.add_node("g", name="DOMAIN USERS@C.L", type="Group", props={}, is_azure=False)
        G.add_edge("g", "t", label="Enroll")
        return G

    def test_pend_all_requests_numeric_blocks_esc1(self):
        out = _capture(bb.print_adcs_vulnerabilities, self._template_graph(enrollmentflag=2))
        self.assertNotIn("ESC1:", out)

    def test_flag_text_still_blocks_esc1(self):
        out = _capture(
            bb.print_adcs_vulnerabilities,
            self._template_graph(enrollmentflag="PEND_ALL_REQUESTS"),
        )
        self.assertNotIn("ESC1:", out)

    def test_no_pending_flag_reports_esc1(self):
        out = _capture(bb.print_adcs_vulnerabilities, self._template_graph(enrollmentflag=0))
        self.assertIn("ESC1:", out)

    def test_numeric_no_security_extension_detected(self):
        out = _capture(
            bb.print_adcs_vulnerabilities,
            self._template_graph(enrollmentflag=0x00080000),
        )
        self.assertIn("ESC9", out)


class TestAzureNoise(unittest.TestCase):
    def test_custom_roles_not_high_value(self):
        G = nx.MultiDiGraph()
        for i in range(5):
            G.add_node(f"r{i}", name=f"Custom Role {i}", type="Azure Role", props={}, is_azure=True)
        G.add_node("p", name="Global Administrator", type="Azure Role", props={}, is_azure=True)
        hv = [t[1] for t in bb.get_high_value_targets(G)]
        self.assertEqual(hv, ["Global Administrator"])

    def test_global_admin_owner_is_not_app_secret_finding(self):
        G = nx.MultiDiGraph()
        G.add_node("ga", name="Global Administrator", type="Azure Role", props={}, is_azure=True)
        G.add_node("app", name="App1", type="Azure Application", props={}, is_azure=True)
        G.add_edge("ga", "app", label="Owns")
        out = _capture(bb.print_azure_app_secrets, G)
        self.assertNotIn("credential abuse path", out)

    def test_low_priv_owner_still_found(self):
        G = nx.MultiDiGraph()
        G.add_node("u", name="bob@contoso.com", type="Azure User", props={}, is_azure=True)
        G.add_node("app", name="App1", type="Azure Application", props={}, is_azure=True)
        G.add_edge("u", "app", label="Owns")
        out = _capture(bb.print_azure_app_secrets, G)
        self.assertIn("credential abuse path", out)


class TestPartialNodes(unittest.TestCase):
    def test_detectors_tolerate_missing_attributes(self):
        G = nx.MultiDiGraph()
        G.add_node("x")
        G.add_node("y", name="Y@C.L", type="User", props={}, is_azure=False)
        G.add_edge("x", "y", label="MemberOf")
        for fn in (
            bb.print_verbose_summary,
            bb.print_stats_dashboard,
            bb.print_shortest_paths,
        ):
            with self.subTest(fn=fn.__name__):
                _capture(fn, G)


class TestMarkupSafety(unittest.TestCase):
    def test_description_closing_tag_does_not_crash(self):
        G = _user("u", "BOB@C.L", description="password: hunter2 [/]")
        out = _capture(bb.print_password_in_descriptions, G)
        self.assertIn("Potential password", out)

    def test_malformed_markup_is_escaped_not_fatal(self):
        buf = StringIO()
        con = Console(file=buf, width=80, force_terminal=False)
        original = con.print
        bb._install_markup_guard(con)
        con.print("[bold]opens and never closes")
        self.assertTrue(original is not con.print)

    def test_name_with_markup_in_dot(self):
        G = nx.MultiDiGraph()
        G.add_node("a", name='BAD "NAME"', type="User", props={}, is_azure=False)
        path = os.path.join(tempfile.mkdtemp(), "g.dot")
        _capture(bb.export_to_dot, G, path)
        text = Path(path).read_text()
        self.assertIn('BAD \\"NAME\\"', text)
        self.assertNotIn('"BAD "NAME""', text)

    def test_dot_roundtrips_backslashes(self):
        self.assertEqual(bb._dot_escape("a\\b"), "a\\\\b")


class TestCsvInjection(unittest.TestCase):
    def test_formula_prefix_is_neutralized(self):
        paths = bb.write_csv_file(
            os.path.join(tempfile.mkdtemp(), "x.csv"),
            ["Name"],
            [["=cmd|'/C calc'!A0"], ["+SUM(1,1)"], ["-1+1"], ["@evil"], ["normal"]],
        )
        rows = list(csv.reader(open(paths, encoding="utf-8")))
        self.assertEqual(rows[1][0], "'=cmd|'/C calc'!A0")
        self.assertEqual(rows[2][0], "'+SUM(1,1)")
        self.assertEqual(rows[3][0], "'-1+1")
        self.assertEqual(rows[4][0], "'@evil")
        self.assertEqual(rows[5][0], "normal")

    def test_numbers_are_not_quoted(self):
        G = nx.MultiDiGraph()
        G.add_node("u", name="A@C.L", type="User", props={"enabled": True}, is_azure=False)
        d = tempfile.mkdtemp()
        bb.export_csv_pack(G, d)
        self.assertNotIn("'", Path(d, "index.csv").read_text().splitlines()[1][:1])


class TestExportRawFindings(unittest.TestCase):
    def test_json_contains_pre_collapse_rows(self):
        saved = list(bb.global_findings)
        try:
            bb.global_findings[:] = [(8, "Kerberoastable", f"u{i}") for i in range(40)]
            G = nx.MultiDiGraph()
            G.add_node("a", name="a", type="User", props={}, is_azure=False)
            path = os.path.join(tempfile.mkdtemp(), "r")
            _capture(bb.export_results, G, output_prefix=path, format_type="json")
            report = json.loads(Path(path + ".json").read_text())
            self.assertEqual(report["findings_raw_count"], 40)
            self.assertEqual(len(report["findings_raw"]), 40)
            self.assertLess(len(report["findings"]), 40)
            hint = [f for f in report["findings"] if "collapsed" in f["details"]]
            self.assertIn("findings_raw", hint[0]["details"])
        finally:
            bb.global_findings[:] = saved


class TestDomainFilterExit(unittest.TestCase):
    def test_unknown_domain_warns(self):
        G = nx.MultiDiGraph()
        G.add_node("a", name="A@C.L", type="User", props={"domain": "C.L"}, is_azure=False)
        self.assertTrue(bb.warn_if_domain_filter_empty(G, "NOPE.LOCAL"))
        self.assertFalse(bb.warn_if_domain_filter_empty(G, "C.L"))

    def test_cli_exits_nonzero_for_unknown_domain(self):
        import subprocess
        import sys

        env = dict(os.environ, BLOODBASH_NO_CACHE="1", TQDM_DISABLE="1")
        r = subprocess.run(
            [sys.executable, "BloodBash.py", "SampleSharphoundADData",
             "--domain", "NOPE.LOCAL", "--quick-wins", "--no-cache"],
            capture_output=True, text=True, env=env,
        )
        self.assertEqual(r.returncode, 3, msg=r.stdout[-600:] + r.stderr[-400:])


class TestWritableHeader(unittest.TestCase):
    def test_single_column_header_skipped(self):
        d = Path(tempfile.mkdtemp())
        p = d / "w.tsv"
        p.write_text("target\nCN=X,DC=corp,DC=local\n", encoding="utf-8")
        rows = bb.parse_writable_file(str(p))
        self.assertEqual([r["target"] for r in rows], ["CN=X"])

    def test_multi_column_header_skipped(self):
        d = Path(tempfile.mkdtemp())
        p = d / "w.tsv"
        p.write_text("target\trights\nCN=Y,DC=corp,DC=local\tGenericAll\n", encoding="utf-8")
        rows = bb.parse_writable_file(str(p))
        self.assertEqual([r["target"] for r in rows], ["CN=Y,DC=corp,DC=local"])

    def test_data_row_starting_with_target_kept(self):
        d = Path(tempfile.mkdtemp())
        p = d / "w.tsv"
        p.write_text("targetbox\tGenericAll\n", encoding="utf-8")
        rows = bb.parse_writable_file(str(p))
        self.assertEqual(rows[0]["target"], "targetbox")


if __name__ == "__main__":
    unittest.main()

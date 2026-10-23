#!/usr/bin/env python3
"""Tests for v1.5 coverage additions: watch mode, GPO XML extras, ESC10-12,
and Entra posture checks."""
from __future__ import annotations

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
    con = Console(file=buf, width=140, force_terminal=False, legacy_windows=False)
    with patch.object(bb.console, "print", side_effect=con.print):
        fn(*args, **kwargs)
    return buf.getvalue()


class TestWatchMode(unittest.TestCase):
    def test_runs_immediately_then_on_change(self):
        d = Path(tempfile.mkdtemp())
        (d / "users.json").write_text("[]", encoding="utf-8")
        calls = []
        ticks = {"n": 0}
        original = bb._watch_signature
        seq = iter(["sig-a", "sig-a", "sig-b"])

        def fake_sig(paths):
            try:
                return next(seq)
            except StopIteration:
                return "sig-b"

        def fake_sleep(_):
            ticks["n"] += 1
            # Change the file so the real fingerprint logic also exercised elsewhere
            if ticks["n"] == 2:
                (d / "users.json").write_text("[{}]", encoding="utf-8")

        with patch.object(bb, "_watch_signature", side_effect=fake_sig):
            cycles = bb.run_watch_mode(
                [str(d)],
                interval=0,
                run_once=lambda: calls.append(1),
                max_cycles=2,
                sleep_fn=fake_sleep,
            )
        self.assertEqual(cycles, 2)
        self.assertEqual(len(calls), 2)
        self.assertTrue(original)  # patch restored

    def test_no_rerun_without_change(self):
        d = Path(tempfile.mkdtemp())
        calls = []
        with patch.object(bb, "_watch_signature", return_value="same"):
            cycles = bb.run_watch_mode(
                [str(d)], interval=0, run_once=lambda: calls.append(1),
                max_cycles=3, sleep_fn=lambda _s: None,
            )
        self.assertEqual(len(calls), 1)  # initial run only
        self.assertEqual(cycles, 1)

    def test_watch_argv_strips_flags(self):
        argv = ["data", "--watch", "--watch-interval", "2", "--all"]
        self.assertEqual(bb._watch_argv(argv), ["data", "--all"])
        argv2 = ["data", "--watch", "./dir", "--fast"]
        self.assertEqual(bb._watch_argv(argv2), ["data", "--fast"])
        argv3 = ["data", "--watch-interval=9", "--fast"]
        self.assertEqual(bb._watch_argv(argv3), ["data", "--fast"])


class TestGpoXmlExtras(unittest.TestCase):
    def _run(self, xml: str, filename: str = "GPO.xml") -> str:
        d = Path(tempfile.mkdtemp())
        (d / filename).write_text(xml, encoding="utf-8")
        G = nx.MultiDiGraph()
        G.add_node("g", name="TESTGPO@C.L", type="GPO", props={}, is_azure=False)
        return _capture(bb.print_gpo_content_analysis, G, str(d))

    def test_group_membership_change_reported(self):
        xml = """<Groups><Group name="Administrators">
          <Properties groupName="Administrators" />
          <Members><Member name="CORP\\lowpriv" action="ADD" /></Members>
        </Group></Groups>"""
        saved = list(bb.global_findings)
        try:
            bb.global_findings[:] = []
            out = self._run(xml)
            self.assertIn("local group change", out)
            self.assertTrue(any("local group" in f[2] for f in bb.global_findings))
        finally:
            bb.global_findings[:] = saved

    def test_scheduled_task_trigger_shown(self):
        xml = """<ScheduledTasks><Task>
          <Name>Updater</Name>
          <Command>cmd.exe</Command>
          <Arguments>/c whoami</Arguments>
          <Triggers><LogonTrigger type="logon" /></Triggers>
        </Task></ScheduledTasks>"""
        out = self._run(xml)
        self.assertIn("Updater", out)
        self.assertIn("logon", out.lower())

    def test_malformed_xml_does_not_raise(self):
        out = self._run("<Groups><Group>")
        self.assertIn("Could not parse", out)


class TestEscCoverage(unittest.TestCase):
    def _ca(self, **props):
        G = nx.MultiDiGraph()
        G.add_node(
            "ca", name="CORP-CA", type="Enterprise CA", props=props, is_azure=False
        )
        # adcs_object_count must be > 0
        return G

    def test_esc10_weak_mapping(self):
        out = _capture(
            bb.print_adcs_vulnerabilities,
            self._ca(**{"certificatemappingmethod": "weak"}),
        )
        self.assertIn("ESC10", out)

    def test_esc11_no_encryption(self):
        out = _capture(
            bb.print_adcs_vulnerabilities,
            self._ca(**{"ifencryptionrequired": False}),
        )
        self.assertIn("ESC11", out)

    def test_esc12_exportable_key(self):
        out = _capture(
            bb.print_adcs_vulnerabilities,
            self._ca(**{"capexportablekey": True}),
        )
        self.assertIn("ESC12", out)

    def test_clean_ca_reports_none(self):
        out = _capture(
            bb.print_adcs_vulnerabilities,
            self._ca(**{"ifencryptionrequired": True}),
        )
        self.assertNotIn("ESC10", out)
        self.assertNotIn("ESC11", out)
        self.assertNotIn("ESC12", out)


class TestEntraPosture(unittest.TestCase):
    def test_standing_assignment_flagged(self):
        G = nx.MultiDiGraph()
        G.add_node("r", name="Global Administrator", type="Azure Role", props={}, is_azure=True)
        G.add_node("u", name="bob@contoso.com", type="Azure User", props={}, is_azure=True)
        G.add_edge("u", "r", label="HasRole")
        saved = list(bb.global_findings)
        try:
            bb.global_findings[:] = []
            out = _capture(bb.print_azure_consent_and_pim, G)
            self.assertIn("Standing privileged role", out)
            self.assertTrue(bb.global_findings)
        finally:
            bb.global_findings[:] = saved

    def test_eligible_assignment_not_flagged(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "r", name="Global Administrator", type="Azure Role",
            props={"assignmentType": "Eligible"}, is_azure=True,
        )
        G.add_node("u", name="bob@contoso.com", type="Azure User", props={}, is_azure=True)
        G.add_edge("u", "r", label="HasRole")
        out = _capture(bb.print_azure_consent_and_pim, G)
        self.assertNotIn("Standing privileged role", out)

    def test_broad_consent_scope_flagged(self):
        G = nx.MultiDiGraph()
        G.add_node(
            "sp", name="SP1", type="Azure Service Principal",
            props={"oauth2PermissionGrants": [{"scope": "User.ReadWrite.All Directory.Read.All"}]},
            is_azure=True,
        )
        saved = list(bb.global_findings)
        try:
            bb.global_findings[:] = []
            out = _capture(bb.print_azure_consent_and_pim, G)
            self.assertIn("Broad consent grant", out)
        finally:
            bb.global_findings[:] = saved

    def test_unmanaged_device_flagged(self):
        G = nx.MultiDiGraph()
        G.add_node("d", name="LAPTOP01", type="Azure Device", props={"isManaged": False}, is_azure=True)
        out = _capture(bb.print_azure_consent_and_pim, G)
        self.assertIn("Unmanaged device", out)


if __name__ == "__main__":
    unittest.main()

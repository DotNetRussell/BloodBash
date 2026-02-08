import unittest
import sys
import os
from io import StringIO
from unittest.mock import patch, MagicMock
import json
import networkx as nx
from rich.console import Console

# Load the BloodBash script by executing it in a controlled namespace
bloodbash_globals = {}
with open("BloodBash", "r") as f:
    exec(f.read(), bloodbash_globals)

class TestBloodBash(unittest.TestCase):
    def setUp(self):
        # Base directory for test data
        self.test_data_dir = "testData"
    
    def _load_and_build_graph(self, test_subdir):
        """Helper to load JSON files from a test subdirectory and build the graph."""
        test_dir = os.path.join(self.test_data_dir, test_subdir)
        nodes = bloodbash_globals['load_json_dir'](test_dir)
        G, _ = bloodbash_globals['build_graph'](nodes)
        return G
    
    def _capture_output(self, func, *args, **kwargs):
        """Helper to capture console output using Rich's Console with StringIO."""
        string_io = StringIO()
        test_console = Console(file=string_io, width=80, legacy_windows=False)
        # Patch the console.print to use our test_console
        with patch.object(bloodbash_globals['console'], 'print', side_effect=test_console.print):
            func(*args, **kwargs)
        output = string_io.getvalue()
        return output
    
    def test_adcs_vulnerabilities(self):
        G = self._load_and_build_graph("adcs-tests")
        output = self._capture_output(bloodbash_globals['print_adcs_vulnerabilities'], G)
        # Assert key vulnerabilities are detected (check for plain text output)
        self.assertIn("ESC1/ESC2", output)
        self.assertIn("ESC3", output)
        self.assertIn("ESC6", output)
        self.assertIn("ESC8", output)
    
    def test_gpo_abuse(self):
        G = self._load_and_build_graph("gpo-tests")
        output = self._capture_output(bloodbash_globals['print_gpo_abuse'], G)
        # Assert weak GPO is detected with high-risk note (plain text)
        self.assertIn("Weak GPO", output)
        self.assertIn("High-risk", output)
        self.assertIn("Vulnerable-GPO", output)
    
    def test_dcsync_rights(self):
        G = self._load_and_build_graph("dcsync-tests")
        output = self._capture_output(bloodbash_globals['print_dcsync_rights'], G)
        # Assert DCSync is detected (plain text)
        self.assertIn("DCSync possible", output)
        self.assertIn("LOWPRIV@LAB.LOCAL", output)
    
    def test_rbcd(self):
        G = self._load_and_build_graph("rdbc-tests")  # Note: 'rdbc-tests' as per your structure
        output = self._capture_output(bloodbash_globals['print_rbcd'], G)
        # Assert RBCD is detected (plain text)
        self.assertIn("RBCD configured", output)
        self.assertIn("TARGET-COMPUTER$", output)
    
    def test_shortest_paths(self):
        G = self._load_and_build_graph("shortest-paths-tests")
        output = self._capture_output(bloodbash_globals['print_shortest_paths'], G)
        # Assert paths are shown (adjusted to plain text without markup)
        self.assertIn("DC1$", output)
        self.assertIn("USER2@LAB.LOCAL", output)
    
    def test_dangerous_permissions(self):
        G = self._load_and_build_graph("dangerous-permissions-tests")
        output = self._capture_output(bloodbash_globals['print_dangerous_permissions'], G)
        # Assert dangerous permissions are grouped (plain text)
        self.assertIn("Domain Admins", output)
        self.assertIn("GenericAll", output)
        self.assertIn("LOWPRIV@LAB.LOCAL", output)
    
    def test_kerberoastable(self):
        G = self._load_and_build_graph("kerberoastable-tests")
        output = self._capture_output(bloodbash_globals['print_kerberoastable'], G)
        # Assert Kerberoastable user is detected (plain text)
        self.assertIn("KERBUSER@LAB.LOCAL", output)
    
    def test_as_rep_roastable(self):
        G = self._load_and_build_graph("as-rep-roastable-tests")
        output = self._capture_output(bloodbash_globals['print_as_rep_roastable'], G)
        # Assert AS-REP Roastable user is detected (plain text)
        self.assertIn("ASREPUSER@LAB.LOCAL", output)
    
    def test_sessions_localadmin(self):
        G = self._load_and_build_graph("local-admin-sessions-tests")
        output = self._capture_output(bloodbash_globals['print_sessions_localadmin'], G)
        # Assert local admins are listed (plain text, check for content in rendered table)
        self.assertIn("ADMINUSER@LAB.LOCAL", output)
        self.assertIn("Total LocalAdmin instances", output)
    
    def test_get_high_value_targets(self):
        G = self._load_and_build_graph("high-value-targets-tests")
        targets = bloodbash_globals['get_high_value_targets'](G)
        # Assert high-value targets are found (case-insensitive check for "domain admins")
        target_names = [name for _, name, _ in targets]
        self.assertTrue(any("domain admins" in name.lower() for name in target_names))
        self.assertTrue(any("krbtgt" in name.lower() for name in target_names))
    
    def test_format_path(self):
        # Mock a simple graph for testing
        G = nx.MultiDiGraph()
        G.add_node("A", name="UserA")
        G.add_node("B", name="TargetB")
        G.add_edge("A", "B", label="AdminTo")
        path = ["A", "B"]
        formatted = bloodbash_globals['format_path'](G, path)
        # Assert path is formatted correctly (plain text)
        self.assertIn("UserA", formatted)
        self.assertIn("AdminTo", formatted)
        self.assertIn("TargetB", formatted)

if __name__ == '__main__':
    unittest.main()
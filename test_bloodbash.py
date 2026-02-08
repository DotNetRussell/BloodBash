import unittest
import sys
import os
import tempfile
import shutil
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
        # Temporary directory for DB/export tests
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        # Clean up temp directory
        shutil.rmtree(self.temp_dir)
    
    def _load_and_build_graph(self, test_subdir):
        """Helper to load JSON files from a test subdirectory and build the graph."""
        test_dir = os.path.join(self.test_data_dir, test_subdir)
        if not os.path.exists(test_dir):
            raise FileNotFoundError(f"Test data directory '{test_dir}' does not exist. Skipping test.")
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
    
    # Existing tests (unchanged)
    def test_adcs_vulnerabilities(self):
        try:
            G = self._load_and_build_graph("adcs-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_adcs_vulnerabilities'], G)
        self.assertIn("ESC1/ESC2", output)
        self.assertIn("ESC3", output)
        self.assertIn("ESC6", output)
        self.assertIn("ESC8", output)
    
    def test_gpo_abuse(self):
        try:
            G = self._load_and_build_graph("gpo-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_gpo_abuse'], G)
        self.assertIn("Weak GPO", output)
        self.assertIn("High-risk", output)
        self.assertIn("Vulnerable-GPO", output)
    
    def test_dcsync_rights(self):
        try:
            G = self._load_and_build_graph("dcsync-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_dcsync_rights'], G)
        self.assertIn("DCSync possible", output)
        self.assertIn("LOWPRIV@LAB.LOCAL", output)
    
    def test_rbcd(self):
        try:
            G = self._load_and_build_graph("rdbc-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_rbcd'], G)
        self.assertIn("RBCD configured", output)
        self.assertIn("TARGET-COMPUTER$", output)
    
    def test_shortest_paths(self):
        try:
            G = self._load_and_build_graph("shortest-paths-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_shortest_paths'], G)
        self.assertIn("DC1$", output)
        self.assertIn("USER2@LAB.LOCAL", output)
    
    def test_dangerous_permissions(self):
        try:
            G = self._load_and_build_graph("dangerous-permissions-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_dangerous_permissions'], G)
        self.assertIn("Domain Admins", output)
        self.assertIn("GenericAll", output)
        self.assertIn("LOWPRIV@LAB.LOCAL", output)
    
    def test_kerberoastable(self):
        try:
            G = self._load_and_build_graph("kerberoastable-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_kerberoastable'], G)
        self.assertIn("KERBUSER@LAB.LOCAL", output)
    
    def test_as_rep_roastable(self):
        try:
            G = self._load_and_build_graph("as-rep-roastable-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_as_rep_roastable'], G)
        self.assertIn("ASREPUSER@LAB.LOCAL", output)
    
    def test_sessions_localadmin(self):
        try:
            G = self._load_and_build_graph("local-admin-sessions-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_sessions_localadmin'], G)
        self.assertIn("ADMINUSER@LAB.LOCAL", output)
        self.assertIn("Total LocalAdmin instances", output)
    
    def test_get_high_value_targets(self):
        try:
            G = self._load_and_build_graph("high-value-targets-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        targets = bloodbash_globals['get_high_value_targets'](G)
        target_names = [name for _, name, _ in targets]
        self.assertTrue(any("domain admins" in name.lower() for name in target_names))
        self.assertTrue(any("krbtgt" in name.lower() for name in target_names))
    
    def test_format_path(self):
        G = nx.MultiDiGraph()
        G.add_node("A", name="UserA")
        G.add_node("B", name="TargetB")
        G.add_edge("A", "B", label="AdminTo")
        path = ["A", "B"]
        formatted = bloodbash_globals['format_path'](G, path)
        self.assertIn("UserA", formatted)
        self.assertIn("AdminTo", formatted)
        self.assertIn("TargetB", formatted)
    
     
    def test_domain_filtering(self):
        try:
            G = self._load_and_build_graph("domain-filter-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output_filtered = self._capture_output(bloodbash_globals['print_verbose_summary'], G, domain_filter="lab.local")
        self.assertIn("lab.local", output_filtered.lower())
        output_all = self._capture_output(bloodbash_globals['print_verbose_summary'], G, domain_filter=None)
        self.assertGreater(len(output_all), len(output_filtered))
    
    def test_indirect_paths(self):
        try:
            G = self._load_and_build_graph("indirect-paths-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_shortest_paths'], G, indirect=True)
        # Check for high-value target presence and indirect paths
        self.assertIn("DOMAIN ADMINS@LAB.LOCAL", output)  # High-value target now present
        self.assertIn("Indirect paths", output)
        self.assertIn("via groups", output)

    def test_indirect_dangerous_permissions(self):
        try:
            G = self._load_and_build_graph("indirect-permissions-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_dangerous_permissions'], G, indirect=True)
        # Check for high-value target and indirect permissions
        self.assertIn("DOMAIN ADMINS@LAB.LOCAL", output)  # High-value target now present
        self.assertIn("Indirect via group", output)

    def test_sid_history_abuse(self):
        try:
            G = self._load_and_build_graph("sid-history-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_sid_history_abuse'], G)
        # Now checks outgoing edges correctly; handle newline in output
        self.assertIn("SID History potential", output)
        self.assertIn("DOMAIN ADMINS@LAB.LOCAL", output.replace("\n", ""))  # Remove newlines for assertion

    def test_database_persistence(self):
        try:
            G = self._load_and_build_graph("adcs-tests")  # Use existing directory for basic data
        except FileNotFoundError as e:
            self.skipTest(str(e))
        db_path = os.path.join(self.temp_dir, "test.db")
        bloodbash_globals['save_graph_to_db'](G, db_path)
        self.assertTrue(os.path.exists(db_path))
        G_loaded, _ = bloodbash_globals['load_graph_from_db'](db_path)
        self.assertEqual(G.number_of_nodes(), G_loaded.number_of_nodes())
        self.assertEqual(G.number_of_edges(), G_loaded.number_of_edges())
    
    def test_severity_scoring_and_prioritization(self):
        bloodbash_globals['global_findings'].clear()
        bloodbash_globals['add_finding']("ESC1-ESC8", "Test ESC issue")
        bloodbash_globals['add_finding']("Kerberoastable", "Test kerb issue")
        output = self._capture_output(bloodbash_globals['print_prioritized_findings'])
        self.assertIn("Prioritized Findings", output)
        self.assertIn("ESC1-ESC8", output)
        self.assertIn("Test ESC issue", output)
        lines = output.split('\n')
        esc_line = next((line for line in lines if "ESC1-ESC8" in line), None)
        kerb_line = next((line for line in lines if "Kerberoastable" in line), None)
        if esc_line and kerb_line:
            self.assertLess(lines.index(esc_line), lines.index(kerb_line))
    
    def test_export_html(self):
        try:
            G = self._load_and_build_graph("adcs-tests")  # Use existing directory
        except FileNotFoundError as e:
            self.skipTest(str(e))
        export_path = os.path.join(self.temp_dir, "test")
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="html")
        html_file = f"{export_path}.html"
        self.assertTrue(os.path.exists(html_file))
        with open(html_file, 'r') as f:
            content = f.read()
            self.assertIn("<html>", content)
            self.assertIn("BashHound Report", content)
            self.assertIn("Prioritized Findings", content)
    
    def test_export_csv(self):
        try:
            G = self._load_and_build_graph("local-admin-sessions-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        export_path = os.path.join(self.temp_dir, "test")
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="csv")
        csv_file = f"{export_path}_sessions.csv"
        self.assertTrue(os.path.exists(csv_file))
        with open(csv_file, 'r') as f:
            lines = f.readlines()
            self.assertGreater(len(lines), 1)
            self.assertIn("Principal", lines[0])
    
    def test_get_indirect_paths(self):
        # Mock graph directly (no file dependency)
        G = nx.MultiDiGraph()
        G.add_node("U", name="User")
        G.add_node("G", name="Group", type="Group")
        G.add_node("T", name="Target")
        G.add_edge("U", "G", label="MemberOf")
        G.add_edge("G", "T", label="AdminTo")
        paths = bloodbash_globals['get_indirect_paths'](G, "U", "T")
        self.assertGreater(len(paths), 0)
        self.assertIn("G", paths[0])

if __name__ == '__main__':
    unittest.main()
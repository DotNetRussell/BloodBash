import unittest
import sys
import os
import tempfile
import shutil
from io import StringIO
from unittest.mock import patch, MagicMock, mock_open
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
        # Reset global findings between tests to avoid cross-test pollution
        bloodbash_globals['global_findings'].clear()
    
    def tearDown(self):
        # Clean up temp directory
        shutil.rmtree(self.temp_dir)
        # Clear global findings after each test
        bloodbash_globals['global_findings'].clear()
    
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
    

    def test_new_features_password_never_expires(self):
        """Test detection of users with 'Password Never Expires' set."""
        G = nx.MultiDiGraph()
        G.add_node("U1", name="User1", type="User", props={"passwordneverexpires": True})  # Should detect
        G.add_node("U2", name="User2", type="User", props={"passwordneverexpires": False})  # Should not detect
        G.add_node("U3", name="User3", type="User", props={"PasswordNeverExpires": True})  # Case-insensitive
        G.add_node("U4", name="User4", type="User", props={})  # Missing prop, should not detect
        output = self._capture_output(bloodbash_globals['print_password_never_expires'], G)
        self.assertIn("Password Never Expires", output)
        self.assertIn("User1", output)
        self.assertIn("User3", output)
        self.assertNotIn("User2", output)
        self.assertNotIn("User4", output)
        # Check findings were added
        self.assertTrue(any("Password Never Expires" in f[2] for f in bloodbash_globals['global_findings']))

    def test_new_features_password_not_required(self):
        """Test detection of users with 'Password Not Required' set."""
        G = nx.MultiDiGraph()
        G.add_node("U1", name="User1", type="User", props={"passwordnotrequired": True})  # Should detect
        G.add_node("U2", name="User2", type="User", props={"passwordnotrequired": False})  # Should not detect
        G.add_node("U3", name="User3", type="User", props={"PasswordNotRequired": True})  # Case-insensitive
        G.add_node("U4", name="User4", type="User", props={})  # Missing prop, should not detect
        output = self._capture_output(bloodbash_globals['print_password_not_required'], G)
        self.assertIn("Password Not Required", output)
        self.assertIn("User1", output)
        self.assertIn("User3", output)
        self.assertNotIn("User2", output)
        self.assertNotIn("User4", output)
        # Check findings were added
        self.assertTrue(any("Password Not Required" in f[2] for f in bloodbash_globals['global_findings']))

    def test_export_yaml(self):
        """Test YAML export functionality."""
        G = nx.MultiDiGraph()
        G.add_node("T", name="Target", type="User")
        bloodbash_globals['add_finding']("Test", "Sample finding")
        export_path = os.path.join(self.temp_dir, "test")
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="yaml")
        yaml_file = f"{export_path}.yaml"
        self.assertTrue(os.path.exists(yaml_file))
        with open(yaml_file, 'r') as f:
            content = f.read()
            self.assertIn("nodes:", content)
            self.assertIn("edges:", content)
            self.assertIn("high_value:", content)
            self.assertIn("Sample finding", content)  # Findings included

    def test_no_results_password_never_expires(self):
        """Test that print_password_never_expires handles no matches gracefully."""
        G = nx.MultiDiGraph()
        G.add_node("U", name="User", type="User", props={"passwordneverexpires": False})
        output = self._capture_output(bloodbash_globals['print_password_never_expires'], G)
        self.assertIn("No users with 'Password Never Expires' found", output)

    def test_no_results_password_not_required(self):
        """Test that print_password_not_required handles no matches gracefully."""
        G = nx.MultiDiGraph()
        G.add_node("U", name="User", type="User", props={"passwordnotrequired": False})
        output = self._capture_output(bloodbash_globals['print_password_not_required'], G)
        self.assertIn("No users with 'Password Not Required' found", output)

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
        self.assertIn("DOMAIN ADMINS@LAB.LOCAL", output)
        self.assertIn("Indirect paths", output)
        self.assertIn("via groups", output)
    
    def test_indirect_dangerous_permissions(self):
        try:
            G = self._load_and_build_graph("indirect-permissions-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_dangerous_permissions'], G, indirect=True)
        self.assertIn("DOMAIN ADMINS@LAB.LOCAL", output)
        self.assertIn("Indirect via group", output)
    
    def test_sid_history_abuse(self):
        try:
            G = self._load_and_build_graph("sid-history-tests")
        except FileNotFoundError as e:
            self.skipTest(str(e))
        output = self._capture_output(bloodbash_globals['print_sid_history_abuse'], G)
        self.assertIn("SID History potential", output)
        self.assertIn("DOMAIN ADMINS@LAB.LOCAL", output.replace("\n", ""))
    
    def test_database_persistence(self):
        try:
            G = self._load_and_build_graph("adcs-tests")
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
            G = self._load_and_build_graph("adcs-tests")
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
        G = nx.MultiDiGraph()
        G.add_node("U", name="User")
        G.add_node("G", name="Group", type="Group")
        G.add_node("T", name="Target")
        G.add_edge("U", "G", label="MemberOf")
        G.add_edge("G", "T", label="AdminTo")
        paths = bloodbash_globals['get_indirect_paths'](G, "U", "T")
        self.assertGreater(len(paths), 0)
        self.assertIn("G", paths[0])
    
    def test_error_handling_invalid_json(self):
        """Test that invalid JSON files are handled gracefully without crashing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            invalid_json_path = os.path.join(temp_dir, "invalid.json")
            with open(invalid_json_path, 'w') as f:
                f.write("{ invalid json }")
            with patch.object(bloodbash_globals['console'], 'print') as mock_print:
                nodes = bloodbash_globals['load_json_dir'](temp_dir)
                # Check for partial match in calls (message may vary slightly)
                self.assertTrue(any("Warning" in str(call) and "invalid.json" in str(call) for call in mock_print.call_args_list))
                self.assertEqual(len(nodes), 0)
    
    def test_case_sensitivity_types_and_labels(self):
        """Test that types and labels are handled case-insensitively."""
        # Mock graph with mixed-case data and a high-value target
        G = nx.MultiDiGraph()
        G.add_node("U", name="User", type="USER")
        G.add_node("C", name="DC1$", type="computer")  # High-value name for testing
        G.add_node("G", name="Group", type="GROUP")
        G.add_edge("U", "C", label="ADMinto")
        # Test that get_high_value_targets finds the computer
        targets = bloodbash_globals['get_high_value_targets'](G)
        self.assertTrue(any("computer" in t[2].lower() for t in targets))
        # Test path formatting preserves label case
        path = ["U", "C"]
        formatted = bloodbash_globals['format_path'](G, path)
        self.assertIn("ADMinto", formatted)
    
    def test_performance_fast_mode_and_limits(self):
        """Test that fast mode skips heavy computations and respects limits."""
        # Create a large mock graph with a high-value target
        G = nx.MultiDiGraph()
        G.add_node("T", name="DC1$", type="Computer")  # High-value to trigger logic
        for i in range(100):
            G.add_node(f"N{i}", name=f"Node{i}", type="User")
            if i > 0:
                G.add_edge(f"N{i-1}", f"N{i}", label="MemberOf")
        # Fast mode should skip path computation
        output = self._capture_output(bloodbash_globals['print_shortest_paths'], G, fast=True, max_paths=5)
        self.assertIn("Fast mode enabled", output)
        self.assertNotIn("Length:", output)
        # Test indirect paths limit
        paths = bloodbash_globals['get_indirect_paths'](G, "N0", "N99")
        self.assertLessEqual(len(paths), 5)
    
    def test_code_duplication_roastable_checks(self):
        """Test shared logic for roastable checks."""
        G = nx.MultiDiGraph()
        G.add_node("K", name="KerbUser", type="User", props={"hasspn": True, "sensitive": False, "enabled": True})
        G.add_node("A", name="AsRepUser", type="User", props={"dontreqpreauth": True, "sensitive": False, "enabled": True})
        kerb_output = self._capture_output(bloodbash_globals['print_kerberoastable'], G)
        asrep_output = self._capture_output(bloodbash_globals['print_as_rep_roastable'], G)
        self.assertIn("KerbUser", kerb_output)
        self.assertIn("AsRepUser", asrep_output)
        self.assertNotIn("AsRepUser", kerb_output)
    
    def test_bugs_placeholder_nodes_and_missing_data(self):
        """Test graph building handles placeholders and missing OIDs."""
        # Mock nodes with relationship and a high-value target to avoid early exit
        nodes = {
            "rel1": {"start": "UserA", "end": "GroupB", "label": "MemberOf"},
            "UserA": {"ObjectIdentifier": "UserA", "Properties": {"name": "UserA"}, "ObjectType": "User"},
            "T": {"ObjectIdentifier": "T", "Properties": {"name": "DC1$"}, "ObjectType": "Computer"}  # High-value
        }
        G, _ = bloodbash_globals['build_graph'](nodes)
        self.assertIn("UserA", G.nodes)
        # Check if placeholder node for "GroupB" was created
        groupb_node = next((n for n in G.nodes if G.nodes[n].get('name') == "GroupB"), None)
        self.assertIsNotNone(groupb_node, "Placeholder node for 'GroupB' should exist")
        # Then check the edge exists
        self.assertTrue(G.has_edge("UserA", groupb_node))
    
    def test_security_input_validation_and_escaping(self):
        """Test input validation and HTML escaping."""
        with patch.object(bloodbash_globals['console'], 'print') as mock_print:
            nodes = bloodbash_globals['load_json_dir']("/nonexistent")
            # Now it should handle gracefully without crashing
            mock_print.assert_called_with("[yellow]Warning: Directory '/nonexistent' not found. Skipping.[/yellow]")
            self.assertEqual(len(nodes), 0)  # Should return empty
        # Test HTML escaping (unchanged)
        G = nx.MultiDiGraph()
        G.add_node("T", name="<script>alert('xss')</script>", type="User")
        bloodbash_globals['add_finding']("Test", "Injected<script>")
        export_path = os.path.join(self.temp_dir, "test")
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="html")
        with open(f"{export_path}.html", 'r') as f:
            content = f.read()
            self.assertNotIn("<script>", content)  # Escaped
            self.assertIn("&lt;script&gt;", content)
    
    def test_new_features_unconstrained_delegation(self):
        """Test unconstrained delegation detection."""
        G = nx.MultiDiGraph()
        G.add_node("C1", name="Comp1", type="Computer", props={"TrustedForDelegation": True})
        G.add_node("C2", name="Comp2", type="Computer", props={"TrustedForDelegation": False})
        output = self._capture_output(bloodbash_globals['print_unconstrained_delegation'], G)
        self.assertIn("Unconstrained delegation enabled", output)
        self.assertIn("Comp1", output)
        self.assertNotIn("Comp2", output)
    
    def test_new_features_password_in_description(self):
        """Test detection of passwords in user descriptions, including None values."""
        G = nx.MultiDiGraph()
        G.add_node("U1", name="User1", type="User", props={"description": "Password: P@ssw0rd123"})
        G.add_node("U2", name="User2", type="User", props={"description": "Normal description"})
        G.add_node("U3", name="User3", type="User", props={"description": None})  # Test explicit None handling
        output = self._capture_output(bloodbash_globals['print_password_in_descriptions'], G)
        self.assertIn("Potential password in description", output)
        self.assertIn("User1", output)  # Should detect password pattern
        self.assertNotIn("User2", output)  # Should not detect normal description
        self.assertNotIn("User3", output)  # Should not detect None (treated as empty)
    
    def test_export_md_and_json(self):
        """Test MD and JSON exports."""
        G = nx.MultiDiGraph()
        G.add_node("T", name="Target", type="User")
        bloodbash_globals['add_finding']("Test", "Sample finding")
        export_path = os.path.join(self.temp_dir, "test")
        # MD
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="md")
        self.assertTrue(os.path.exists(f"{export_path}.md"))
        # JSON
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="json")
        self.assertTrue(os.path.exists(f"{export_path}.json"))
        with open(f"{export_path}.json", 'r') as f:
            data = json.load(f)
            self.assertIn("nodes", data)
    
    def test_prioritization_custom_scores(self):
        """Test custom scores."""
        bloodbash_globals['global_findings'].clear()
        bloodbash_globals['add_finding']("Custom", "Low priority", score=1)
        bloodbash_globals['add_finding']("Custom2", "High priority", score=10)
        output = self._capture_output(bloodbash_globals['print_prioritized_findings'])
        lines = output.split('\n')
        high_line = next((line for line in lines if "High priority" in line), None)
        low_line = next((line for line in lines if "Low priority" in line), None)
        if high_line and low_line:
            self.assertLess(lines.index(high_line), lines.index(low_line))
    
    def test_no_results_adcs_vulnerabilities(self):
        """Test that print_adcs_vulnerabilities handles no vulnerabilities gracefully."""
        G = nx.MultiDiGraph()  # Empty graph with no PKI objects
        G.add_node("Dummy", name="Dummy", type="User")  # Add a non-PKI node
        output = self._capture_output(bloodbash_globals['print_adcs_vulnerabilities'], G)
        self.assertIn("No obvious ESC1–ESC8 misconfigurations detected", output)
    
    def test_no_results_shortest_paths(self):
        """Test that print_shortest_paths handles no paths gracefully."""
        G = nx.MultiDiGraph()
        G.add_node("User", name="User", type="User")
        G.add_node("Target", name="DC1$", type="Computer")  # High-value name ('dc' keyword) to trigger target detection
        # No edges, so no paths can be found
        output = self._capture_output(bloodbash_globals['print_shortest_paths'], G)
        self.assertIn("No paths found", output)  # Should now check paths and find none
    
    def test_no_results_dangerous_permissions(self):
        """Test that print_dangerous_permissions handles no high-value targets gracefully."""
        G = nx.MultiDiGraph()
        G.add_node("User", name="User", type="User")  # No high-value targets
        output = self._capture_output(bloodbash_globals['print_dangerous_permissions'], G)
        self.assertIn("No high-value targets found", output)
    
    def test_no_results_get_high_value_targets(self):
        """Test that get_high_value_targets returns empty list for no matches."""
        G = nx.MultiDiGraph()
        G.add_node("N1", name="RegularUser", type="User")  # No high-value keywords
        targets = bloodbash_globals['get_high_value_targets'](G)
        self.assertEqual(len(targets), 0)
    
    def test_no_results_export_empty_graph(self):
        """Test that export_results handles empty graph gracefully."""
        G = nx.MultiDiGraph()  # Completely empty
        export_path = os.path.join(self.temp_dir, "empty")
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="json")
        self.assertTrue(os.path.exists(f"{export_path}.json"))
        with open(f"{export_path}.json", 'r') as f:
            data = json.load(f)
            self.assertEqual(data.get("nodes"), 0)  # Should report 0 nodes
    
    def test_full_analysis_integration(self):
        """Test full analysis mode runs all checks and generates findings."""
        # Load a basic graph with vulnerabilities
        try:
            G = self._load_and_build_graph("adcs-tests")  # Reuse existing data
        except FileNotFoundError:
            self.skipTest("Test data missing")
        # Simulate --all mode by calling functions manually (since main() uses argparse)
        bloodbash_globals['global_findings'].clear()
        self._capture_output(bloodbash_globals['print_adcs_vulnerabilities'], G)
        self._capture_output(bloodbash_globals['print_dcsync_rights'], G)
        self._capture_output(bloodbash_globals['print_shortest_paths'], G)
        output = self._capture_output(bloodbash_globals['print_prioritized_findings'])
        self.assertIn("Prioritized Findings", output)
        self.assertGreater(len(bloodbash_globals['global_findings']), 0)
    
    def test_indirect_permissions_complex_groups(self):
        """Test indirect permissions through group chains."""
        G = nx.MultiDiGraph()
        G.add_node("U", name="User", type="User")
        G.add_node("G", name="Group", type="Group")
        G.add_node("T", name="DC1$", type="Computer")  # High-value
        G.add_edge("U", "G", label="MemberOf")  # User is member of Group
        G.add_edge("G", "T", label="GenericAll")  # Dangerous right (in dangerous_rights set)
        output = self._capture_output(bloodbash_globals['print_dangerous_permissions'], G, indirect=True)
        self.assertIn("Indirect via group", output)  # Should detect and print
        self.assertIn("User", output)  # Should list the user
    
    def test_export_html_with_findings(self):
        """Test HTML export includes findings and escapes content."""
        G = nx.MultiDiGraph()
        G.add_node("T", name="Target", type="User")
        bloodbash_globals['add_finding']("Test", "<script>alert('xss')</script>")
        export_path = os.path.join(self.temp_dir, "with_findings")
        bloodbash_globals['export_results'](G, output_prefix=export_path, format_type="html")
        with open(f"{export_path}.html", 'r') as f:
            content = f.read()
            self.assertIn("Prioritized Findings", content)
            self.assertNotIn("<script>", content)  # Escaped
            self.assertIn("&lt;script&gt;", content)
    
    def test_state_isolation_multiple_runs(self):
        """Test that global state is reset between runs."""
        bloodbash_globals['global_findings'].clear()
        bloodbash_globals['add_finding']("Run1", "Test1")
        output1 = self._capture_output(bloodbash_globals['print_prioritized_findings'])
        self.assertIn("Test1", output1)
        bloodbash_globals['global_findings'].clear()
        bloodbash_globals['add_finding']("Run2", "Test2")
        output2 = self._capture_output(bloodbash_globals['print_prioritized_findings'])
        self.assertIn("Test2", output2)
        self.assertNotIn("Test1", output2)  # Isolated
    
    def test_case_insensitive_properties(self):
        """Test that property checks are case-insensitive."""
        G = nx.MultiDiGraph()
        G.add_node("K1", name="Kerb1", type="User", props={"HASSPN": True, "sensitive": False, "enabled": True})  # Corrected key: 'HASSPN' -> 'hasspn'
        G.add_node("K2", name="Kerb2", type="User", props={"hasSPN": True, "Sensitive": False, "Enabled": True})
        output = self._capture_output(bloodbash_globals['print_kerberoastable'], G)
        self.assertIn("Kerb1", output)  # Should now detect due to case-insensitive match
        self.assertIn("Kerb2", output)
    
    def test_prioritization_multiple_findings_and_sorting(self):
        """Test prioritization with multiple findings of varying severity."""
        bloodbash_globals['global_findings'].clear()
        # Add findings with different scores
        bloodbash_globals['add_finding']("Kerberoastable", "Low-risk kerb account", score=5)
        bloodbash_globals['add_finding']("DCSync", "High-risk DCSync", score=10)
        bloodbash_globals['add_finding']("GPO Abuse", "Medium-risk GPO", score=7)
        output = self._capture_output(bloodbash_globals['print_prioritized_findings'])
        lines = output.split('\n')
        # Extract lines with findings (skip headers)
        finding_lines = [line for line in lines if "DCSync" in line or "GPO" in line or "Kerberoastable" in line]
        # Ensure DCSync (score 10) appears before GPO (7), which appears before Kerberoastable (5)
        dcsync_idx = next(i for i, line in enumerate(finding_lines) if "DCSync" in line)
        gpo_idx = next(i for i, line in enumerate(finding_lines) if "GPO" in line)
        kerb_idx = next(i for i, line in enumerate(finding_lines) if "Kerberoastable" in line)
        self.assertLess(dcsync_idx, gpo_idx)
        self.assertLess(gpo_idx, kerb_idx)
    
    def test_large_graph_performance(self):
        """Test performance on large graphs with limits."""
        G = nx.MultiDiGraph()
        # Create a large graph with chains of nodes
        for i in range(1000):
            G.add_node(f"N{i}", name=f"Node{i}", type="User" if i % 2 == 0 else "Computer")
            if i > 0:
                G.add_edge(f"N{i-1}", f"N{i}", label="MemberOf")
        # Add a high-value target
        G.add_node("Target", name="DC1$", type="Computer")
        # Test fast mode skips computation
        output = self._capture_output(bloodbash_globals['print_shortest_paths'], G, fast=True, max_paths=5)
        self.assertIn("Fast mode enabled", output)
        self.assertNotIn("Length:", output)
        # Test normal mode with limits (should not hang, limit to 5 paths)
        output = self._capture_output(bloodbash_globals['print_shortest_paths'], G, max_paths=5)
        path_count = output.count("Length:")
        self.assertLessEqual(path_count, 5)

if __name__ == '__main__':
    unittest.main()

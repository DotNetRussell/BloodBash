#!/usr/bin/env python3
"""Regression tests for the v1.5 ingest fixes.

Covers Azure misclassification, duplicate object ids inside one collection,
and nested collector output directories.
"""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import networkx as nx

import BloodBash as bb


def _write(path: Path, payload) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")


def _user(oid: str, name: str, **props) -> dict:
    props.setdefault("name", name)
    props.setdefault("enabled", True)
    return {"ObjectIdentifier": oid, "ObjectType": "User", "Properties": props}


class TestAzureDetection(unittest.TestCase):
    def test_ad_name_containing_azure_is_not_azure(self):
        d = Path(tempfile.mkdtemp())
        _write(
            d / "20240101_users.json",
            {
                "meta": {"type": "users", "count": 1, "version": 6},
                "data": [_user("S-1-5-21-1-2-3-1105", "AZURE_MAINT@CORP.LOCAL")],
            },
        )
        nodes = bb.load_json_dir(str(d))
        node = nodes["S-1-5-21-1-2-3-1105"]
        self.assertFalse(node.get("IsAzure"))
        self.assertEqual(node["ObjectType"], "User")

    def test_ad_description_mentioning_microsoft_is_not_azure(self):
        d = Path(tempfile.mkdtemp())
        _write(
            d / "20240101_groups.json",
            {
                "meta": {"type": "groups", "count": 1, "version": 6},
                "data": [
                    {
                        "ObjectIdentifier": "S-1-5-21-1-2-3-513",
                        "ObjectType": "Group",
                        "Properties": {
                            "name": "DOMAIN USERS@CORP.LOCAL",
                            "description": "Synced from microsoft.com tenant",
                        },
                    }
                ],
            },
        )
        nodes = bb.load_json_dir(str(d))
        self.assertFalse(nodes["S-1-5-21-1-2-3-513"].get("IsAzure"))

    def test_azurehound_kind_still_detected(self):
        d = Path(tempfile.mkdtemp())
        _write(
            d / "azure.json",
            [
                {
                    "kind": "azuser",
                    "data": {"id": "az-1", "displayName": "Alice", "userPrincipalName": "alice@contoso.com"},
                }
            ],
        )
        nodes = bb.load_json_dir(str(d))
        self.assertTrue(nodes["az-1"].get("IsAzure"))

    def test_plural_meta_type_azureusers_detected(self):
        d = Path(tempfile.mkdtemp())
        _write(
            d / "azureusers.json",
            {"meta": {"type": "azureusers", "count": 1}, "data": [{"id": "az-2", "displayName": "Bob"}]},
        )
        nodes = bb.load_json_dir(str(d))
        self.assertTrue(nodes["az-2"].get("IsAzure"))


class TestDuplicateObjectIds(unittest.TestCase):
    def test_later_record_without_memberof_keeps_edges(self):
        d = Path(tempfile.mkdtemp())
        first = _user("S-1-5-21-1-1-1-1105", "ALICE@C.L")
        first["MemberOf"] = [{"ObjectIdentifier": "S-1-5-21-1-1-1-512", "ObjectType": "Group"}]
        second = _user("S-1-5-21-1-1-1-1105", "ALICE@C.L", description="newer collect")
        _write(d / "20240101_users.json", {"meta": {"type": "users"}, "data": [first]})
        _write(d / "20240201_users.json", {"meta": {"type": "users"}, "data": [second]})

        nodes = bb.load_json_dir(str(d))
        self.assertEqual(len(nodes), 1)
        merged = nodes["S-1-5-21-1-1-1-1105"]
        self.assertIn("MemberOf", merged)
        self.assertEqual(merged["Properties"].get("description"), "newer collect")

        G, _ = bb.build_graph(nodes)
        self.assertTrue(any(d2.get("label") == "MemberOf" for _, _, d2 in G.edges(data=True)))

    def test_named_record_wins_over_sid_only(self):
        d = Path(tempfile.mkdtemp())
        sid_only = {
            "ObjectIdentifier": "S-1-5-21-1-1-1-1200",
            "ObjectType": "User",
            "Properties": {"name": "S-1-5-21-1-1-1-1200", "enabled": True},
        }
        named = _user("S-1-5-21-1-1-1-1200", "REALUSER@C.L")
        _write(d / "a_users.json", {"meta": {"type": "users"}, "data": [sid_only]})
        _write(d / "b_users.json", {"meta": {"type": "users"}, "data": [named]})
        nodes = bb.load_json_dir(str(d))
        self.assertEqual(nodes["S-1-5-21-1-1-1-1200"]["Properties"]["name"], "REALUSER@C.L")


class TestNestedCollectorOutput(unittest.TestCase):
    def test_json_in_subdirectory_is_loaded(self):
        d = Path(tempfile.mkdtemp())
        _write(d / "inner" / "users.json", {"meta": {"type": "users"}, "data": [_user("S-1-5-21-9-9-9-1105", "X@C.L")]})
        nodes = bb.load_json_dir(str(d))
        self.assertEqual(len(nodes), 1)
        self.assertTrue(bb.sources_have_collection_data([str(d)]))

    def test_deep_nesting_bounded(self):
        d = Path(tempfile.mkdtemp())
        _write(d / "a" / "b" / "c" / "users.json", {"meta": {"type": "users"}, "data": [_user("S-1-5-21-9-9-9-1106", "Y@C.L")]})
        nodes = bb.load_json_dir(str(d))
        self.assertEqual(len(nodes), 1)

    def test_zip_with_nested_folder_loads(self):
        import zipfile

        d = Path(tempfile.mkdtemp())
        zpath = d / "collection.zip"
        with zipfile.ZipFile(zpath, "w") as zf:
            zf.writestr(
                "corp/users.json",
                json.dumps({"meta": {"type": "users"}, "data": [_user("S-1-5-21-9-9-9-1107", "Z@C.L")]}),
            )
        nodes = bb.load_json_dir(str(zpath))
        self.assertEqual(len(nodes), 1)

    def test_fingerprint_covers_nested_files(self):
        d = Path(tempfile.mkdtemp())
        _write(d / "inner" / "users.json", {"meta": {"type": "users"}, "data": [_user("S-1-5-21-9-9-9-1108", "Q@C.L")]})
        fp1 = bb.compute_collection_fingerprint([str(d)])
        _write(d / "inner" / "users.json", {"meta": {"type": "users"}, "data": [_user("S-1-5-21-9-9-9-1108", "Q2@C.L")]})
        fp2 = bb.compute_collection_fingerprint([str(d)])
        self.assertNotEqual(fp1, fp2)


if __name__ == "__main__":
    unittest.main()

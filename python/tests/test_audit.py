from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from dataset_delivery_audit.core import AuditError, audit, file_sha256, load_config, load_expectation, scan


class DeliveryAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.repo = Path(__file__).resolve().parents[2]
        cls.temp = tempfile.TemporaryDirectory(prefix="delivery-audit-tests.")
        cls.root = Path(cls.temp.name)
        cls.generated = cls.root / "generated"
        subprocess.run(["python3", str(cls.repo / "scripts/generate_fixtures.py"), "--output-dir", str(cls.generated)], check=True)
        cls.valid = audit(cls.generated / "valid-delivery", cls.repo / "configs/audit-v1.json", cls.root / "valid", cls.generated / "valid-expectation.json")
        cls.problem = audit(cls.generated / "problem-delivery", cls.repo / "configs/audit-v1.json", cls.root / "problem", cls.generated / "problem-expectation.json")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def test_empty_directory(self) -> None:
        root = self.root / "empty"
        root.mkdir()
        self.assertEqual(scan(root), [])

    def test_single_file_and_streaming_sha256(self) -> None:
        root = self.root / "large"
        root.mkdir()
        data = b"0123456789" * 100_000
        (root / "one.txt").write_bytes(data)
        item = scan(root)[0]
        self.assertEqual(item["size_bytes"], len(data))
        self.assertEqual(item["sha256"], file_sha256(root / "one.txt"))

    def test_recursive_order_is_stable(self) -> None:
        left, right = self.root / "order-left", self.root / "order-right"
        for root, names in ((left, ("b", "a")), (right, ("a", "b"))):
            root.mkdir()
            for name in names:
                (root / f"{name}.txt").write_text(name, encoding="utf-8")
        self.assertEqual(scan(left), scan(right))

    def test_duplicate_content_group(self) -> None:
        root = self.root / "duplicates"
        root.mkdir()
        (root / "a.txt").write_text("same", encoding="utf-8")
        (root / "b.txt").write_text("same", encoding="utf-8")
        values = scan(root)
        self.assertIsNotNone(values[0]["duplicate_content_group"])
        self.assertEqual(values[0]["duplicate_content_group"], values[1]["duplicate_content_group"])

    def test_symlink_is_not_followed(self) -> None:
        root = self.root / "links"
        root.mkdir()
        (root / "target.txt").write_text("target", encoding="utf-8")
        os.symlink("target.txt", root / "link.txt")
        by_path = {item["path"]: item for item in scan(root)}
        self.assertEqual(by_path["link.txt"]["entry_type"], "symlink")
        self.assertIsNone(by_path["link.txt"]["sha256"])

    def test_output_inside_input_is_rejected(self) -> None:
        with self.assertRaisesRegex(AuditError, "output_directory_inside_input_root"):
            audit(self.generated / "valid-delivery", self.repo / "configs/audit-v1.json", self.generated / "valid-delivery/output")

    def test_valid_delivery_has_no_issues(self) -> None:
        self.assertEqual(self.valid["summary"]["issue_count"], 0)
        self.assertEqual(self.valid["summary"]["regular_file_count"], 8)
        self.assertEqual(self.valid["summary"]["dataset_count"], 3)

    def test_problem_truth_matches_all_issues(self) -> None:
        truth = json.loads((self.generated / "injection-truth.json").read_text(encoding="utf-8"))["injections"]
        key = lambda item: (item["issue_category"], item["code"], item["dataset_id"], item["path"], item["line"], item["member"], item["field"])
        self.assertEqual({key(item) for item in truth}, {key(item) for item in self.problem["issues"]})
        self.assertEqual(len(truth), len(self.problem["issues"]))

    def test_archive_issue_coverage(self) -> None:
        codes = {item["code"] for item in self.problem["issues"] if item["issue_category"] == "ISS-02"}
        self.assertEqual(codes, {"archive_integrity_failure", "archive_crc_failure", "archive_encrypted", "archive_empty", "archive_truncated", "archive_unsafe_member_path", "archive_limit_exceeded", "archive_extension_mismatch"})

    def test_format_issue_coverage_and_jsonl_continues(self) -> None:
        issues = [item for item in self.problem["issues"] if item["issue_category"] == "ISS-03"]
        self.assertEqual(len(issues), 8)
        self.assertIn(("jsonl_parse_failure", 2), {(item["code"], item["line"]) for item in issues})

    def test_schema_issue_coverage(self) -> None:
        codes = {item["code"] for item in self.problem["issues"] if item["issue_category"] == "ISS-04"}
        self.assertEqual(codes, {"schema_missing_required_field", "schema_type_mismatch", "schema_version_missing", "schema_version_unsupported", "schema_unknown_field", "schema_record_count_mismatch", "schema_mixed_versions"})

    def test_without_expectation_does_not_invent_missing_or_unexpected(self) -> None:
        value = audit(self.generated / "valid-delivery", self.repo / "configs/audit-v1.json", self.root / "no-expectation")
        self.assertFalse({"missing_required_file", "unexpected_file"} & {item["code"] for item in value["issues"]})

    def test_duplicate_expectation_path_is_rejected(self) -> None:
        value = json.loads((self.generated / "valid-expectation.json").read_text(encoding="utf-8"))
        value["files"].append(value["files"][0])
        path = self.root / "duplicate-expectation.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(AuditError, "duplicate_expectation_path"):
            load_expectation(path)

    def test_invalid_config_is_rejected(self) -> None:
        value = json.loads((self.repo / "configs/audit-v1.json").read_text(encoding="utf-8"))
        value["archive_limits"]["max_member_count"] = 0
        path = self.root / "invalid-config.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(AuditError, "invalid_archive_limits"):
            load_config(path)

    def test_duplicate_record_id_is_rejected(self) -> None:
        root = self.root / "duplicate-record"
        root.mkdir()
        record = {"record_id": "same", "dataset_id": "d", "source_file": "x", "source_offset": 0, "record_type": "article", "event_date": None, "title": None, "raw_text": "x", "clean_text": "x", "metadata": {}, "parser_version": "p", "schema_version": "record-v1"}
        (root / "records.jsonl").write_text(json.dumps(record) + "\n" + json.dumps(record) + "\n", encoding="utf-8")
        expectation = {"delivery_id": "d", "files": [{"dataset_id": "d", "path": "records.jsonl", "expected_format": "jsonl", "expected_encoding": "utf8", "expected_schema_version": "record-v1", "required": True}], "contract_version": "delivery-expectation-v1"}
        path = self.root / "duplicate-record-expectation.json"
        path.write_text(json.dumps(expectation), encoding="utf-8")
        with self.assertRaisesRegex(AuditError, "duplicate_record_id"):
            audit(root, self.repo / "configs/audit-v1.json", self.root / "duplicate-record-out", path)

    def test_outputs_are_repeatable_and_safe(self) -> None:
        second = self.root / "problem-two"
        audit(self.generated / "problem-delivery", self.repo / "configs/audit-v1.json", second, self.generated / "problem-expectation.json")
        for name in ("file-inventory.jsonl", "issues.jsonl", "audit-summary.json", "run-manifest.json"):
            first_bytes = (self.root / "problem" / name).read_bytes()
            self.assertEqual(first_bytes, (second / name).read_bytes())
            for line in first_bytes.decode().splitlines():
                self._assert_safe(json.loads(line))

    def _assert_safe(self, value: object) -> None:
        self.assertNotIsInstance(value, float)
        if isinstance(value, str):
            self.assertFalse(value.startswith("/Users/"))
        elif isinstance(value, list):
            for item in value:
                self._assert_safe(item)
        elif isinstance(value, dict):
            self.assertFalse(set(value) & {"timestamp", "created_at", "run_at", "time"})
            for item in value.values():
                self._assert_safe(item)


if __name__ == "__main__":
    unittest.main()


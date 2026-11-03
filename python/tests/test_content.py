from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from dataset_delivery_audit.content import (
    AuditError,
    audit_content,
    load_content_config,
    load_records,
    load_sample_plan,
    select_sample,
)

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures/content-generated"
CONFIG = ROOT / "configs/content-audit-v1.json"
PLAN = ROOT / "configs/content-sample-plan-v1.json"


def run(kind: str, output: Path, root: Path | None = None, quality: Path | None = None) -> dict:
    return audit_content(
        root or FIXTURES / f"{kind}-delivery",
        FIXTURES / f"{kind}-expectation.json",
        CONFIG,
        PLAN,
        FIXTURES / f"{kind}-canonical-decisions.jsonl",
        quality or FIXTURES / f"{kind}-quality-scores.jsonl",
        output,
    )


class ContentAuditTests(unittest.TestCase):
    def test_valid_delivery_has_zero_issues(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run("valid", Path(tmp) / "out")
        self.assertEqual(result["issues"], [])
        self.assertEqual((result["summary"]["population_count"], result["summary"]["sample_count"], result["summary"]["stratum_count"]), (12, 12, 12))

    def test_problem_truth_is_exact_and_all_categories_have_eight(self) -> None:
        truth = json.loads((FIXTURES / "injection-truth.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            issues = run("problem", Path(tmp) / "out")["issues"]
        actual = {(i["issue_category"], i["code"], i["severity"], i["dataset_id"], i["path"], i["record_id"], i["line"], i["field"], i["reference"], i["evidence_scope"]) for i in issues}
        expected = {(i["issue_category"], i["code"], i["expected_severity"], i["dataset_id"], i["path"], i["record_id"], i["line"], i["field"], i["reference"], i["expected_evidence_scope"]) for i in truth["injections"]}
        self.assertEqual(actual, expected)
        counts = {category: sum(issue["issue_category"] == category for issue in issues) for category in ("ISS-05", "ISS-06", "ISS-07", "ISS-08", "ISS-09")}
        self.assertTrue(all(value >= 8 for value in counts.values()), counts)

    def test_sampling_small_strata_and_manifest_reconcile(self) -> None:
        expectation = json.loads((FIXTURES / "problem-expectation.json").read_text())
        records = load_records(FIXTURES / "problem-delivery", expectation)
        sample, manifest = select_sample(records, load_sample_plan(PLAN))
        self.assertEqual(len(sample), len(records))
        self.assertEqual(sum(item["population_count"] for item in manifest["strata"]), manifest["population_count"])
        self.assertEqual(sum(item["sample_count"] for item in manifest["strata"]), manifest["sample_count"])
        self.assertTrue(all(item["sample_count"] == item["population_count"] for item in manifest["strata"]))

    def test_minimum_then_proportional_is_deterministic(self) -> None:
        records = []
        for dataset, count in (("a", 5), ("b", 3), ("c", 2)):
            for index in range(count):
                records.append({"record": {"record_id": f"{dataset}-{index}", "dataset_id": dataset, "record_type": "article", "event_date": "2026-01-01"}, "path": "records.jsonl", "line": index + 1, "expected_dataset_id": dataset})
        plan = {"plan_id": "p", "seed": 7, "target_size": 7, "strata_keys": ["dataset_id", "record_type", "event_month"], "allocation_method": "minimum_then_proportional", "minimum_per_stratum": 1, "filters": {}, "algorithm_version": "deterministic-stratified-sampling-v1", "schema_version": "sample-plan-v1"}
        first, first_manifest = select_sample(records, plan)
        second, second_manifest = select_sample(list(reversed(records)), plan)
        self.assertEqual([row["record"]["record_id"] for row in first], [row["record"]["record_id"] for row in second])
        self.assertEqual(first_manifest, second_manifest)
        self.assertEqual(len(first), 7)

    def test_repeat_is_byte_identical_and_reverse_selection_is_equal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            a, b = tmp / "a", tmp / "b"
            run("problem", a)
            run("problem", b)
            for name in ("record-issues.jsonl", "sampling-manifest.json", "content-summary.json", "run-manifest.json"):
                self.assertEqual((a / name).read_bytes(), (b / name).read_bytes())
            expectation = json.loads((FIXTURES / "problem-expectation.json").read_text())
            records = load_records(FIXTURES / "problem-delivery", expectation)
            plan = load_sample_plan(PLAN)
            forward, forward_manifest = select_sample(records, plan)
            reverse, reverse_manifest = select_sample(list(reversed(records)), plan)
            self.assertEqual([row["record"]["record_id"] for row in forward], [row["record"]["record_id"] for row in reverse])
            self.assertEqual(forward_manifest, reverse_manifest)

    def test_issue_code_families_and_evidence_reconciliation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = run("problem", Path(tmp) / "out")
        codes = set(result["summary"]["issues_by_code"])
        for required in ("content_empty_body", "record_near_duplicate_evidence", "event_date_future_as_of", "external_url_dependency", "evidence_fingerprint_mismatch"):
            self.assertIn(required, codes)
        evidence = result["summary"]["evidence_reconciliation"]
        self.assertEqual(evidence, {"delivered_record_count": 54, "canonical_decision_count": 53, "quality_score_count": 54, "canonical_selected_matched_count": 52, "quality_record_matched_count": 53})

    def test_quality_label_is_not_content_truth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            changed = tmp / "quality.jsonl"
            values = [json.loads(line) for line in (FIXTURES / "valid-quality-scores.jsonl").read_text().splitlines()]
            for value in values:
                value["score_based_label"] = "REJECT"
                value["final_label"] = "REJECT"
            changed.write_text("".join(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n" for value in values))
            result = run("valid", tmp / "out", quality=changed)
        self.assertEqual(result["issues"], [])

    def test_missing_canonical_does_not_recompute_near_duplicate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            issues = run("problem", Path(tmp) / "out")["issues"]
        missing = [item for item in issues if item["record_id"] == "prov-canonical-missing"]
        self.assertEqual([item["code"] for item in missing], ["canonical_evidence_missing"])

    def test_outputs_have_no_float_clock_absolute_path_or_body(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "out"
            run("problem", output)
            text = "".join(path.read_text() for path in output.iterdir())
            self.assertNotIn("/" + "Users/", text)
            self.assertNotIn("/" + "tmp/", text)
            self.assertNotRegex(text, r"\d{2}:\d{2}:\d{2}")
            self.assertNotIn("很长很长合成正文", text)
            def no_float(value: object) -> bool:
                if isinstance(value, float):
                    return False
                if isinstance(value, dict):
                    return all(no_float(item) for item in value.values())
                if isinstance(value, list):
                    return all(no_float(item) for item in value)
                return True
            for path in output.iterdir():
                for line in path.read_text().splitlines():
                    self.assertTrue(no_float(json.loads(line)))

    def test_invalid_config_and_sample_plan_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            config = json.loads(CONFIG.read_text())
            config["as_of_date"] = "today"
            bad_config = tmp / "config.json"
            bad_config.write_text(json.dumps(config))
            with self.assertRaisesRegex(AuditError, "invalid_as_of_date"):
                load_content_config(bad_config)
            plan = json.loads(PLAN.read_text())
            plan["allocation_method"] = "simple_random"
            bad_plan = tmp / "plan.json"
            bad_plan.write_text(json.dumps(plan))
            with self.assertRaisesRegex(AuditError, "unsupported_sample_plan"):
                load_sample_plan(bad_plan)

    def test_duplicate_record_and_evidence_ids_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            delivery = tmp / "delivery"
            shutil.copytree(FIXTURES / "valid-delivery", delivery)
            path = delivery / "alpha/records.jsonl"
            first = path.read_text().splitlines()[0]
            path.write_text(path.read_text() + first + "\n")
            with self.assertRaisesRegex(AuditError, "duplicate_record_id"):
                run("valid", tmp / "out", root=delivery)
            evidence = tmp / "decisions.jsonl"
            line = (FIXTURES / "valid-canonical-decisions.jsonl").read_text().splitlines()[0]
            evidence.write_text(line + "\n" + line + "\n")
            with self.assertRaisesRegex(AuditError, "duplicate_evidence_id"):
                audit_content(FIXTURES / "valid-delivery", FIXTURES / "valid-expectation.json", CONFIG, PLAN, evidence, FIXTURES / "valid-quality-scores.jsonl", tmp / "evidence-out")

    def test_issue_v2_required_fields_and_scopes(self) -> None:
        schema = json.loads((ROOT / "contracts/issue-v2.schema.json").read_text())
        with tempfile.TemporaryDirectory() as tmp:
            issues = run("problem", Path(tmp) / "out")["issues"]
        self.assertTrue(set(schema["required"]) <= set(issues[0]))
        self.assertEqual({item["schema_version"] for item in issues}, {"issue-v2"})
        self.assertEqual({item["algorithm_version"] for item in issues}, {"delivery-content-audit-v1"})
        self.assertEqual({item["evidence_scope"] for item in issues}, {"sampled_content", "full_metadata_scan"})


if __name__ == "__main__":
    unittest.main()

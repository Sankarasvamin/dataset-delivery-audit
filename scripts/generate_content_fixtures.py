#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import os
import shutil
from collections import Counter
from pathlib import Path
from typing import Any

SEED = 20260822

# Independent expected locators. The generator never calls the auditor to derive truth.
EXPECTED = [
    ("ISS-05", "content_empty_body", "ERROR", "alpha", "alpha/records.jsonl", "content-empty", 1, "clean_text", None, "sampled_content"),
    ("ISS-05", "content_field_misalignment", "ERROR", "alpha", "alpha/records.jsonl", "content-misaligned", 4, "event_date", None, "sampled_content"),
    ("ISS-05", "content_noninformative_body", "ERROR", "alpha", "alpha/records.jsonl", "content-symbol", 7, "clean_text", None, "sampled_content"),
    ("ISS-05", "content_noninformative_body", "ERROR", "alpha", "alpha/records.jsonl", "content-template", 8, "clean_text", None, "sampled_content"),
    ("ISS-05", "content_repeated_fragment", "WARNING", "alpha", "alpha/records.jsonl", "content-repeat", 5, "clean_text", None, "sampled_content"),
    ("ISS-05", "content_suspected_truncation", "WARNING", "alpha", "alpha/records.jsonl", "content-marker", 2, "clean_text", None, "sampled_content"),
    ("ISS-05", "content_suspected_truncation", "WARNING", "alpha", "alpha/records.jsonl", "content-metadata-trunc", 3, "clean_text", None, "sampled_content"),
    ("ISS-05", "content_suspected_truncation", "WARNING", "alpha", "alpha/records.jsonl", "content-misaligned", 4, "clean_text", None, "sampled_content"),
    ("ISS-05", "content_suspected_truncation", "WARNING", "alpha", "alpha/records.jsonl", "content-short", 6, "clean_text", None, "sampled_content"),
    ("ISS-05", "content_suspected_truncation", "WARNING", "alpha", "alpha/records.jsonl", "resource-attachment", 21, "clean_text", None, "sampled_content"),
    ("ISS-05", "content_suspected_truncation", "WARNING", "beta", "beta/records.jsonl", "source-version-a", 12, "clean_text", None, "sampled_content"),
    ("ISS-05", "content_suspected_truncation", "WARNING", "beta", "beta/records.jsonl", "source-version-b", 13, "clean_text", None, "sampled_content"),
    ("ISS-05", "content_suspected_truncation", "WARNING", "gamma", "gamma/records.tsv", "canonical-fuzzy-selected", 3, "clean_text", None, "sampled_content"),
    ("ISS-05", "content_template_noise", "WARNING", "alpha", "alpha/records.jsonl", "content-template", 8, "clean_text", None, "sampled_content"),
    ("ISS-06", "canonical_group_multiple_members_delivered", "ERROR", "gamma", "gamma/records.tsv", "canonical-fuzzy-nonselected", 2, None, None, "full_metadata_scan"),
    ("ISS-06", "canonical_nonselected_member_delivered", "ERROR", "gamma", "gamma/records.tsv", "canonical-fuzzy-nonselected", 2, None, None, "full_metadata_scan"),
    ("ISS-06", "duplicate_across_datasets", "ERROR", "alpha", "alpha/records.jsonl", "duplicate-cross-a", 9, None, None, "full_metadata_scan"),
    ("ISS-06", "duplicate_within_dataset", "ERROR", "alpha", "alpha/records.jsonl", "duplicate-within-a", 10, None, None, "full_metadata_scan"),
    ("ISS-06", "record_exact_duplicate", "ERROR", "alpha", "alpha/records.jsonl", "duplicate-cross-a", 9, None, None, "full_metadata_scan"),
    ("ISS-06", "record_exact_duplicate", "ERROR", "alpha", "alpha/records.jsonl", "duplicate-within-a", 10, None, None, "full_metadata_scan"),
    ("ISS-06", "record_near_duplicate_evidence", "WARNING", "gamma", "gamma/records.tsv", "canonical-fuzzy-nonselected", 2, None, None, "full_metadata_scan"),
    ("ISS-06", "source_identity_multiple_versions", "ERROR", "beta", "beta/records.jsonl", "source-version-a", 12, None, None, "full_metadata_scan"),
    ("ISS-06", "source_identity_multiple_versions", "ERROR", "gamma", "gamma/records.tsv", "date-source-a", 7, None, None, "full_metadata_scan"),
    ("ISS-06", "version_content_conflict", "ERROR", "beta", "beta/records.jsonl", "source-version-a", 12, None, None, "full_metadata_scan"),
    ("ISS-06", "version_content_conflict", "ERROR", "gamma", "gamma/records.tsv", "date-source-a", 7, None, None, "full_metadata_scan"),
    ("ISS-07", "dataset_time_window_empty", "WARNING", "alpha", "alpha/records.jsonl", "content-empty", 1, None, None, "full_metadata_scan"),
    ("ISS-07", "date_conflict_with_partition", "ERROR", "gamma", "gamma/records.tsv", "date-partition", 6, "event_date", None, "full_metadata_scan"),
    ("ISS-07", "event_date_future_as_of", "ERROR", "gamma", "gamma/records.tsv", "date-future", 4, "event_date", None, "full_metadata_scan"),
    ("ISS-07", "event_date_invalid", "ERROR", "alpha", "alpha/records.jsonl", "content-misaligned", 4, "event_date", None, "full_metadata_scan"),
    ("ISS-07", "event_date_invalid", "ERROR", "beta", "beta/records.jsonl", "date-invalid", 1, "event_date", None, "full_metadata_scan"),
    ("ISS-07", "event_date_missing", "WARNING", "beta", "beta/records.jsonl", "date-missing-1", 2, "event_date", None, "full_metadata_scan"),
    ("ISS-07", "event_date_missing", "WARNING", "gamma", "gamma/records.tsv", "date-missing-2", 5, "event_date", None, "full_metadata_scan"),
    ("ISS-07", "event_date_outside_expected_range", "ERROR", "beta", "beta/records.jsonl", "date-outside", 3, "event_date", None, "full_metadata_scan"),
    ("ISS-07", "event_date_outside_expected_range", "ERROR", "gamma", "gamma/records.tsv", "date-future", 4, "event_date", None, "full_metadata_scan"),
    ("ISS-07", "source_identity_date_conflict", "ERROR", "gamma", "gamma/records.tsv", "date-source-a", 7, None, None, "full_metadata_scan"),
    ("ISS-08", "empty_referenced_resource", "ERROR", "alpha", "alpha/records.jsonl", "resource-empty", 22, None, "resources/empty.bin", "sampled_content"),
    ("ISS-08", "external_url_dependency", "WARNING", "alpha", "alpha/records.jsonl", "resource-http", 23, None, "https://example.invalid/a.png", "sampled_content"),
    ("ISS-08", "external_url_dependency", "WARNING", "alpha", "alpha/records.jsonl", "resource-http-2", 24, None, "http://example.invalid/a.js", "sampled_content"),
    ("ISS-08", "missing_attachment", "ERROR", "alpha", "alpha/records.jsonl", "resource-attachment", 21, None, "resources/missing-attachment.bin", "sampled_content"),
    ("ISS-08", "missing_relative_resource", "ERROR", "alpha", "alpha/records.jsonl", "resource-missing", 25, None, "resources/missing.png", "sampled_content"),
    ("ISS-08", "resource_reference_unresolved", "WARNING", "alpha", "alpha/records.jsonl", "resource-unresolved", 27, None, "attachment://unknown", "sampled_content"),
    ("ISS-08", "unsafe_resource_path", "ERROR", "alpha", "alpha/records.jsonl", "resource-unsafe", 28, None, "../escape.png", "sampled_content"),
    ("ISS-08", "unsupported_resource_scheme", "ERROR", "alpha", "alpha/records.jsonl", "resource-scheme", 26, None, "javascript:alert(1", "sampled_content"),
    ("ISS-09", "canonical_evidence_missing", "ERROR", "gamma", "gamma/records.tsv", "canonical-fuzzy-nonselected", 2, None, None, "full_metadata_scan"),
    ("ISS-09", "canonical_evidence_missing", "ERROR", "gamma", "gamma/records.tsv", "prov-canonical-missing", 13, None, None, "full_metadata_scan"),
    ("ISS-09", "evidence_fingerprint_mismatch", "ERROR", "beta", "beta/records.jsonl", "prov-fingerprint-mismatch", 9, "input_record_fingerprint", None, "full_metadata_scan"),
    ("ISS-09", "evidence_record_orphan", "ERROR", "alpha", "canonical-decisions.jsonl", "canonical-orphan", None, None, None, "full_metadata_scan"),
    ("ISS-09", "evidence_record_orphan", "ERROR", "beta", "quality-scores.jsonl", "quality-orphan", None, None, None, "full_metadata_scan"),
    ("ISS-09", "provenance_dataset_mismatch", "ERROR", "beta", "alpha/records.jsonl", "prov-dataset-mismatch", 16, "dataset_id", None, "full_metadata_scan"),
    ("ISS-09", "provenance_missing_field", "ERROR", "alpha", "alpha/records.jsonl", "prov-missing-field", 17, "metadata.source_batch", None, "full_metadata_scan"),
    ("ISS-09", "provenance_missing_field", "ERROR", "beta", "beta/records.jsonl", "prov-version-missing", 11, "parser_version", None, "full_metadata_scan"),
    ("ISS-09", "provenance_processing_version_missing", "ERROR", "beta", "beta/records.jsonl", "prov-version-missing", 11, "parser_version/schema_version", None, "full_metadata_scan"),
    ("ISS-09", "provenance_source_file_missing", "ERROR", "alpha", "alpha/records.jsonl", "prov-source-missing", 20, "source_file", "sources/not-delivered.txt", "full_metadata_scan"),
    ("ISS-09", "provenance_source_offset_invalid", "ERROR", "alpha", "alpha/records.jsonl", "prov-offset-invalid", 18, "source_offset", None, "full_metadata_scan"),
    ("ISS-09", "provenance_source_offset_out_of_range", "ERROR", "beta", "beta/records.jsonl", "prov-offset-range", 10, "source_offset", None, "full_metadata_scan"),
    ("ISS-09", "provenance_version_unsupported", "ERROR", "beta", "beta/records.jsonl", "source-version-b", 13, "parser_version/schema_version", None, "full_metadata_scan"),
    ("ISS-09", "provenance_version_unsupported", "ERROR", "gamma", "gamma/records.tsv", "prov-version-unsupported", 14, "parser_version/schema_version", None, "full_metadata_scan"),
    ("ISS-09", "quality_evidence_missing", "ERROR", "alpha", "alpha/records.jsonl", "prov-quality-missing", 19, None, None, "full_metadata_scan"),
]


def canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def fp(value: Any) -> str:
    data = value if isinstance(value, bytes) else canonical(value)
    return "sha256:" + hashlib.sha256(data).hexdigest()


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_json(path: Path, value: Any) -> None:
    write(path, canonical(value) + b"\n")


def write_jsonl(path: Path, values: list[dict[str, Any]]) -> None:
    write(path, b"".join(canonical(value) + b"\n" for value in values))


def record(record_id: str, dataset: str, offset: int, month: int, record_type: str = "article", **changes: Any) -> dict[str, Any]:
    text = f"{dataset} 数据集的合成记录 {record_id} 提供足够且独立的文本分析信息。"
    value = {
        "record_id": record_id, "dataset_id": dataset, "source_file": f"sources/{dataset}.txt",
        "source_offset": offset, "record_type": record_type, "event_date": f"2026-{month:02d}-15",
        "title": f"合成标题 {record_id}", "raw_text": text, "clean_text": text,
        "metadata": {"source_batch": "synthetic-batch-v1", "source_format": "jsonl", "category_signal": f"category-{dataset}", "partition_date": f"2026-{month:02d}-15"},
        "parser_version": "parser-v1", "schema_version": "record-v1",
    }
    value.update(changes)
    return value


def decision(records: list[dict[str, Any]], group_type: str = "singleton", selected: str | None = None) -> dict[str, Any]:
    members = sorted(item["record_id"] for item in records)
    selected = selected or members[0]
    digest = hashlib.sha256(("group|" + "|".join(members)).encode()).hexdigest()
    candidates = []
    for item in sorted(records, key=lambda value: value["record_id"]):
        body = item.get("clean_text") or ""
        informative = sum(char.isalnum() for char in body)
        scores = {"body_length_bps": 10000, "informative_ratio_bps": 10000, "title_presence_bps": 10000, "date_presence_bps": 10000, "record_type_bps": 10000}
        candidates.append({
            "record_id": item["record_id"], "eligible": True, "hard_failure_reasons": [], "component_scores": scores,
            "weighted_total_score_bps": 10000, "informative_character_count": informative, "dedup_text_length": len(body),
            "tie_break_key": {"eligible_rank": 1, "weighted_total_score_bps": 10000, "informative_character_count": informative, "dedup_text_length": len(body), "title_presence_rank": 1, "date_presence_rank": 1, "record_type_bps": 10000, "record_id_ascending": item["record_id"]},
            "selected": item["record_id"] == selected,
        })
    fuzzy = ["fuzzy-pair:" + hashlib.sha256(("fuzzy|" + digest).encode()).hexdigest()] if group_type == "exact_fuzzy" else []
    return {
        "decision_id": "canonical-decision:" + hashlib.sha256(("decision|" + digest).encode()).hexdigest(),
        "group_id": "star-group:" + digest, "group_type": group_type, "source_star_cluster_id": None,
        "structural_representative_id": members[0], "selected_canonical_id": selected,
        "scope": {"dataset_id": records[0]["dataset_id"]}, "member_ids": members, "candidates": candidates,
        "selection_tie_break_level": "singleton" if len(members) == 1 else "record_id", "all_ineligible_fallback": False,
        "evidence": {"exact_pair_evidence_ids": [], "fuzzy_pair_evidence_ids": fuzzy, "direct_center_evidence": []},
        "canonical_config_fingerprint": fp({"fixture": "content-v1"}), "algorithm_version": "canonical-selection-v1", "schema_version": "canonical-decision-v1",
    }


def quality(record_value: dict[str, Any], decision_value: dict[str, Any]) -> dict[str, Any]:
    dimension = {"score_bps": 10000, "reasons": [], "evidence": {"synthetic": True}}
    return {
        "record_id": record_value["record_id"], "dataset_id": record_value["dataset_id"],
        "category": record_value.get("metadata", {}).get("category_signal", "synthetic"), "record_type": record_value["record_type"],
        "canonical_group_id": decision_value["group_id"],
        "dimensions": {name: dict(dimension) for name in ("completeness", "cleanliness", "uniqueness", "consistency", "readability", "traceability", "temporal_coverage", "resource_independence")},
        "weighted_score_bps": 10000, "hard_failures": [], "score_based_label": "ACCEPT", "final_label": "ACCEPT",
        "config_version": "quality-scoring-config-v1", "algorithm_version": "quality-scoring-v1", "schema_version": "quality-score-v1",
        "input_record_fingerprint": fp(record_value), "canonical_decision_fingerprint": fp(decision_value),
    }


def tsv_bytes(values: list[dict[str, Any]]) -> bytes:
    output = io.StringIO(newline="")
    fields = ["record_id", "dataset_id", "source_file", "source_offset", "record_type", "event_date", "title", "raw_text", "clean_text", "metadata", "parser_version", "schema_version"]
    writer = csv.DictWriter(output, fields, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    for value in values:
        row = dict(value)
        row["metadata"] = json.dumps(row["metadata"], ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        for field in ("event_date", "title", "clean_text"):
            if row[field] is None:
                row[field] = "__NULL__"
        writer.writerow(row)
    return output.getvalue().encode()


def source_bytes(dataset: str) -> bytes:
    return "".join(f"{dataset} synthetic source line {index:03d}\n" for index in range(220)).encode()


def write_delivery(root: Path, records: list[dict[str, Any]], reverse: bool) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = {dataset: [] for dataset in ("alpha", "beta", "gamma")}
    expected_dataset: dict[str, str] = {}
    for value in records:
        file_dataset = value.pop("__file_dataset", value["dataset_id"])
        grouped[file_dataset].append(value)
        expected_dataset[value["record_id"]] = file_dataset
    files = [
        ("alpha/records.jsonl", b"".join(canonical(value) + b"\n" for value in sorted(grouped["alpha"], key=lambda item: item["record_id"]))),
        ("beta/records.jsonl", b"".join(canonical(value) + b"\n" for value in sorted(grouped["beta"], key=lambda item: item["record_id"]))),
        ("gamma/records.tsv", tsv_bytes(sorted(grouped["gamma"], key=lambda item: item["record_id"]))),
        ("sources/alpha.txt", source_bytes("alpha")), ("sources/beta.txt", source_bytes("beta")), ("sources/gamma.txt", source_bytes("gamma")),
        ("resources/ok.txt", b"synthetic local resource\n"), ("resources/empty.bin", b""),
    ]
    for relative, data in reversed(files) if reverse else files:
        write(root / relative, data)
    entries = []
    for dataset, relative, fmt in (("alpha", "alpha/records.jsonl", "jsonl"), ("beta", "beta/records.jsonl", "jsonl"), ("gamma", "gamma/records.tsv", "tsv")):
        entries.append({"dataset_id": dataset, "path": relative, "expected_format": fmt, "expected_encoding": "utf8", "expected_schema_version": "record-v1", "expected_record_count": len(grouped[dataset]), "required": True})
    for dataset in ("alpha", "beta", "gamma"):
        entries.append({"dataset_id": dataset, "path": f"sources/{dataset}.txt", "expected_format": "text", "expected_encoding": "utf8", "expected_schema_version": None, "required": True})
    for relative in ("resources/ok.txt", "resources/empty.bin"):
        entries.append({"dataset_id": "resources", "path": relative, "expected_format": "text", "expected_encoding": "utf8", "expected_schema_version": None, "required": False})
    return {"delivery_id": root.name.replace("-delivery", "-content-delivery"), "files": sorted(entries, key=lambda item: item["path"]), "contract_version": "delivery-expectation-v1"}


def valid_records() -> list[dict[str, Any]]:
    values = []
    offset = 0
    types = ("article", "comment", "reply", "article")
    for dataset in ("alpha", "beta", "gamma"):
        for month, record_type in zip(range(1, 5), types):
            values.append(record(f"valid-{dataset}-{month:02d}", dataset, offset, month, record_type))
            offset += 1
    return values


def problem_records() -> list[dict[str, Any]]:
    values = [dict(item) for item in valid_records()]
    for item in values:
        item["record_id"] = item["record_id"].replace("valid-", "problem-")
        item["title"] = item["title"].replace("valid-", "problem-")
        item["raw_text"] = item["raw_text"].replace("valid-", "problem-")
        item["clean_text"] = item["clean_text"].replace("valid-", "problem-")
    # Leave alpha/2026-04 empty while retaining other datasets' four declared windows.
    for item in values:
        if item["record_id"] == "problem-alpha-04":
            item["event_date"] = "2026-03-20"
            item["metadata"] = dict(item["metadata"], partition_date="2026-03-20")
    offsets = Counter({"alpha": 20, "beta": 20, "gamma": 20})
    def add(identifier: str, dataset: str = "alpha", month: int = 2, record_type: str = "article", **changes: Any) -> dict[str, Any]:
        offsets[dataset] += 1
        value = record(identifier, dataset, offsets[dataset], month, record_type, **changes)
        values.append(value)
        return value

    add("content-empty", clean_text=None, raw_text="", title=None)
    add("content-symbol", record_type="reply", clean_text="!!!???", raw_text="!!!???")
    add("content-template", record_type="reply", clean_text="[待补充]", raw_text="[待补充]")
    add("content-marker", clean_text="这是保守截断检测所需的足够长合成正文，[内容截断] 后续未知。")
    add("content-metadata-trunc", clean_text="这是由显式元数据声明截断的足够长合成正文。", metadata={"source_batch": "synthetic-batch-v1", "source_format": "jsonl", "category_signal": "category-alpha", "partition_date": "2026-02-15", "truncated": True})
    add("content-short", clean_text="八个汉字足够信息", raw_text="八个汉字足够信息")
    add("content-misaligned", event_date="这是一段明显放错日期字段的很长很长合成正文内容用于确定性验证", clean_text="2026-02-15", raw_text="2026-02-15")
    add("content-repeat", clean_text="前置合成说明足够长。重复片段ABCDEFGH重复片段ABCDEFGH。")

    add("resource-http", clean_text="正文依赖外部图片 <img src=\"https://example.invalid/a.png\"> 但不访问网络。")
    add("resource-missing", clean_text="正文引用本地图片 ![图](resources/missing.png) 供审计。")
    add("resource-unsafe", clean_text="正文引用不安全图片 ![图](../escape.png) 供审计。")
    add("resource-attachment", clean_text="正文声明一个合成附件供审计。", metadata={"source_batch": "synthetic-batch-v1", "source_format": "jsonl", "category_signal": "category-alpha", "partition_date": "2026-02-15", "attachments": ["resources/missing-attachment.bin"]})
    add("resource-scheme", clean_text="正文包含 [链接](javascript:alert(1)) 作为不允许 scheme。")
    add("resource-empty", clean_text="正文通过 HTML 引用空资源 <img src=\"resources/empty.bin\"> 供审计。")
    add("resource-unresolved", clean_text="正文引用 [附件](attachment://unknown) 但缺少解析上下文。")
    add("resource-http-2", clean_text="另一个外部依赖 <script src=\"http://example.invalid/a.js\"></script> 不访问网络。")

    within_a = add("duplicate-within-a", clean_text="同一数据集内完全相同的合成正文用于精确哈希。")
    within_b = add("duplicate-within-b", clean_text=within_a["clean_text"])
    cross_a = add("duplicate-cross-a", "alpha", clean_text="跨数据集完全相同的合成正文用于精确哈希。")
    cross_b = add("duplicate-cross-b", "beta", clean_text=cross_a["clean_text"])
    source_a = add("source-version-a", "beta", clean_text="同一来源的第一个合成版本。")
    source_b = add("source-version-b", "beta", clean_text="同一来源的第二个冲突版本。", parser_version="parser-v0")
    source_b["source_offset"] = source_a["source_offset"]
    fuzzy_a = add("canonical-fuzzy-selected", "gamma", clean_text="近似组中被选择的完整合成文本版本。")
    fuzzy_b = add("canonical-fuzzy-nonselected", "gamma", clean_text="近似组中未选择的完整合成文本版本，略有差异。")

    add("date-missing-1", "beta", event_date=None, metadata={"source_batch": "synthetic-batch-v1", "source_format": "jsonl", "category_signal": "category-beta"})
    add("date-missing-2", "gamma", event_date=None, metadata={"source_batch": "synthetic-batch-v1", "source_format": "jsonl", "category_signal": "category-gamma"})
    add("date-invalid", "beta", event_date="2026-99-99", metadata={"source_batch": "synthetic-batch-v1", "source_format": "jsonl", "category_signal": "category-beta", "partition_date": "2026-02-15"})
    add("date-outside", "beta", event_date="2025-12-31", metadata={"source_batch": "synthetic-batch-v1", "source_format": "jsonl", "category_signal": "category-beta", "partition_date": "2025-12-31"})
    add("date-future", "gamma", event_date="2027-01-01", metadata={"source_batch": "synthetic-batch-v1", "source_format": "jsonl", "category_signal": "category-gamma", "partition_date": "2027-01-01"})
    add("date-partition", "gamma", event_date="2026-02-15", metadata={"source_batch": "synthetic-batch-v1", "source_format": "jsonl", "category_signal": "category-gamma", "partition_date": "2026-03-15"})
    date_source_a = add("date-source-a", "gamma", event_date="2026-02-10", metadata={"source_batch": "synthetic-batch-v1", "source_format": "jsonl", "category_signal": "category-gamma", "partition_date": "2026-02-10"})
    date_source_b = add("date-source-b", "gamma", event_date="2026-03-10", metadata={"source_batch": "synthetic-batch-v1", "source_format": "jsonl", "category_signal": "category-gamma", "partition_date": "2026-03-10"})
    date_source_b["source_offset"] = date_source_a["source_offset"]

    add("prov-missing-field", "alpha", metadata={"source_format": "jsonl", "category_signal": "category-alpha", "partition_date": "2026-02-15"})
    mismatch = add("prov-dataset-mismatch", "beta")
    mismatch["__file_dataset"] = "alpha"
    add("prov-source-missing", "alpha", source_file="sources/not-delivered.txt")
    add("prov-offset-invalid", "alpha", source_offset=-1)
    add("prov-offset-range", "beta", source_offset=99999)
    add("prov-version-missing", "beta", parser_version="")
    add("prov-version-unsupported", "gamma", parser_version="parser-v9")
    add("prov-canonical-missing", "gamma")
    add("prov-quality-missing", "alpha")
    add("prov-fingerprint-mismatch", "beta")
    return values


def evidence(values: list[dict[str, Any]], problem: bool) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    by_id = {value["record_id"]: value for value in values}
    grouped_ids = {"canonical-fuzzy-selected", "canonical-fuzzy-nonselected"} if problem else set()
    decisions: list[dict[str, Any]] = []
    decision_by_member: dict[str, dict[str, Any]] = {}
    for value in sorted(values, key=lambda item: item["record_id"]):
        if value["record_id"] in grouped_ids or (problem and value["record_id"] == "prov-canonical-missing"):
            continue
        current = decision([value])
        decisions.append(current)
        decision_by_member[value["record_id"]] = current
    if problem:
        fuzzy = decision([by_id["canonical-fuzzy-selected"], by_id["canonical-fuzzy-nonselected"]], "exact_fuzzy", "canonical-fuzzy-selected")
        decisions.append(fuzzy)
        decision_by_member["canonical-fuzzy-selected"] = fuzzy
        decision_by_member["canonical-fuzzy-nonselected"] = fuzzy
        orphan = record("canonical-orphan", "alpha", 1, 1)
        decisions.append(decision([orphan]))
    decisions.sort(key=lambda item: item["decision_id"])
    scores = []
    for value in sorted(values, key=lambda item: item["record_id"]):
        if problem and value["record_id"] == "prov-quality-missing":
            continue
        current_decision = decision_by_member.get(value["record_id"])
        if current_decision is None:
            current_decision = decision([value])
        score = quality(value, current_decision)
        if problem and value["record_id"] == "prov-fingerprint-mismatch":
            score["input_record_fingerprint"] = fp({"corrupted": True})
        scores.append(score)
    if problem:
        orphan = record("quality-orphan", "beta", 2, 2)
        orphan_decision = decision([orphan])
        scores.append(quality(orphan, orphan_decision))
    return decisions, sorted(scores, key=lambda item: item["record_id"])


def tree_fingerprint(root: Path, excluded: set[str] | None = None) -> str:
    excluded = excluded or set()
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if relative in excluded:
            continue
        data = b"F" + path.read_bytes() if path.is_file() else b"D"
        digest.update(relative.encode() + b"\0" + data + b"\0")
    return "sha256:" + digest.hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--seed", type=int, default=SEED)
    parser.add_argument("--reverse-creation", action="store_true")
    args = parser.parse_args()
    if args.seed != SEED:
        raise SystemExit("unsupported_seed")
    output = Path(args.output_dir)
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)
    valid = valid_records()
    problem = problem_records()
    valid_expectation = write_delivery(output / "valid-delivery", valid, args.reverse_creation)
    problem_expectation = write_delivery(output / "problem-delivery", problem, args.reverse_creation)
    valid_decisions, valid_scores = evidence(valid, False)
    problem_decisions, problem_scores = evidence(problem, True)
    write_json(output / "valid-expectation.json", valid_expectation)
    write_json(output / "problem-expectation.json", problem_expectation)
    write_jsonl(output / "valid-canonical-decisions.jsonl", valid_decisions)
    write_jsonl(output / "problem-canonical-decisions.jsonl", problem_decisions)
    write_jsonl(output / "valid-quality-scores.jsonl", valid_scores)
    write_jsonl(output / "problem-quality-scores.jsonl", problem_scores)
    write_json(output / "sampling-truth.json", {"seed": SEED, "valid_population_count": len(valid), "problem_population_count": len(problem), "schema_version": "content-sampling-truth-v1"})
    injections = []
    for index, (category, code, severity, dataset, relative, record_id, line, field, reference, scope) in enumerate(EXPECTED, 1):
        fixture = output / "problem-delivery" / relative
        fixture_fingerprint = fp(fixture.read_bytes()) if fixture.is_file() else fp(f"{relative}|{record_id}".encode())
        injections.append({
            "injection_id": f"content-inj-{index:03d}", "issue_category": category, "code": code,
            "expected_severity": severity, "delivery_id": "problem-content-delivery", "dataset_id": dataset,
            "path": relative, "record_id": record_id, "line": line, "field": field, "reference": reference,
            "expected_evidence_scope": scope, "fixture_fingerprint": fixture_fingerprint,
        })
    write_json(output / "injection-truth.json", {"seed": SEED, "injection_count": len(injections), "injections": injections, "schema_version": "content-injection-truth-v1"})
    content_fp = tree_fingerprint(output, {"generation-manifest.json"})
    manifest = {
        "generator_version": "delivery-content-fixture-generator-v1", "seed": SEED,
        "deliveries": {"valid": {"dataset_count": 3, "record_count": len(valid)}, "problem": {"dataset_count": 3, "record_count": len(problem)}},
        "formats": ["html", "jsonl", "markdown", "tsv"], "injection_count": len(injections), "fixture_fingerprint": content_fp,
        "schema_version": "content-generation-manifest-v1",
    }
    write_json(output / "generation-manifest.json", manifest)


if __name__ == "__main__":
    main()

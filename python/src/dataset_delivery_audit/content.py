from __future__ import annotations

import csv
import hashlib
import json
import re
import unicodedata
from collections import Counter, defaultdict
from datetime import date
from html.parser import HTMLParser
from pathlib import Path, PurePosixPath
from typing import Any, Iterable
from urllib.parse import urlparse

from .core import (
    AuditError,
    _safe_output,
    _safe_relative,
    canonical_bytes,
    file_sha256,
    fingerprint,
    load_expectation,
    write_json,
    write_jsonl,
)

CONTENT_VERSION = "delivery-content-audit-v1"
ISSUE_SCHEMA = "issue-v2"
SAMPLED = "sampled_content"
FULL_METADATA = "full_metadata_scan"

CONTENT_CODES = {
    "ISS-05": {
        "content_empty_body", "content_noninformative_body", "content_template_noise",
        "content_suspected_truncation", "content_field_misalignment", "content_repeated_fragment",
    },
    "ISS-06": {
        "record_exact_duplicate", "duplicate_within_dataset", "duplicate_across_datasets",
        "source_identity_multiple_versions", "version_content_conflict",
        "canonical_group_multiple_members_delivered", "canonical_nonselected_member_delivered",
        "record_near_duplicate_evidence",
    },
    "ISS-07": {
        "event_date_missing", "event_date_invalid", "event_date_outside_expected_range",
        "event_date_future_as_of", "dataset_time_window_empty", "date_conflict_with_partition",
        "source_identity_date_conflict",
    },
    "ISS-08": {
        "external_url_dependency", "missing_relative_resource", "unsafe_resource_path",
        "missing_attachment", "unsupported_resource_scheme", "empty_referenced_resource",
        "resource_reference_unresolved",
    },
    "ISS-09": {
        "provenance_missing_field", "provenance_dataset_mismatch", "provenance_source_file_missing",
        "provenance_source_offset_invalid", "provenance_source_offset_out_of_range",
        "provenance_processing_version_missing", "provenance_version_unsupported",
        "canonical_evidence_missing", "quality_evidence_missing", "evidence_record_orphan",
        "evidence_fingerprint_mismatch",
    },
}

HINTS = {
    "ISS-05": "复核样本正文和字段映射；本仓库不自动清洗或删除。",
    "ISS-06": "核对交付版本与上游 canonical 证据；本仓库不重算近似度。",
    "ISS-07": "核对固定日期窗口、分区和来源日期；不从当前时间推断。",
    "ISS-08": "复核依赖并补齐安全的本地资源；本仓库不访问网络。",
    "ISS-09": "补齐并核对来源、canonical 和质量证据；不修改上游产物。",
}


def _read_json(path: str | Path) -> Any:
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuditError(f"invalid_json:{Path(path).name}:{exc}") from exc


def _strict(value: Any, keys: set[str], name: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise AuditError(f"invalid_{name}_fields")
    return value


def load_content_config(path: str | Path) -> dict[str, Any]:
    keys = {
        "algorithm_version", "allowed_parser_versions", "allowed_record_schema_versions",
        "as_of_date", "content_rules", "date_ranges", "expected_windows",
        "require_source_files", "schema_version",
    }
    config = _strict(_read_json(path), keys, "content_config")
    if config["algorithm_version"] != CONTENT_VERSION or config["schema_version"] != "content-audit-config-v1":
        raise AuditError("unsupported_content_config_version")
    for key in ("allowed_parser_versions", "allowed_record_schema_versions"):
        values = config[key]
        if not isinstance(values, list) or not values or len(values) != len(set(values)) or any(not isinstance(v, str) or not v for v in values):
            raise AuditError(f"invalid_{key}")
    try:
        date.fromisoformat(config["as_of_date"])
    except (TypeError, ValueError) as exc:
        raise AuditError("invalid_as_of_date") from exc
    if not isinstance(config["require_source_files"], bool):
        raise AuditError("invalid_require_source_files")
    rules = config["content_rules"]
    required_rules = {
        "informative_character_minimum", "repeated_character_run", "repeated_fragment_minimum_length",
        "template_literals", "template_regexes", "template_ratio_threshold_bps", "truncation_markers", "minimum_body_length",
    }
    _strict(rules, required_rules, "content_rules")
    for key in ("informative_character_minimum", "repeated_character_run", "repeated_fragment_minimum_length"):
        if type(rules[key]) is not int or rules[key] <= 0:
            raise AuditError(f"invalid_{key}")
    if type(rules["template_ratio_threshold_bps"]) is not int or not 0 <= rules["template_ratio_threshold_bps"] <= 10000:
        raise AuditError("invalid_template_ratio_threshold_bps")
    for key in ("template_literals", "truncation_markers"):
        if not isinstance(rules[key], list) or len(rules[key]) != len(set(rules[key])) or any(not isinstance(v, str) or not v for v in rules[key]):
            raise AuditError(f"invalid_{key}")
    if not isinstance(rules["template_regexes"], list) or len(rules["template_regexes"]) != len(set(rules["template_regexes"])):
        raise AuditError("invalid_template_regexes")
    try:
        for pattern in rules["template_regexes"]:
            if not isinstance(pattern, str) or not pattern:
                raise re.error
            re.compile(pattern)
    except re.error as exc:
        raise AuditError("invalid_template_regexes") from exc
    if set(rules["minimum_body_length"]) != {"article", "comment", "reply"} or any(type(v) is not int or v < 0 for v in rules["minimum_body_length"].values()):
        raise AuditError("invalid_minimum_body_length")
    if not isinstance(config["date_ranges"], dict) or not isinstance(config["expected_windows"], dict):
        raise AuditError("invalid_date_configuration")
    for dataset, bounds in config["date_ranges"].items():
        try:
            if not isinstance(dataset, str) or len(bounds) != 2 or date.fromisoformat(bounds[0]) > date.fromisoformat(bounds[1]):
                raise ValueError
        except (TypeError, ValueError) as exc:
            raise AuditError("invalid_date_range") from exc
    for windows in config["expected_windows"].values():
        if not isinstance(windows, list) or len(windows) != len(set(windows)) or any(not re.fullmatch(r"\d{4}-\d{2}", v) for v in windows):
            raise AuditError("invalid_expected_windows")
    return config


def load_sample_plan(path: str | Path) -> dict[str, Any]:
    keys = {
        "plan_id", "seed", "target_size", "strata_keys", "allocation_method",
        "minimum_per_stratum", "filters", "algorithm_version", "schema_version",
    }
    plan = _strict(_read_json(path), keys, "sample_plan")
    if plan["schema_version"] != "sample-plan-v1" or plan["allocation_method"] != "minimum_then_proportional":
        raise AuditError("unsupported_sample_plan")
    if plan["strata_keys"] != ["dataset_id", "record_type", "event_month"] or plan["filters"] != {}:
        raise AuditError("unsupported_sample_plan_shape")
    for key in ("seed", "target_size", "minimum_per_stratum"):
        minimum = 0 if key != "target_size" else 1
        if type(plan[key]) is not int or plan[key] < minimum:
            raise AuditError(f"invalid_sample_plan_{key}")
    return plan


def _load_jsonl(path: str | Path, id_field: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    with Path(path).open(encoding="utf-8") as handle:
        for line, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                value = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise AuditError(f"invalid_jsonl:{Path(path).name}:{line}") from exc
            identifier = value.get(id_field) if isinstance(value, dict) else None
            if not isinstance(identifier, str) or not identifier:
                raise AuditError(f"missing_evidence_id:{Path(path).name}:{line}")
            if identifier in seen:
                raise AuditError(f"duplicate_evidence_id:{identifier}")
            seen.add(identifier)
            result.append(value)
    return result


def _decode_tsv(value: str, field: str) -> Any:
    if field in {"source_offset"}:
        try:
            return int(value)
        except ValueError:
            return value
    if field == "metadata":
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    if field in {"event_date", "title", "clean_text"} and value == "__NULL__":
        return None
    return value


def load_records(root: str | Path, expectation: dict[str, Any]) -> list[dict[str, Any]]:
    root = Path(root)
    records: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in expectation["files"]:
        if item.get("expected_schema_version") != "record-v1":
            continue
        path = root / item["path"]
        if not path.is_file():
            raise AuditError(f"record_file_missing:{item['path']}")
        parsed: Iterable[tuple[int, Any]]
        if item["expected_format"] == "jsonl":
            def json_rows() -> Iterable[tuple[int, Any]]:
                with path.open(encoding="utf-8") as handle:
                    for number, raw in enumerate(handle, 1):
                        if raw.strip():
                            try:
                                yield number, json.loads(raw)
                            except json.JSONDecodeError as exc:
                                raise AuditError(f"invalid_record_jsonl:{item['path']}:{number}") from exc
            parsed = json_rows()
        elif item["expected_format"] == "tsv":
            def tsv_rows() -> Iterable[tuple[int, Any]]:
                with path.open(encoding="utf-8", newline="") as handle:
                    rows = csv.DictReader(handle, delimiter="\t")
                    if rows.fieldnames is None or len(rows.fieldnames) != len(set(rows.fieldnames)):
                        raise AuditError(f"invalid_record_tsv_header:{item['path']}")
                    for number, row in enumerate(rows, 2):
                        yield number, {key: _decode_tsv(value, key) for key, value in row.items()}
            parsed = tsv_rows()
        else:
            raise AuditError(f"unsupported_record_format:{item['expected_format']}")
        for line, record in parsed:
            if not isinstance(record, dict):
                raise AuditError(f"record_not_object:{item['path']}:{line}")
            record_id = record.get("record_id")
            if not isinstance(record_id, str) or not record_id:
                raise AuditError(f"missing_record_id:{item['path']}:{line}")
            if record_id in seen:
                raise AuditError(f"duplicate_record_id:{record_id}")
            seen.add(record_id)
            records.append({"record": record, "path": item["path"], "line": line, "expected_dataset_id": item["dataset_id"]})
    if not records:
        raise AuditError("no_record_files")
    return sorted(records, key=lambda row: row["record"]["record_id"])


def _event_month(record: dict[str, Any]) -> str:
    if "event_date" not in record:
        return "__MISSING__"
    value = record["event_date"]
    if value is None:
        return "__NULL__"
    if not isinstance(value, str):
        return "__INVALID__"
    try:
        return date.fromisoformat(value).strftime("%Y-%m")
    except ValueError:
        return "__INVALID__"


def _stratum(row: dict[str, Any]) -> tuple[str, str, str]:
    record = row["record"]
    dataset = record.get("dataset_id", "__MISSING__")
    record_type = record.get("record_type", "__MISSING__")
    return str(dataset), str(record_type), _event_month(record)


def _stratum_id(key: tuple[str, str, str]) -> str:
    return "stratum:" + hashlib.sha256("\x1f".join(key).encode()).hexdigest()


def select_sample(records: list[dict[str, Any]], plan: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    # ponytail: 内存分层索引适合中小型交付；超大交付再换外部排序或 SQLite。
    strata: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in records:
        strata[_stratum(row)].append(row)
    target = min(plan["target_size"], len(records))
    minimums = {key: min(plan["minimum_per_stratum"], len(rows)) for key, rows in strata.items()}
    if sum(minimums.values()) > target:
        raise AuditError("sample_target_below_stratum_minimums")
    quotas = dict(minimums)
    remaining = target - sum(quotas.values())
    capacities = {key: len(strata[key]) - quotas[key] for key in strata}
    while remaining:
        total = sum(capacities.values())
        if total == 0:
            break
        grants = {key: remaining * capacities[key] // total for key in strata}
        used = sum(grants.values())
        for key, value in grants.items():
            take = min(value, capacities[key])
            quotas[key] += take
            capacities[key] -= take
        remaining -= used
        if remaining:
            order = sorted(strata, key=lambda key: (-(remaining * capacities[key] % max(sum(capacities.values()), 1)), key))
            progressed = False
            for key in order:
                if remaining == 0:
                    break
                if capacities[key]:
                    quotas[key] += 1
                    capacities[key] -= 1
                    remaining -= 1
                    progressed = True
            if not progressed:
                break
    selected: list[dict[str, Any]] = []
    manifest_strata: list[dict[str, Any]] = []
    for key in sorted(strata):
        ranked = []
        for row in strata[key]:
            record_id = row["record"]["record_id"]
            selection_key = hashlib.sha256(f"{plan['seed']}|{key[0]}|{key[1]}|{key[2]}|{record_id}".encode()).hexdigest()
            ranked.append((selection_key, record_id, row))
        ranked.sort(key=lambda item: (item[0], item[1]))
        chosen = ranked[: quotas[key]]
        for selection_key, _, row in chosen:
            row["selection_key"] = selection_key
            row["stratum_id"] = _stratum_id(key)
            selected.append(row)
        manifest_strata.append({
            "dataset_id": key[0], "record_type": key[1], "event_month": key[2],
            "stratum_id": _stratum_id(key), "population_count": len(ranked), "sample_count": len(chosen),
            "selected": [{"record_id": record_id, "selection_key": selection_key} for selection_key, record_id, _ in chosen],
        })
    selected.sort(key=lambda row: row["record"]["record_id"])
    manifest = {
        "plan_id": plan["plan_id"], "seed": plan["seed"], "allocation_method": plan["allocation_method"],
        "population_count": len(records), "sample_count": len(selected), "stratum_count": len(strata),
        "strata": manifest_strata, "plan_fingerprint": fingerprint(plan),
        "population_fingerprint": fingerprint([row["record"] for row in sorted(records, key=lambda value: value["record"]["record_id"])]),
        "sample_fingerprint": fingerprint([row["record"]["record_id"] for row in selected]),
        "algorithm_version": plan["algorithm_version"], "schema_version": "sampling-manifest-v1",
    }
    return selected, manifest


def make_issue(category: str, code: str, severity: str, delivery: str, row: dict[str, Any] | None, *, dataset: str | None = None, path: str | None = None, record_id: str | None = None, line: int | None = None, field: str | None = None, member: str | None = None, reference: str | None = None, scope: str = FULL_METADATA, sample_plan_fingerprint: str | None = None, stratum_id: str | None = None, expected: dict[str, Any] | None = None, observed: dict[str, Any] | None = None) -> dict[str, Any]:
    if category not in CONTENT_CODES or code not in CONTENT_CODES[category]:
        raise AuditError(f"unknown_content_issue_code:{category}:{code}")
    if row:
        record = row["record"]
        dataset = str(record.get("dataset_id", "__MISSING__")) if dataset is None else dataset
        path = row["path"] if path is None else path
        record_id = record.get("record_id") if record_id is None else record_id
        line = row["line"] if line is None else line
        if scope == SAMPLED:
            stratum_id = row.get("stratum_id")
    evidence = {
        "category": category, "code": code, "delivery_id": delivery, "dataset_id": dataset,
        "path": path, "record_id": record_id, "line": line, "member": member, "field": field,
        "reference": reference, "evidence_scope": scope, "stratum_id": stratum_id,
        "sample_plan_fingerprint": sample_plan_fingerprint, "expected": expected, "observed": observed,
    }
    evidence_fp = fingerprint(evidence)
    return {
        "issue_id": "issue:" + hashlib.sha256((CONTENT_VERSION + "\x1f" + evidence_fp).encode()).hexdigest(),
        "issue_category": category, "code": code, "severity": severity,
        "delivery_id": delivery, "dataset_id": dataset, "path": path, "record_id": record_id,
        "line": line, "member": member, "field": field, "reference": reference,
        "evidence_scope": scope, "stratum_id": stratum_id,
        "sample_plan_fingerprint": sample_plan_fingerprint, "expected": expected, "observed": observed,
        "evidence_fingerprint": evidence_fp, "remediation_hint": HINTS[category],
        "algorithm_version": CONTENT_VERSION, "schema_version": ISSUE_SCHEMA,
    }


def _informative(text: str) -> int:
    return sum(unicodedata.category(char)[0] in {"L", "N"} or "\u3400" <= char <= "\u9fff" for char in text)


def _content_issues(row: dict[str, Any], config: dict[str, Any], delivery: str, plan_fp: str) -> list[dict[str, Any]]:
    record, rules = row["record"], config["content_rules"]
    body = record.get("clean_text")
    text = body if isinstance(body, str) else ""
    stripped = text.strip()
    result: list[dict[str, Any]] = []
    add = lambda code, severity, **kw: result.append(make_issue("ISS-05", code, severity, delivery, row, scope=SAMPLED, sample_plan_fingerprint=plan_fp, **kw))
    if not stripped:
        add("content_empty_body", "ERROR", field="clean_text", observed={"present": "clean_text" in record, "is_null": body is None, "character_count": len(text)})
    else:
        informative = _informative(stripped)
        if informative < rules["informative_character_minimum"]:
            add("content_noninformative_body", "ERROR", field="clean_text", expected={"informative_character_minimum": rules["informative_character_minimum"]}, observed={"informative_character_count": informative, "pure_symbol": informative == 0})
        found = sorted(literal for literal in rules["template_literals"] if literal in stripped)
        regex_matches = sorted({match.group(0) for pattern in rules["template_regexes"] for match in re.finditer(pattern, stripped)})
        template_chars = sum(stripped.count(literal) * len(literal) for literal in found) + sum(len(value) for value in regex_matches)
        ratio = (template_chars * 10000 + len(stripped) // 2) // len(stripped)
        if (found or regex_matches) and ratio >= rules["template_ratio_threshold_bps"]:
            add("content_template_noise", "WARNING", field="clean_text", expected={"maximum_template_ratio_bps": rules["template_ratio_threshold_bps"] - 1}, observed={"matched_literals": found, "matched_regex_values": regex_matches, "template_ratio_bps": ratio})
        reasons: list[str] = []
        markers = sorted(marker for marker in rules["truncation_markers"] if marker in stripped)
        if markers:
            reasons.append("explicit_marker")
        metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
        if metadata.get("truncated") is True:
            reasons.append("metadata_flag")
        minimum = rules["minimum_body_length"].get(record.get("record_type"), 0)
        if len(stripped) < minimum:
            reasons.append("below_declared_minimum")
        if reasons:
            add("content_suspected_truncation", "WARNING", field="clean_text", expected={"minimum_body_length": minimum}, observed={"character_count": len(stripped), "markers": markers, "reasons": reasons})
        event = record.get("event_date")
        if isinstance(event, str) and len(event) > 20 and re.fullmatch(r"\d{4}-\d{2}-\d{2}", stripped):
            add("content_field_misalignment", "ERROR", field="event_date", observed={"clean_text_looks_like_date": True, "event_date_character_count": len(event)})
        run = re.search(r"(.)\1{%d,}" % (rules["repeated_character_run"] - 1), stripped)
        fragment = re.search(r"(.{%d,}?)\1+" % rules["repeated_fragment_minimum_length"], stripped)
        if run or fragment:
            add("content_repeated_fragment", "WARNING", field="clean_text", observed={"repeated_character_run": len(run.group(0)) if run else 0, "adjacent_fragment_length": len(fragment.group(1)) if fragment else 0})
    return result


class _References(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.values: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for key, value in attrs:
            if value and key.lower() in {"src", "href"} and tag.lower() in {"img", "script", "link", "a", "source"}:
                self.values.append(value)


def _references(text: str) -> list[str]:
    parser = _References()
    try:
        parser.feed(text)
    except Exception:
        pass
    markdown = re.findall(r"!?\[[^\]]*\]\(([^)]+)\)", text)
    return sorted(set(value.strip() for value in parser.values + markdown if value.strip()))


def _resource_issues(row: dict[str, Any], root: Path, delivery: str, plan_fp: str) -> list[dict[str, Any]]:
    record = row["record"]
    text = "\n".join(value for value in (record.get("title"), record.get("clean_text"), record.get("raw_text")) if isinstance(value, str))
    references = _references(text)
    metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    attachments = metadata.get("attachments", [])
    if isinstance(attachments, list):
        references.extend(value for value in attachments if isinstance(value, str))
    result: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    def add(code: str, severity: str, reference: str, **kw: Any) -> None:
        key = code, reference
        if key not in seen:
            seen.add(key)
            result.append(make_issue("ISS-08", code, severity, delivery, row, reference=reference[:256], scope=SAMPLED, sample_plan_fingerprint=plan_fp, **kw))
    for reference in sorted(set(references)):
        parsed = urlparse(reference)
        if parsed.scheme in {"http", "https"}:
            add("external_url_dependency", "WARNING", reference, observed={"scheme": parsed.scheme, "network_checked": False})
            continue
        if parsed.scheme:
            code = "resource_reference_unresolved" if parsed.scheme == "attachment" else "unsupported_resource_scheme"
            add(code, "WARNING" if code.endswith("unresolved") else "ERROR", reference, observed={"scheme": parsed.scheme})
            continue
        normalized = reference.split("#", 1)[0].split("?", 1)[0]
        if not normalized:
            add("resource_reference_unresolved", "WARNING", reference, observed={"reason": "empty_local_target"})
            continue
        if not _safe_relative(normalized):
            add("unsafe_resource_path", "ERROR", reference, observed={"safe_relative": False})
            continue
        target = root / PurePosixPath(normalized)
        attachment = reference in attachments
        if not target.is_file():
            add("missing_attachment" if attachment else "missing_relative_resource", "ERROR", reference, observed={"present": False})
        elif target.stat().st_size == 0:
            add("empty_referenced_resource", "ERROR", reference, observed={"size_bytes": 0})
    return result


def _text_hash(record: dict[str, Any]) -> str:
    value = record.get("clean_text")
    return "sha256:" + hashlib.sha256((value if isinstance(value, str) else "").encode()).hexdigest()


def _source_identity(record: dict[str, Any]) -> tuple[Any, Any, Any]:
    return record.get("dataset_id"), record.get("source_file"), record.get("source_offset")


def _duplicate_issues(records: list[dict[str, Any]], decisions: list[dict[str, Any]], delivery: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    by_hash: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_source: dict[tuple[Any, Any, Any], list[dict[str, Any]]] = defaultdict(list)
    for row in records:
        by_hash[_text_hash(row["record"])].append(row)
        by_source[_source_identity(row["record"])].append(row)
    for text_hash, group in sorted(by_hash.items()):
        if len(group) < 2:
            continue
        group.sort(key=lambda row: row["record"]["record_id"])
        ids = [row["record"]["record_id"] for row in group]
        datasets = sorted({str(row["record"].get("dataset_id")) for row in group})
        observed = {"record_ids": ids, "clean_text_sha256": text_hash, "datasets": datasets}
        result.append(make_issue("ISS-06", "record_exact_duplicate", "ERROR", delivery, group[0], observed=observed))
        code = "duplicate_within_dataset" if len(datasets) == 1 else "duplicate_across_datasets"
        result.append(make_issue("ISS-06", code, "ERROR", delivery, group[0], observed=observed))
    for identity, group in sorted(by_source.items(), key=lambda item: repr(item[0])):
        variants = {(row["record"].get("parser_version"), row["record"].get("schema_version"), _text_hash(row["record"])) for row in group}
        if len(group) > 1 and len(variants) > 1:
            group.sort(key=lambda row: row["record"]["record_id"])
            observed = {"source_identity": list(identity), "record_ids": [row["record"]["record_id"] for row in group], "variant_count": len(variants)}
            result.append(make_issue("ISS-06", "source_identity_multiple_versions", "ERROR", delivery, group[0], observed=observed))
            if len({_text_hash(row["record"]) for row in group}) > 1:
                result.append(make_issue("ISS-06", "version_content_conflict", "ERROR", delivery, group[0], observed=observed))
    delivered = {row["record"]["record_id"]: row for row in records}
    for decision in sorted(decisions, key=lambda item: item["group_id"]):
        members = [record_id for record_id in decision.get("member_ids", []) if record_id in delivered]
        if len(members) > 1:
            first = delivered[sorted(members)[0]]
            result.append(make_issue("ISS-06", "canonical_group_multiple_members_delivered", "ERROR", delivery, first, observed={"group_id": decision["group_id"], "delivered_member_ids": sorted(members), "selected_canonical_id": decision.get("selected_canonical_id")}))
        for record_id in sorted(set(members) - {decision.get("selected_canonical_id")}):
            result.append(make_issue("ISS-06", "canonical_nonselected_member_delivered", "ERROR", delivery, delivered[record_id], observed={"group_id": decision["group_id"], "selected_canonical_id": decision.get("selected_canonical_id")}))
        if decision.get("group_type") == "exact_fuzzy" and members:
            fuzzy_ids = decision.get("evidence", {}).get("fuzzy_pair_evidence_ids", [])
            result.append(make_issue("ISS-06", "record_near_duplicate_evidence", "WARNING", delivery, delivered[sorted(members)[0]], observed={"group_id": decision["group_id"], "delivered_member_ids": sorted(members), "fuzzy_pair_evidence_ids": sorted(fuzzy_ids)}))
    return result


def _date_issues(records: list[dict[str, Any]], config: dict[str, Any], delivery: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    result: list[dict[str, Any]] = []
    parsed: dict[str, date] = {}
    coverage: Counter[tuple[str, str, str, str]] = Counter()
    as_of = date.fromisoformat(config["as_of_date"])
    for row in records:
        record, value = row["record"], row["record"].get("event_date")
        if value is None or "event_date" not in record:
            result.append(make_issue("ISS-07", "event_date_missing", "WARNING", delivery, row, field="event_date", observed={"present": "event_date" in record, "is_null": value is None}))
            month = _event_month(record)
        else:
            try:
                parsed_date = date.fromisoformat(value) if isinstance(value, str) else None
                if parsed_date is None:
                    raise ValueError
                parsed[record["record_id"]] = parsed_date
                month = parsed_date.strftime("%Y-%m")
                bounds = config["date_ranges"].get(record.get("dataset_id"))
                if bounds and not date.fromisoformat(bounds[0]) <= parsed_date <= date.fromisoformat(bounds[1]):
                    result.append(make_issue("ISS-07", "event_date_outside_expected_range", "ERROR", delivery, row, field="event_date", expected={"range": bounds}, observed={"value": value}))
                if parsed_date > as_of:
                    result.append(make_issue("ISS-07", "event_date_future_as_of", "ERROR", delivery, row, field="event_date", expected={"as_of_date": config["as_of_date"]}, observed={"value": value}))
                partition = record.get("metadata", {}).get("partition_date") if isinstance(record.get("metadata"), dict) else None
                if isinstance(partition, str) and partition != value:
                    result.append(make_issue("ISS-07", "date_conflict_with_partition", "ERROR", delivery, row, field="event_date", expected={"partition_date": partition}, observed={"event_date": value}))
            except (TypeError, ValueError):
                month = "__INVALID__"
                result.append(make_issue("ISS-07", "event_date_invalid", "ERROR", delivery, row, field="event_date", observed={"json_type": type(value).__name__, "value_length": len(value) if isinstance(value, str) else None}))
        metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
        coverage[(str(record.get("dataset_id", "__MISSING__")), str(metadata.get("category_signal", "__MISSING__")), str(record.get("record_type", "__MISSING__")), month)] += 1
    for dataset, windows in sorted(config["expected_windows"].items()):
        present = {key[3] for key in coverage if key[0] == dataset}
        anchor = next((row for row in records if row["record"].get("dataset_id") == dataset), None)
        for window in windows:
            if window not in present:
                path = anchor["path"] if anchor else f"datasets/{dataset}"
                result.append(make_issue("ISS-07", "dataset_time_window_empty", "WARNING", delivery, anchor, dataset=dataset, path=path, record_id=None, line=None, expected={"window": window}, observed={"record_count": 0}))
    sources: dict[tuple[Any, Any, Any], list[dict[str, Any]]] = defaultdict(list)
    for row in records:
        sources[_source_identity(row["record"])].append(row)
    for identity, group in sorted(sources.items(), key=lambda item: repr(item[0])):
        dated = sorted({row["record"].get("event_date") for row in group if row["record"].get("event_date") is not None})
        if len(dated) > 1:
            group.sort(key=lambda row: row["record"]["record_id"])
            result.append(make_issue("ISS-07", "source_identity_date_conflict", "ERROR", delivery, group[0], observed={"source_identity": list(identity), "record_ids": [row["record"]["record_id"] for row in group], "dates": dated}))
    coverage_rows = [{"dataset_id": key[0], "category": key[1], "record_type": key[2], "event_month": key[3], "record_count": count} for key, count in sorted(coverage.items())]
    return result, {"groups": coverage_rows, "group_count": len(coverage_rows)}


def _provenance_issues(records: list[dict[str, Any]], decisions: list[dict[str, Any]], scores: list[dict[str, Any]], root: Path, config: dict[str, Any], delivery: str) -> tuple[list[dict[str, Any]], dict[str, int]]:
    result: list[dict[str, Any]] = []
    delivered = {row["record"]["record_id"]: row for row in records}
    decision_by_member: dict[str, dict[str, Any]] = {}
    for decision in decisions:
        for record_id in decision.get("member_ids", []):
            if record_id in decision_by_member:
                raise AuditError(f"duplicate_canonical_member:{record_id}")
            decision_by_member[record_id] = decision
    score_by_record = {score["record_id"]: score for score in scores}
    for row in records:
        record = row["record"]
        metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
        required = {
            "dataset_id": record.get("dataset_id"), "metadata.source_batch": metadata.get("source_batch"),
            "source_file": record.get("source_file"), "metadata.source_format": metadata.get("source_format"),
            "source_offset": record.get("source_offset"), "parser_version": record.get("parser_version"),
            "schema_version": record.get("schema_version"),
        }
        for field, value in required.items():
            if value is None or value == "":
                result.append(make_issue("ISS-09", "provenance_missing_field", "ERROR", delivery, row, field=field, observed={"present": value is not None, "empty": value == ""}))
        if record.get("dataset_id") != row["expected_dataset_id"]:
            result.append(make_issue("ISS-09", "provenance_dataset_mismatch", "ERROR", delivery, row, field="dataset_id", expected={"dataset_id": row["expected_dataset_id"]}, observed={"dataset_id": record.get("dataset_id")}))
        source_file = record.get("source_file")
        source_path = root / source_file if isinstance(source_file, str) and _safe_relative(source_file) else None
        if config["require_source_files"] and (source_path is None or not source_path.is_file()):
            result.append(make_issue("ISS-09", "provenance_source_file_missing", "ERROR", delivery, row, field="source_file", reference=source_file if isinstance(source_file, str) else None, observed={"present": False}))
        offset = record.get("source_offset")
        if type(offset) is not int or offset < 0:
            result.append(make_issue("ISS-09", "provenance_source_offset_invalid", "ERROR", delivery, row, field="source_offset", observed={"json_type": type(offset).__name__, "value": offset if isinstance(offset, (str, int)) else None}))
        elif source_path and source_path.is_file():
            size = source_path.stat().st_size
            if offset >= size:
                result.append(make_issue("ISS-09", "provenance_source_offset_out_of_range", "ERROR", delivery, row, field="source_offset", expected={"maximum_exclusive_bytes": size}, observed={"value": offset}))
        if not record.get("parser_version") or not record.get("schema_version"):
            result.append(make_issue("ISS-09", "provenance_processing_version_missing", "ERROR", delivery, row, field="parser_version/schema_version", observed={"parser_version": record.get("parser_version"), "schema_version": record.get("schema_version")}))
        unsupported: dict[str, Any] = {}
        if record.get("parser_version") and record.get("parser_version") not in config["allowed_parser_versions"]:
            unsupported["parser_version"] = record.get("parser_version")
        if record.get("schema_version") and record.get("schema_version") not in config["allowed_record_schema_versions"]:
            unsupported["schema_version"] = record.get("schema_version")
        if unsupported:
            result.append(make_issue("ISS-09", "provenance_version_unsupported", "ERROR", delivery, row, field="parser_version/schema_version", expected={"parser_versions": config["allowed_parser_versions"], "schema_versions": config["allowed_record_schema_versions"]}, observed=unsupported))
        decision = decision_by_member.get(record["record_id"])
        if decision is None or decision.get("selected_canonical_id") != record["record_id"]:
            result.append(make_issue("ISS-09", "canonical_evidence_missing", "ERROR", delivery, row, expected={"selected_canonical_id": record["record_id"]}, observed={"decision_present": decision is not None, "selected_canonical_id": decision.get("selected_canonical_id") if decision else None}))
        score = score_by_record.get(record["record_id"])
        if score is None:
            result.append(make_issue("ISS-09", "quality_evidence_missing", "ERROR", delivery, row, observed={"present": False}))
        else:
            mismatches: list[str] = []
            if score.get("dataset_id") != record.get("dataset_id"):
                mismatches.append("dataset_id")
            if decision and score.get("canonical_group_id") != decision.get("group_id"):
                mismatches.append("canonical_group_id")
            if score.get("input_record_fingerprint") != fingerprint(record):
                mismatches.append("input_record_fingerprint")
            if decision and score.get("canonical_decision_fingerprint") != fingerprint(decision):
                mismatches.append("canonical_decision_fingerprint")
            if mismatches:
                result.append(make_issue("ISS-09", "evidence_fingerprint_mismatch", "ERROR", delivery, row, field="/".join(mismatches), observed={"mismatched_fields": mismatches}))
    for decision in decisions:
        selected = decision.get("selected_canonical_id")
        if selected not in delivered:
            result.append(make_issue("ISS-09", "evidence_record_orphan", "ERROR", delivery, None, dataset=str(decision.get("scope", {}).get("dataset_id", "__UNSPECIFIED__")), path="canonical-decisions.jsonl", record_id=selected, observed={"evidence_type": "canonical", "group_id": decision.get("group_id")}))
    for score in scores:
        if score["record_id"] not in delivered:
            result.append(make_issue("ISS-09", "evidence_record_orphan", "ERROR", delivery, None, dataset=str(score.get("dataset_id", "__UNSPECIFIED__")), path="quality-scores.jsonl", record_id=score["record_id"], observed={"evidence_type": "quality"}))
    counts = {
        "delivered_record_count": len(records), "canonical_decision_count": len(decisions),
        "quality_score_count": len(scores), "canonical_selected_matched_count": sum(decision.get("selected_canonical_id") in delivered for decision in decisions),
        "quality_record_matched_count": sum(score["record_id"] in delivered for score in scores),
    }
    return result, counts


def _issue_sort(item: dict[str, Any]) -> tuple[Any, ...]:
    return (item["issue_category"], item["code"], item["dataset_id"], item["path"], item["record_id"] or "", item["line"] or 0, item["field"] or "", item["reference"] or "", item["issue_id"])


def audit_content(root: str | Path, expectation_path: str | Path, config_path: str | Path, sample_plan_path: str | Path, canonical_path: str | Path, quality_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
    root, output_dir = Path(root), Path(output_dir)
    if not root.is_dir():
        raise AuditError("input_root_not_directory")
    _safe_output(root, output_dir)
    expectation = load_expectation(expectation_path)
    config = load_content_config(config_path)
    plan = load_sample_plan(sample_plan_path)
    records = load_records(root, expectation)
    decisions = _load_jsonl(canonical_path, "decision_id")
    scores = _load_jsonl(quality_path, "record_id")
    sample, sampling = select_sample(records, plan)
    plan_fp = sampling["plan_fingerprint"]
    delivery = expectation["delivery_id"]
    issues: list[dict[str, Any]] = []
    for row in sample:
        issues.extend(_content_issues(row, config, delivery, plan_fp))
        issues.extend(_resource_issues(row, root, delivery, plan_fp))
    issues.extend(_duplicate_issues(records, decisions, delivery))
    date_issues, date_coverage = _date_issues(records, config, delivery)
    issues.extend(date_issues)
    provenance_issues, evidence_counts = _provenance_issues(records, decisions, scores, root, config, delivery)
    issues.extend(provenance_issues)
    issues.sort(key=_issue_sort)

    output_dir.mkdir(parents=True, exist_ok=True)
    issues_path = output_dir / "record-issues.jsonl"
    write_jsonl(issues_path, issues)
    write_json(output_dir / "sampling-manifest.json", sampling)
    by_category = dict(sorted(Counter(item["issue_category"] for item in issues).items()))
    by_code = dict(sorted(Counter(item["code"] for item in issues).items()))
    summary = {
        "delivery_id": delivery, "population_count": len(records), "sample_count": len(sample),
        "stratum_count": sampling["stratum_count"], "issue_count": len(issues),
        "issues_by_category": by_category, "issues_by_code": by_code,
        "issues_by_severity": {severity: sum(item["severity"] == severity for item in issues) for severity in ("BLOCKER", "ERROR", "WARNING", "INFO")},
        "date_coverage": date_coverage, "evidence_reconciliation": evidence_counts,
        "algorithm_version": CONTENT_VERSION, "schema_version": "content-summary-v1",
    }
    write_json(output_dir / "content-summary.json", summary)
    outputs = {
        "record-issues.jsonl": file_sha256(issues_path),
        "sampling-manifest.json": file_sha256(output_dir / "sampling-manifest.json"),
        "content-summary.json": file_sha256(output_dir / "content-summary.json"),
    }
    manifest = {
        "input_fingerprint": fingerprint([row["record"] for row in records]),
        "expectation_fingerprint": fingerprint(expectation), "config_fingerprint": fingerprint(config),
        "sample_plan_fingerprint": fingerprint(plan), "canonical_evidence_fingerprint": fingerprint(decisions),
        "quality_evidence_fingerprint": fingerprint(scores), "outputs": outputs,
        "output_fingerprint": fingerprint(outputs), "algorithm_version": CONTENT_VERSION,
        "schema_version": "content-audit-run-manifest-v1",
    }
    write_json(output_dir / "run-manifest.json", manifest)
    return {"issues": issues, "sampling": sampling, "summary": summary, "manifest": manifest}

from __future__ import annotations

import codecs
import csv
import gzip
import hashlib
import io
import json
import os
import tarfile
import zipfile
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SCAN_VERSION = "delivery-scan-v1"
AUDIT_VERSION = "delivery-audit-v1"
INVENTORY_SCHEMA = "file-inventory-v1"
ISSUE_SCHEMA = "issue-v1"
UNKNOWN = "__UNSPECIFIED__"

RECORD_REQUIRED = (
    "record_id", "dataset_id", "source_file", "source_offset", "record_type",
    "event_date", "title", "raw_text", "clean_text", "metadata",
    "parser_version", "schema_version",
)
RECORD_TYPES: dict[str, object] = {
    "record_id": str, "dataset_id": str, "source_file": str, "source_offset": int,
    "record_type": str, "event_date": (str, type(None)), "title": (str, type(None)),
    "raw_text": str, "clean_text": (str, type(None)), "metadata": dict,
    "parser_version": str, "schema_version": str,
}


class AuditError(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def fingerprint(value: Any) -> str:
    data = value if isinstance(value, bytes) else canonical_bytes(value)
    return "sha256:" + hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def extension_of(path: str) -> str:
    lower = path.lower()
    if lower.endswith(".tar.gz"):
        return ".tar.gz"
    if lower.endswith(".tgz"):
        return ".tgz"
    return PurePosixPath(lower).suffix


def _format(extension: str, head: bytes, encoding: str) -> str:
    if head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06"):
        return "zip"
    if head.startswith(b"\x1f\x8b"):
        return "gzip"
    if len(head) >= 262 and head[257:262] == b"ustar":
        return "tar"
    if encoding == "binary":
        return "binary"
    by_extension = {
        ".json": "json", ".jsonl": "jsonl", ".tsv": "tsv",
        ".html": "html", ".htm": "html", ".zip": "zip", ".tar": "tar",
        ".tar.gz": "gzip", ".tgz": "gzip", ".gz": "gzip", ".txt": "text",
    }
    if encoding in {"utf8", "utf8_bom"}:
        text = head.decode("utf-8-sig", errors="ignore").lstrip().lower()
        if text.startswith("<!doctype html") or text.startswith("<html"):
            return "html"
        if text.startswith("{") or text.startswith("["):
            return "jsonl" if extension == ".jsonl" else "json"
        if "\t" in text.partition("\n")[0]:
            return "tsv"
    return by_extension.get(extension, "unknown")


def _scan_file(path: Path) -> tuple[int, str, bytes, str]:
    digest = hashlib.sha256()
    decoder = codecs.getincrementaldecoder("utf-8")()
    head = bytearray()
    size = 0
    invalid_utf8 = False
    binary = False
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
            size += len(chunk)
            if len(head) < 512:
                head.extend(chunk[: 512 - len(head)])
            if b"\x00" in chunk:
                binary = True
            if not invalid_utf8:
                try:
                    decoder.decode(chunk)
                except UnicodeDecodeError:
                    invalid_utf8 = True
        if not invalid_utf8:
            try:
                decoder.decode(b"", final=True)
            except UnicodeDecodeError:
                invalid_utf8 = True
    raw_head = bytes(head)
    archive_magic = raw_head.startswith((b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b")) or (len(raw_head) >= 262 and raw_head[257:262] == b"ustar")
    if archive_magic:
        encoding = "not_applicable"
    elif binary:
        encoding = "binary"
    elif invalid_utf8:
        encoding = "invalid_utf8"
    elif raw_head.startswith(codecs.BOM_UTF8):
        encoding = "utf8_bom"
    else:
        encoding = "utf8"
    return size, "sha256:" + digest.hexdigest(), raw_head, encoding


def _paths(root: Path) -> Iterable[tuple[Path, str]]:
    def visit(directory: Path, prefix: PurePosixPath) -> Iterable[tuple[Path, str]]:
        entries = sorted(os.scandir(directory), key=lambda item: item.name)
        for entry in entries:
            relative = (prefix / entry.name).as_posix()
            if relative == ".git":
                continue
            path = Path(entry.path)
            yield path, relative
            if entry.is_dir(follow_symlinks=False) and not entry.is_symlink():
                yield from visit(path, prefix / entry.name)
    yield from visit(root, PurePosixPath())


def scan(root: str | Path) -> list[dict[str, Any]]:
    root = Path(root)
    if not root.is_dir():
        raise AuditError("input_root_not_directory")
    records: list[dict[str, Any]] = []
    for path, relative in _paths(root):
        stat = path.lstat()
        extension = extension_of(relative)
        if path.is_symlink():
            entry_type, size, sha, detected, encoding = "symlink", 0, None, "unknown", "not_applicable"
        elif path.is_dir():
            entry_type, size, sha, detected, encoding = "directory", 0, None, "unknown", "not_applicable"
        elif path.is_file():
            entry_type = "regular_file"
            size, sha, head, encoding = _scan_file(path)
            detected = _format(extension, head, encoding)
        else:
            raise AuditError(f"unsupported_filesystem_entry:{relative}:{stat.st_mode}")
        records.append({
            "delivery_id": UNKNOWN, "dataset_id": UNKNOWN, "path": relative,
            "entry_type": entry_type, "size_bytes": size, "sha256": sha,
            "extension": extension, "detected_format": detected,
            "encoding_status": encoding, "empty": entry_type == "regular_file" and size == 0,
            "archive": detected in {"zip", "tar", "gzip"},
            "duplicate_content_group": None, "expectation_match": "not_evaluated",
            "schema_version": INVENTORY_SCHEMA, "algorithm_version": SCAN_VERSION,
        })
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        if record["entry_type"] == "regular_file":
            groups[record["sha256"]].append(record)
    for sha, members in groups.items():
        if len(members) > 1:
            group_id = "duplicate:" + hashlib.sha256((SCAN_VERSION + "\x1f" + sha).encode()).hexdigest()
            for member in members:
                member["duplicate_content_group"] = group_id
    return sorted(records, key=lambda item: item["path"])


def write_json(path: Path, value: Any) -> None:
    path.write_bytes(canonical_bytes(value) + b"\n")


def write_jsonl(path: Path, values: Iterable[Any]) -> None:
    with path.open("wb") as handle:
        for value in values:
            handle.write(canonical_bytes(value) + b"\n")


def run_scan(root: str | Path, output: str | Path) -> list[dict[str, Any]]:
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    result = scan(root)
    write_jsonl(output, result)
    return result


def _strict_object(path: Path, allowed: set[str], required: set[str]) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise AuditError(f"invalid_json:{path.name}:{exc}") from exc
    if not isinstance(value, dict) or set(value) - allowed or not required <= set(value):
        raise AuditError(f"invalid_object_fields:{path.name}")
    return value


def load_config(path: str | Path) -> dict[str, Any]:
    value = _strict_object(Path(path), {"algorithm_version", "allowed_record_schema_versions", "archive_limits", "reject_unknown_record_fields", "schema_version"}, {"algorithm_version", "allowed_record_schema_versions", "archive_limits", "reject_unknown_record_fields", "schema_version"})
    if value["algorithm_version"] != AUDIT_VERSION or value["schema_version"] != "audit-config-v1":
        raise AuditError("unsupported_audit_config_version")
    versions = value["allowed_record_schema_versions"]
    limits = value["archive_limits"]
    if not isinstance(versions, list) or not versions or any(not isinstance(item, str) or not item for item in versions) or len(set(versions)) != len(versions):
        raise AuditError("invalid_allowed_record_schema_versions")
    if not isinstance(value["reject_unknown_record_fields"], bool):
        raise AuditError("invalid_reject_unknown_record_fields")
    expected_limit_keys = {"max_member_count", "max_member_uncompressed_bytes", "max_total_uncompressed_bytes"}
    if not isinstance(limits, dict) or set(limits) != expected_limit_keys or any(type(limits[key]) is not int or limits[key] <= 0 for key in expected_limit_keys):
        raise AuditError("invalid_archive_limits")
    return value


def _safe_relative(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts and "\\" not in value and ":" not in path.parts[0]


def load_expectation(path: str | Path) -> dict[str, Any]:
    value = _strict_object(Path(path), {"delivery_id", "files", "contract_version"}, {"delivery_id", "files", "contract_version"})
    if value["contract_version"] != "delivery-expectation-v1" or not isinstance(value["delivery_id"], str) or not value["delivery_id"] or not isinstance(value["files"], list):
        raise AuditError("invalid_expectation_header")
    allowed = {"dataset_id", "path", "expected_format", "expected_encoding", "expected_schema_version", "expected_size_bytes", "expected_sha256", "expected_record_count", "required"}
    required = {"dataset_id", "path", "expected_format", "expected_encoding", "expected_schema_version", "required"}
    seen: set[str] = set()
    for item in value["files"]:
        if not isinstance(item, dict) or set(item) - allowed or not required <= set(item):
            raise AuditError("invalid_expectation_entry_fields")
        if not all(isinstance(item[key], str) and item[key] for key in ("dataset_id", "path", "expected_format")) or not _safe_relative(item["path"]):
            raise AuditError("invalid_expectation_entry")
        if item["path"] in seen:
            raise AuditError("duplicate_expectation_path")
        seen.add(item["path"])
        if not isinstance(item["required"], bool):
            raise AuditError("invalid_expectation_required")
        for key in ("expected_encoding", "expected_schema_version"):
            if item[key] is not None and (not isinstance(item[key], str) or not item[key]):
                raise AuditError(f"invalid_{key}")
        for key in ("expected_size_bytes", "expected_record_count"):
            if key in item and (type(item[key]) is not int or item[key] < 0):
                raise AuditError(f"invalid_{key}")
        if "expected_sha256" in item and (not isinstance(item["expected_sha256"], str) or not item["expected_sha256"].startswith("sha256:") or len(item["expected_sha256"]) != 71):
            raise AuditError("invalid_expected_sha256")
    value["files"].sort(key=lambda item: item["path"])
    return value


HINTS = {
    "ISS-01": "核对交付清单与原始交付方，不自动修改文件。",
    "ISS-02": "隔离归档并由交付方重新生成；不要解压不可信成员。",
    "ISS-03": "由交付方确认格式和 UTF-8 编码后重新导出。",
    "ISS-04": "按版本化 RecordV1 契约修正来源数据；不要自动迁移。",
}


def issue(category: str, code: str, severity: str, delivery: str, dataset: str, path: str, *, line: int | None = None, member: str | None = None, field: str | None = None, expected: dict[str, Any] | None = None, observed: dict[str, Any] | None = None) -> dict[str, Any]:
    evidence = {"category": category, "code": code, "delivery_id": delivery, "dataset_id": dataset, "path": path, "line": line, "member": member, "field": field, "expected": expected, "observed": observed}
    evidence_fp = fingerprint(evidence)
    return {
        "issue_id": "issue:" + hashlib.sha256((AUDIT_VERSION + "\x1f" + evidence_fp).encode()).hexdigest(),
        "issue_category": category, "code": code, "severity": severity,
        "delivery_id": delivery, "dataset_id": dataset, "path": path,
        "line": line, "member": member, "field": field,
        "expected": expected, "observed": observed,
        "evidence_fingerprint": evidence_fp, "remediation_hint": HINTS[category],
        "algorithm_version": AUDIT_VERSION, "schema_version": ISSUE_SCHEMA,
    }


def _unsafe_member(name: str) -> bool:
    if not name or name.startswith(("/", "\\")) or "\\" in name:
        return True
    path = PurePosixPath(name)
    return ".." in path.parts or (path.parts and ":" in path.parts[0])


def _archive_issues(root: Path, item: dict[str, Any], delivery: str, dataset: str, config: dict[str, Any]) -> list[dict[str, Any]]:
    path = root / item["path"]
    fmt, ext = item["detected_format"], item["extension"]
    result: list[dict[str, Any]] = []
    expected_by_ext = {".zip": "zip", ".tar": "tar", ".tar.gz": "gzip", ".tgz": "gzip", ".gz": "gzip"}.get(ext)
    if expected_by_ext and expected_by_ext != fmt:
        result.append(issue("ISS-02", "archive_extension_mismatch", "ERROR", delivery, dataset, item["path"], expected={"format": expected_by_ext}, observed={"format": fmt}))
    limits = config["archive_limits"]
    try:
        if fmt == "zip":
            try:
                archive = zipfile.ZipFile(path)
            except zipfile.BadZipFile as exc:
                raw = path.read_bytes()
                eocd = raw.rfind(b"PK\x05\x06")
                code = "archive_truncated" if raw.startswith(b"PK") and (eocd < 0 or len(raw) - eocd < 22) else "archive_integrity_failure"
                return result + [issue("ISS-02", code, "ERROR", delivery, dataset, item["path"], observed={"error_type": type(exc).__name__})]
            with archive:
                members = archive.infolist()
                if not members:
                    result.append(issue("ISS-02", "archive_empty", "ERROR", delivery, dataset, item["path"], observed={"member_count": 0}))
                    return result
                total = sum(member.file_size for member in members)
                over = len(members) > limits["max_member_count"] or total > limits["max_total_uncompressed_bytes"] or any(member.file_size > limits["max_member_uncompressed_bytes"] for member in members)
                if over:
                    result.append(issue("ISS-02", "archive_limit_exceeded", "BLOCKER", delivery, dataset, item["path"], expected=limits, observed={"member_count": len(members), "total_uncompressed_bytes": total, "max_member_uncompressed_bytes": max(member.file_size for member in members)}))
                    return result
                for member_info in members:
                    if _unsafe_member(member_info.filename):
                        result.append(issue("ISS-02", "archive_unsafe_member_path", "BLOCKER", delivery, dataset, item["path"], member=member_info.filename, observed={"unsafe": True}))
                    if member_info.flag_bits & 1:
                        result.append(issue("ISS-02", "archive_encrypted", "ERROR", delivery, dataset, item["path"], member=member_info.filename, observed={"encrypted": True}))
                if not any(member_info.flag_bits & 1 for member_info in members):
                    try:
                        bad = archive.testzip()
                        if bad is not None:
                            result.append(issue("ISS-02", "archive_crc_failure", "ERROR", delivery, dataset, item["path"], member=bad, observed={"crc_valid": False}))
                    except zipfile.BadZipFile as exc:
                        result.append(issue("ISS-02", "archive_crc_failure", "ERROR", delivery, dataset, item["path"], observed={"error_type": type(exc).__name__}))
        elif fmt == "tar" or (fmt == "gzip" and ext in {".tar.gz", ".tgz"}):
            with tarfile.open(path, mode="r:gz" if fmt == "gzip" else "r:") as archive:
                members = archive.getmembers()
                if not members:
                    result.append(issue("ISS-02", "archive_empty", "ERROR", delivery, dataset, item["path"], observed={"member_count": 0}))
                total = sum(member.size for member in members)
                if len(members) > limits["max_member_count"] or total > limits["max_total_uncompressed_bytes"] or any(member.size > limits["max_member_uncompressed_bytes"] for member in members):
                    result.append(issue("ISS-02", "archive_limit_exceeded", "BLOCKER", delivery, dataset, item["path"], expected=limits, observed={"member_count": len(members), "total_uncompressed_bytes": total, "max_member_uncompressed_bytes": max((member.size for member in members), default=0)}))
                    return result
                for member_info in members:
                    if _unsafe_member(member_info.name):
                        result.append(issue("ISS-02", "archive_unsafe_member_path", "BLOCKER", delivery, dataset, item["path"], member=member_info.name, observed={"unsafe": True}))
        elif fmt == "gzip":
            total = 0
            with gzip.open(path, "rb") as archive:
                while True:
                    chunk = archive.read(min(65536, limits["max_total_uncompressed_bytes"] + 1 - total))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > limits["max_total_uncompressed_bytes"] or total > limits["max_member_uncompressed_bytes"]:
                        result.append(issue("ISS-02", "archive_limit_exceeded", "BLOCKER", delivery, dataset, item["path"], expected=limits, observed={"member_count": 1, "total_uncompressed_bytes": total, "max_member_uncompressed_bytes": total}))
                        return result
            if total == 0:
                result.append(issue("ISS-02", "archive_empty", "ERROR", delivery, dataset, item["path"], observed={"member_count": 1, "total_uncompressed_bytes": 0}))
    except (OSError, EOFError, gzip.BadGzipFile, tarfile.TarError, zipfile.BadZipFile) as exc:
        code = "archive_truncated" if isinstance(exc, (EOFError,)) or "end of file" in str(exc).lower() or "truncated" in str(exc).lower() else "archive_integrity_failure"
        result.append(issue("ISS-02", code, "ERROR", delivery, dataset, item["path"], observed={"error_type": type(exc).__name__}))
    return result


def _validate_record(record: dict[str, Any], config: dict[str, Any], delivery: str, dataset: str, path: str, line: int) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for field in RECORD_REQUIRED:
        if field not in record:
            code = "schema_version_missing" if field == "schema_version" else "schema_missing_required_field"
            result.append(issue("ISS-04", code, "ERROR", delivery, dataset, path, line=line, field=field, expected={"required": True}, observed={"present": False}))
    for field in set(record) & set(RECORD_TYPES):
        expected_type = RECORD_TYPES[field]
        if field == "source_offset":
            valid = type(record[field]) is int and record[field] >= 0
        else:
            valid = isinstance(record[field], expected_type)
        if not valid:
            result.append(issue("ISS-04", "schema_type_mismatch", "ERROR", delivery, dataset, path, line=line, field=field, expected={"type": "RecordV1 contract"}, observed={"json_type": type(record[field]).__name__}))
    version = record.get("schema_version")
    if isinstance(version, str) and version not in config["allowed_record_schema_versions"]:
        result.append(issue("ISS-04", "schema_version_unsupported", "ERROR", delivery, dataset, path, line=line, field="schema_version", expected={"allowed": config["allowed_record_schema_versions"]}, observed={"value": version}))
    if config["reject_unknown_record_fields"]:
        for field in sorted(set(record) - set(RECORD_REQUIRED)):
            result.append(issue("ISS-04", "schema_unknown_field", "ERROR", delivery, dataset, path, line=line, field=field, expected={"allowed": False}, observed={"present": True}))
    return result


def _content_issues(root: Path, item: dict[str, Any], expectation: dict[str, Any] | None, delivery: str, dataset: str, config: dict[str, Any], seen_record_ids: set[str]) -> tuple[list[dict[str, Any]], int | None, set[str]]:
    if item["entry_type"] != "regular_file" or item["empty"] or ".git" in PurePosixPath(item["path"]).parts:
        return [], None, set()
    if item["archive"]:
        return _archive_issues(root, item, delivery, dataset, config), None, set()
    result: list[dict[str, Any]] = []
    path = root / item["path"]
    if item["encoding_status"] == "binary":
        return [issue("ISS-03", "binary_content_in_text_file", "ERROR", delivery, dataset, item["path"], observed={"nul_byte": True})], None, set()
    if item["encoding_status"] == "invalid_utf8":
        return [issue("ISS-03", "invalid_utf8", "ERROR", delivery, dataset, item["path"], expected={"encoding": "utf8"}, observed={"encoding": "invalid_utf8"})], None, set()
    if item["encoding_status"] == "utf8_bom":
        result.append(issue("ISS-03", "unexpected_utf8_bom", "WARNING", delivery, dataset, item["path"], expected={"bom": False}, observed={"bom": True}))
    fmt = item["detected_format"]
    extension_format = {".json": "json", ".jsonl": "jsonl", ".tsv": "tsv", ".html": "html", ".htm": "html", ".txt": "text"}.get(item["extension"])
    if extension_format and fmt != extension_format:
        result.append(issue("ISS-03", "format_extension_mismatch", "ERROR", delivery, dataset, item["path"], expected={"format": extension_format}, observed={"format": fmt}))
    if fmt == "unknown":
        return result + [issue("ISS-03", "unsupported_format", "WARNING", delivery, dataset, item["path"], observed={"extension": item["extension"]})], None, set()
    encoding = "utf-8-sig" if item["encoding_status"] == "utf8_bom" else "utf-8"
    parsed_records: list[tuple[int, dict[str, Any]]] = []
    count: int | None = None
    if fmt == "json":
        try:
            value = json.loads(path.read_text(encoding=encoding))
            if isinstance(value, dict):
                parsed_records.append((1, value))
            count = len(value) if isinstance(value, list) else 1
        except json.JSONDecodeError as exc:
            result.append(issue("ISS-03", "json_parse_failure", "ERROR", delivery, dataset, item["path"], line=exc.lineno, observed={"column": exc.colno}))
    elif fmt == "jsonl":
        count = 0
        with path.open(encoding=encoding) as handle:
            for number, raw in enumerate(handle, 1):
                if not raw.strip():
                    continue
                try:
                    value = json.loads(raw)
                    if not isinstance(value, dict):
                        raise json.JSONDecodeError("expected object", raw, 0)
                    parsed_records.append((number, value))
                    count += 1
                except json.JSONDecodeError as exc:
                    result.append(issue("ISS-03", "jsonl_parse_failure", "ERROR", delivery, dataset, item["path"], line=number, observed={"column": exc.colno}))
    elif fmt == "tsv":
        with path.open(encoding=encoding, newline="") as handle:
            rows = csv.reader(handle, delimiter="\t")
            try:
                header = next(rows)
            except StopIteration:
                header = []
            count = 0
            for number, row in enumerate(rows, 2):
                count += 1
                if len(row) != len(header):
                    result.append(issue("ISS-03", "tsv_column_mismatch", "ERROR", delivery, dataset, item["path"], line=number, expected={"column_count": len(header)}, observed={"column_count": len(row)}))
    if expectation and expectation.get("expected_schema_version") == "record-v1":
        versions: set[str] = set()
        for number, record in parsed_records:
            record_id = record.get("record_id")
            if isinstance(record_id, str):
                if record_id in seen_record_ids:
                    raise AuditError(f"duplicate_record_id:{record_id}")
                seen_record_ids.add(record_id)
            result.extend(_validate_record(record, config, delivery, dataset, item["path"], number))
            if isinstance(record.get("schema_version"), str):
                versions.add(record["schema_version"])
        if len(versions) > 1:
            result.append(issue("ISS-04", "schema_mixed_versions", "ERROR", delivery, dataset, item["path"], field="schema_version", expected={"version_count": 1}, observed={"versions": sorted(versions)}))
    return result, count, {record.get("schema_version") for _, record in parsed_records if isinstance(record.get("schema_version"), str)}


def _safe_output(root: Path, output: Path) -> None:
    root_resolved = root.resolve()
    output_resolved = output.resolve()
    if output_resolved == root_resolved or root_resolved in output_resolved.parents:
        raise AuditError("output_directory_inside_input_root")


def audit(root: str | Path, config_path: str | Path, output_dir: str | Path, expectation_path: str | Path | None = None) -> dict[str, Any]:
    root, output_dir = Path(root), Path(output_dir)
    _safe_output(root, output_dir)
    config = load_config(config_path)
    expectation = load_expectation(expectation_path) if expectation_path else None
    delivery = expectation["delivery_id"] if expectation else UNKNOWN
    expected_by_path = {item["path"]: item for item in expectation["files"]} if expectation else {}
    inventory = scan(root)
    actual_by_path = {item["path"]: item for item in inventory}
    issues: list[dict[str, Any]] = []

    if expectation:
        for path, expected in expected_by_path.items():
            if path not in actual_by_path and expected["required"]:
                issues.append(issue("ISS-01", "missing_required_file", "BLOCKER", delivery, expected["dataset_id"], path, expected={"required": True}, observed={"present": False}))
    for item in inventory:
        expected = expected_by_path.get(item["path"])
        item["delivery_id"] = delivery
        item["dataset_id"] = expected["dataset_id"] if expected else UNKNOWN
        if expectation:
            item["expectation_match"] = "matched" if expected else "unexpected"
        if item["entry_type"] == "directory":
            continue
        dataset = item["dataset_id"]
        if expectation and not expected:
            issues.append(issue("ISS-01", "unexpected_file", "WARNING", delivery, dataset, item["path"], expected={"listed": True}, observed={"listed": False}))
        if item["entry_type"] == "symlink":
            issues.append(issue("ISS-01", "unsupported_entry_type", "ERROR", delivery, dataset, item["path"], observed={"entry_type": "symlink"}))
            continue
        if ".git" in PurePosixPath(item["path"]).parts:
            issues.append(issue("ISS-01", "unsafe_nested_git", "BLOCKER", delivery, dataset, item["path"], observed={"nested_git": True}))
            continue
        if item["empty"]:
            issues.append(issue("ISS-01", "empty_file", "ERROR", delivery, dataset, item["path"], observed={"size_bytes": 0}))
        if expected and "expected_size_bytes" in expected and item["size_bytes"] != expected["expected_size_bytes"]:
            issues.append(issue("ISS-01", "size_mismatch", "ERROR", delivery, dataset, item["path"], expected={"size_bytes": expected["expected_size_bytes"]}, observed={"size_bytes": item["size_bytes"]}))
        if expected and "expected_sha256" in expected and item["sha256"] != expected["expected_sha256"]:
            issues.append(issue("ISS-01", "sha256_mismatch", "ERROR", delivery, dataset, item["path"], expected={"sha256": expected["expected_sha256"]}, observed={"sha256": item["sha256"]}))

    duplicate_groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for item in inventory:
        if item["duplicate_content_group"]:
            duplicate_groups[item["duplicate_content_group"]].append(item)
    for group_id, members in sorted(duplicate_groups.items()):
        paths = sorted(item["path"] for item in members)
        issues.append(issue("ISS-01", "duplicate_content", "WARNING", delivery, members[0]["dataset_id"], paths[0], expected={"unique_content": True}, observed={"duplicate_content_group": group_id, "paths": paths}))

    seen_record_ids: set[str] = set()
    for item in inventory:
        expected = expected_by_path.get(item["path"])
        content, record_count, _ = _content_issues(root, item, expected, delivery, item["dataset_id"], config, seen_record_ids)
        issues.extend(content)
        if expected and "expected_record_count" in expected and record_count is not None and record_count != expected["expected_record_count"]:
            issues.append(issue("ISS-04", "schema_record_count_mismatch", "ERROR", delivery, item["dataset_id"], item["path"], expected={"record_count": expected["expected_record_count"]}, observed={"record_count": record_count}))

    issues.sort(key=lambda item: (item["issue_category"], item["code"], item["path"], item["line"] or 0, item["member"] or "", item["field"] or "", item["issue_id"]))
    inventory.sort(key=lambda item: item["path"])
    output_dir.mkdir(parents=True, exist_ok=True)
    inventory_path, issues_path = output_dir / "file-inventory.jsonl", output_dir / "issues.jsonl"
    write_jsonl(inventory_path, inventory)
    write_jsonl(issues_path, issues)
    by_category = dict(sorted(Counter(item["issue_category"] for item in issues).items()))
    by_code = dict(sorted(Counter(item["code"] for item in issues).items()))
    by_severity = {key: Counter(item["severity"] for item in issues).get(key, 0) for key in ("BLOCKER", "ERROR", "WARNING", "INFO")}
    summary = {
        "delivery_id": delivery, "inventory_entry_count": len(inventory),
        "regular_file_count": sum(item["entry_type"] == "regular_file" for item in inventory),
        "dataset_count": len({item["dataset_id"] for item in inventory if item["dataset_id"] != UNKNOWN}),
        "issue_count": len(issues), "issues_by_category": by_category,
        "issues_by_code": by_code, "issues_by_severity": by_severity,
        "algorithm_version": AUDIT_VERSION, "schema_version": "audit-summary-v1",
    }
    write_json(output_dir / "audit-summary.json", summary)
    outputs = {
        "file-inventory.jsonl": file_sha256(inventory_path),
        "issues.jsonl": file_sha256(issues_path),
        "audit-summary.json": file_sha256(output_dir / "audit-summary.json"),
    }
    manifest = {
        "input_fingerprint": fingerprint([{key: item[key] for key in ("path", "entry_type", "size_bytes", "sha256")} for item in inventory]),
        "expectation_fingerprint": fingerprint(expectation) if expectation else None,
        "config_fingerprint": fingerprint(config), "outputs": outputs,
        "output_fingerprint": fingerprint(outputs), "algorithm_version": AUDIT_VERSION,
        "schema_version": "audit-run-manifest-v1",
    }
    write_json(output_dir / "run-manifest.json", manifest)
    return {"inventory": inventory, "issues": issues, "summary": summary, "manifest": manifest}

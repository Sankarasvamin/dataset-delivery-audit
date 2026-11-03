#!/usr/bin/env python3
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import shutil
import struct
import tarfile
import zipfile
from pathlib import Path

SEED = 20260822


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_json(path: Path, value: object) -> None:
    write(path, canonical(value))


def record(record_id: str, dataset: str, offset: int = 0, **changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "record_id": record_id, "dataset_id": dataset, "source_file": f"{dataset}.jsonl",
        "source_offset": offset, "record_type": "article", "event_date": "2026-08-21",
        "title": f"合成标题 {record_id}", "raw_text": f"合成正文 {record_id}",
        "clean_text": f"合成正文 {record_id}", "metadata": {"synthetic": True},
        "parser_version": "fixture-parser-v1", "schema_version": "record-v1",
    }
    value.update(changes)
    return value


def jsonl(values: list[object]) -> bytes:
    return b"".join(canonical(value) for value in values)


def zip_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_STORED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, data)
    return output.getvalue()


def encrypted_zip() -> bytes:
    raw = bytearray(zip_bytes([("encrypted.txt", b"synthetic encrypted marker")]))
    local = raw.find(b"PK\x03\x04")
    central = raw.find(b"PK\x01\x02")
    struct.pack_into("<H", raw, local + 6, struct.unpack_from("<H", raw, local + 6)[0] | 1)
    struct.pack_into("<H", raw, central + 8, struct.unpack_from("<H", raw, central + 8)[0] | 1)
    return bytes(raw)


def crc_zip() -> bytes:
    payload = b"crc-payload-20260822"
    raw = bytearray(zip_bytes([("crc.txt", payload)]))
    position = raw.find(payload)
    raw[position] ^= 1
    return bytes(raw)


def tar_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in entries:
            info = tarfile.TarInfo(name)
            info.size, info.mtime, info.uid, info.gid, info.uname, info.gname, info.mode = len(data), 0, 0, 0, "", "", 0o644
            archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


def gzip_bytes(data: bytes) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as archive:
        archive.write(data)
    return output.getvalue()


def expected_entry(root: Path, dataset: str, relative: str, fmt: str, *, encoding: str | None = "utf8", schema: str | None = None, required: bool = True, size: int | None = None, digest: str | None = None, count: int | None = None) -> dict[str, object]:
    item: dict[str, object] = {
        "dataset_id": dataset, "path": relative, "expected_format": fmt,
        "expected_encoding": encoding, "expected_schema_version": schema, "required": required,
    }
    path = root / relative
    if size is not None:
        item["expected_size_bytes"] = size
    elif path.is_file() and not path.is_symlink():
        item["expected_size_bytes"] = path.stat().st_size
    if digest is not None:
        item["expected_sha256"] = digest
    elif path.is_file() and not path.is_symlink():
        item["expected_sha256"] = sha(path.read_bytes())
    if count is not None:
        item["expected_record_count"] = count
    return item


def create_valid(root: Path, reverse: bool) -> dict[str, object]:
    files: list[tuple[str, bytes]] = [
        ("alpha/records.jsonl", jsonl([record("valid-a-1", "alpha"), record("valid-a-2", "alpha", 1, record_type="comment", title=None)])),
        ("alpha/metadata.json", canonical({"dataset_id": "alpha", "synthetic": True})),
        ("beta/table.tsv", "id\tnote\n1\t\"quoted\tvalue\"\n".encode()),
        ("beta/page.html", "<!doctype html><html><body>合成交付页</body></html>\n".encode()),
        ("gamma/bundle.zip", zip_bytes([("inside.json", canonical({"ok": True}))])),
        ("gamma/bundle.tar", tar_bytes([("inside.txt", b"synthetic tar")])) ,
        ("gamma/bundle.tgz", gzip_bytes(tar_bytes([("inside.txt", b"synthetic tgz")]))),
        ("gamma/records.jsonl.gz", gzip_bytes(jsonl([record("valid-g-1", "gamma")]))),
    ]
    for relative, data in (reversed(files) if reverse else files):
        write(root / relative, data)
    expectations = [
        expected_entry(root, "alpha", "alpha/records.jsonl", "jsonl", schema="record-v1", count=2),
        expected_entry(root, "alpha", "alpha/metadata.json", "json"),
        expected_entry(root, "beta", "beta/table.tsv", "tsv"),
        expected_entry(root, "beta", "beta/page.html", "html"),
        expected_entry(root, "gamma", "gamma/bundle.zip", "zip", encoding=None),
        expected_entry(root, "gamma", "gamma/bundle.tar", "tar", encoding=None),
        expected_entry(root, "gamma", "gamma/bundle.tgz", "gzip", encoding=None),
        expected_entry(root, "gamma", "gamma/records.jsonl.gz", "gzip", encoding=None),
    ]
    return {"delivery_id": "synthetic-valid-delivery", "files": sorted(expectations, key=lambda item: item["path"]), "contract_version": "delivery-expectation-v1"}


def create_problem(root: Path, reverse: bool) -> tuple[dict[str, object], list[dict[str, object]]]:
    valid_html = b"<!doctype html><html><body>synthetic physical evidence</body></html>\n"
    duplicate_html = b"<!doctype html><html><body>duplicate payload</body></html>\n"
    mixed = [record("mixed-1", "schema"), record("mixed-2", "schema", 1, schema_version="record-v0")]
    files: list[tuple[str, bytes]] = [
        ("physical/empty.txt", b""),
        ("physical/size.html", valid_html + b"size"),
        ("physical/hash.html", valid_html + b"hash"),
        ("physical/dup-a.html", duplicate_html), ("physical/dup-b.html", duplicate_html),
        ("physical/unexpected.html", valid_html + b"unexpected"),
        ("nested/.git/config", b"[core]\nrepositoryformatversion = 0\n"),
        ("archives/corrupt.zip", b"not-a-zip"),
        ("archives/crc.zip", crc_zip()), ("archives/encrypted.zip", encrypted_zip()),
        ("archives/empty.zip", zip_bytes([])),
        ("archives/truncated.zip", zip_bytes([("truncated.txt", b"payload")])[:-18]),
        ("archives/unsafe.zip", zip_bytes([("../escape.txt", b"unsafe")])),
        ("archives/limit.zip", zip_bytes([("large.txt", b"x" * 20000)])),
        ("archives/wrong.tar", zip_bytes([("inside.txt", b"wrong extension")])),
        ("format/mismatched.json", b"<!doctype html><html><body>discuss JSON</body></html>\n"),
        ("format/invalid-utf8.jsonl", b'{"ok":true}\n\xff\xfe\n'),
        ("format/bom.json", b"\xef\xbb\xbf" + canonical({"bom": True})),
        ("format/invalid.json", b'{"broken":}\n'),
        ("format/bad.jsonl", canonical({"ok": True}) + b'{"bad":}\n' + canonical({"still": "parsed"})),
        ("format/bad.tsv", b'id\tnote\n1\n2\t"quoted\tvalue"\n'),
        ("format/unsupported.xyz", b"synthetic unknown format\n"),
        ("format/binary.json", b'{"prefix":"ok"}\x00\x01'),
        ("schema/missing-field.jsonl", jsonl([{key: value for key, value in record("missing-field", "schema").items() if key != "raw_text"}])),
        ("schema/type-mismatch.jsonl", jsonl([record("type-mismatch", "schema", source_offset="zero")])),
        ("schema/missing-version.jsonl", jsonl([{key: value for key, value in record("missing-version", "schema").items() if key != "schema_version"}])),
        ("schema/unsupported-version.jsonl", jsonl([record("unsupported-version", "schema", schema_version="record-v0")])),
        ("schema/unknown-field.jsonl", jsonl([record("unknown-field", "schema", future_field="synthetic")])),
        ("schema/mixed-versions.jsonl", jsonl(mixed)),
        ("schema/count-mismatch.jsonl", jsonl([record("count-mismatch", "schema")])),
    ]
    for relative, data in (reversed(files) if reverse else files):
        write(root / relative, data)
    (root / "physical").mkdir(exist_ok=True)
    os.symlink("size.html", root / "physical/link.html")

    entries: list[dict[str, object]] = [
        {"dataset_id": "physical", "path": "physical/missing-required.html", "expected_format": "html", "expected_encoding": "utf8", "expected_schema_version": None, "required": True},
        expected_entry(root, "physical", "physical/empty.txt", "text"),
        expected_entry(root, "physical", "physical/size.html", "html", size=(root / "physical/size.html").stat().st_size + 1),
        expected_entry(root, "physical", "physical/hash.html", "html", digest="sha256:" + "0" * 64),
        expected_entry(root, "physical", "physical/dup-a.html", "html"),
        expected_entry(root, "physical", "physical/dup-b.html", "html"),
        {"dataset_id": "physical", "path": "physical/link.html", "expected_format": "html", "expected_encoding": None, "expected_schema_version": None, "required": True},
        expected_entry(root, "physical", "nested/.git/config", "text"),
    ]
    for relative, _ in files:
        if relative.startswith("physical/") or relative == "physical/unexpected.html" or relative == "nested/.git/config":
            continue
        if relative.startswith("archives/"):
            entries.append(expected_entry(root, "archives", relative, "tar" if relative.endswith(".tar") else "zip", encoding=None))
        elif relative.startswith("format/"):
            fmt = {".jsonl": "jsonl", ".json": "json", ".tsv": "tsv"}.get(Path(relative).suffix, "unknown")
            entries.append(expected_entry(root, "format", relative, fmt))
        elif relative.startswith("schema/"):
            count = 2 if relative.endswith("mixed-versions.jsonl") else (2 if relative.endswith("count-mismatch.jsonl") else 1)
            entries.append(expected_entry(root, "schema", relative, "jsonl", schema="record-v1", count=count))
    expectation = {"delivery_id": "synthetic-problem-delivery", "files": sorted(entries, key=lambda item: item["path"]), "contract_version": "delivery-expectation-v1"}

    specs = [
        ("ISS-01", "missing_required_file", "physical/missing-required.html", None, None, None),
        ("ISS-01", "empty_file", "physical/empty.txt", None, None, None),
        ("ISS-01", "size_mismatch", "physical/size.html", None, None, None),
        ("ISS-01", "sha256_mismatch", "physical/hash.html", None, None, None),
        ("ISS-01", "duplicate_content", "physical/dup-a.html", None, None, None),
        ("ISS-01", "unexpected_file", "physical/unexpected.html", None, None, None),
        ("ISS-01", "unsupported_entry_type", "physical/link.html", None, None, None),
        ("ISS-01", "unsafe_nested_git", "nested/.git/config", None, None, None),
        ("ISS-02", "archive_integrity_failure", "archives/corrupt.zip", None, None, None),
        ("ISS-02", "archive_crc_failure", "archives/crc.zip", None, "crc.txt", None),
        ("ISS-02", "archive_encrypted", "archives/encrypted.zip", None, "encrypted.txt", None),
        ("ISS-02", "archive_empty", "archives/empty.zip", None, None, None),
        ("ISS-02", "archive_truncated", "archives/truncated.zip", None, None, None),
        ("ISS-02", "archive_unsafe_member_path", "archives/unsafe.zip", None, "../escape.txt", None),
        ("ISS-02", "archive_limit_exceeded", "archives/limit.zip", None, None, None),
        ("ISS-02", "archive_extension_mismatch", "archives/wrong.tar", None, None, None),
        ("ISS-03", "format_extension_mismatch", "format/mismatched.json", None, None, None),
        ("ISS-03", "invalid_utf8", "format/invalid-utf8.jsonl", None, None, None),
        ("ISS-03", "unexpected_utf8_bom", "format/bom.json", None, None, None),
        ("ISS-03", "json_parse_failure", "format/invalid.json", 1, None, None),
        ("ISS-03", "jsonl_parse_failure", "format/bad.jsonl", 2, None, None),
        ("ISS-03", "tsv_column_mismatch", "format/bad.tsv", 2, None, None),
        ("ISS-03", "unsupported_format", "format/unsupported.xyz", None, None, None),
        ("ISS-03", "binary_content_in_text_file", "format/binary.json", None, None, None),
        ("ISS-04", "schema_missing_required_field", "schema/missing-field.jsonl", 1, None, "raw_text"),
        ("ISS-04", "schema_type_mismatch", "schema/type-mismatch.jsonl", 1, None, "source_offset"),
        ("ISS-04", "schema_version_missing", "schema/missing-version.jsonl", 1, None, "schema_version"),
        ("ISS-04", "schema_version_unsupported", "schema/unsupported-version.jsonl", 1, None, "schema_version"),
        ("ISS-04", "schema_unknown_field", "schema/unknown-field.jsonl", 1, None, "future_field"),
        ("ISS-04", "schema_version_unsupported", "schema/mixed-versions.jsonl", 2, None, "schema_version"),
        ("ISS-04", "schema_mixed_versions", "schema/mixed-versions.jsonl", None, None, "schema_version"),
        ("ISS-04", "schema_record_count_mismatch", "schema/count-mismatch.jsonl", None, None, None),
    ]
    injections = []
    for index, (category, code, relative, line, member, field) in enumerate(specs, 1):
        fixture = root / relative
        fixture_fp = sha(fixture.read_bytes()) if fixture.is_file() and not fixture.is_symlink() else sha(relative.encode())
        injections.append({
            "injection_id": f"inj-{index:03d}", "issue_category": category, "code": code,
            "delivery_id": "synthetic-problem-delivery",
            "dataset_id": ("__UNSPECIFIED__" if code == "unexpected_file" else "physical") if category == "ISS-01" else {"ISS-02": "archives", "ISS-03": "format", "ISS-04": "schema"}[category],
            "path": relative, "line": line, "member": member, "field": field,
            "expected_detected": True, "fixture_fingerprint": fixture_fp,
        })
    return expectation, injections


def tree_fingerprint(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            data = b"L" + os.readlink(path).encode()
        elif path.is_file():
            data = b"F" + path.read_bytes()
        else:
            data = b"D"
        digest.update(relative.encode() + b"\x00" + data + b"\x00")
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
    valid = create_valid(output / "valid-delivery", args.reverse_creation)
    problem, injections = create_problem(output / "problem-delivery", args.reverse_creation)
    write_json(output / "valid-expectation.json", valid)
    write_json(output / "problem-expectation.json", problem)
    write_json(output / "injection-truth.json", {"seed": SEED, "injection_count": len(injections), "injections": injections, "schema_version": "injection-truth-v1"})
    manifest = {
        "generator_version": "delivery-fixture-generator-v1", "seed": SEED,
        "deliveries": {"valid": {"dataset_count": 3, "file_count": 8}, "problem": {"dataset_count": 4, "file_count": sum(path.is_file() or path.is_symlink() for path in (output / "problem-delivery").rglob("*"))}},
        "formats": ["gzip", "html", "json", "jsonl", "tar", "tsv", "zip"],
        "injection_count": len(injections),
        "fixture_fingerprint": tree_fingerprint(output),
        "schema_version": "generation-manifest-v1",
    }
    write_json(output / "generation-manifest.json", manifest)


if __name__ == "__main__":
    main()

#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
verify_tmp="$(mktemp -d /tmp/dataset-delivery-audit.XXXXXX)"
cleanup() {
  case "$verify_tmp" in
    /tmp/dataset-delivery-audit.*|/private/tmp/dataset-delivery-audit.*) rm -rf -- "$verify_tmp" ;;
    *) printf 'refusing to remove unexpected temporary path: %s\n' "$verify_tmp" >&2 ;;
  esac
}
trap cleanup EXIT
export PYTHONDONTWRITEBYTECODE=1
export CARGO_TARGET_DIR="$verify_tmp/cargo-target"

for command in python3 rustc cargo git shasum diff rg; do
  command -v "$command" >/dev/null || { printf 'missing command: %s\n' "$command" >&2; exit 1; }
done
python3 --version
rustc --version
cargo --version
test -f rust/Cargo.lock

check_upstream() {
  local directory="$1" expected_head="$2" expected_tag="$3" expected_remote="$4" expected_list="$5" expected_state="$6" expected_content="$7"
  test -d "$directory/.git"
  test "$(git -C "$directory" rev-parse HEAD)" = "$expected_head"
  test "$(git -C "$directory" rev-list -n 1 "$expected_tag")" = "$expected_head"
  test -z "$(git -C "$directory" status --porcelain)"
  test "$(git -C "$directory" remote get-url origin)" = "$expected_remote"
  test "$(git -C "$directory" ls-files | LC_ALL=C sort | shasum -a 256 | awk '{print $1}')" = "$expected_list"
  test "$(git -C "$directory" ls-files -s | LC_ALL=C sort | shasum -a 256 | awk '{print $1}')" = "$expected_state"
  test "$(cd "$directory" && git ls-files -z | LC_ALL=C sort -z | xargs -0 shasum -a 256 | shasum -a 256 | awk '{print $1}')" = "$expected_content"
}

check_all_upstreams() {
  check_upstream ../corpus-preprocessing-core 2f7ee33dfbcdb4d80e685b3d6b57545542160e4d v0.3.0 https://github.com/Sankarasvamin/corpus-preprocessing-core.git d14707028c551e2ec3a795dfa7d5a9a9625d5322c34faf996cbd9dc20d769b97 bc65e294bd7cb84d185713463438fc7b2352cc5bd3931e8f29d714d4e7fcbbb7 bc1dbc9100b5897d89542a38dbdd25afb84b926d903523d53dec82d747c7f0fd
  check_upstream ../text-dedup-canonicalization f569c672746d44f3c9a288f0d4b5620b5678e790 v0.4.0 https://github.com/Sankarasvamin/text-dedup-canonicalization.git 219b00f107cb67b47f9cad7fad0aa3faff28b6afc664accb6c28b049ff179a90 0282531950fc504344f9bd958c05132ed5efa8e882902ec77e3b0a28d665fd0f 0c78b2bd1e5033019e780c527b93abce7bfa41747a91ddff1471c2475ccc503a
  check_upstream ../corpus-quality-evaluation 1e8fb664e5020a877f531646e3067bccaa1b40e7 v0.2.0 https://github.com/Sankarasvamin/corpus-quality-evaluation.git c6a2ff9f9721628f07475d60bb5d0400da2a38f6c7990a9a65eb785f8aff01d4 411d6586fb73a6c3642cd0328e4db3031f408452d69f959f9730373dd9d61d5b 8833cbd438e8817557b2f5447cca9f6ddd599ca703cee75e29f5d7b668f81870
}
check_all_upstreams
printf 'three upstream repositories locked and clean\n'

python3 - <<'PY'
import hashlib, json, pathlib
schemas = sorted(pathlib.Path("contracts").glob("*.schema.json"))
assert len(schemas) == 8, schemas
for path in schemas: json.loads(path.read_text(encoding="utf-8"))
actual = hashlib.sha256(pathlib.Path("contracts/record-v1.schema.json").read_bytes()).hexdigest()
assert actual == "a47eae12eb1898f6c34c1af7bbae29ef78f888b71506befda1586d5ec923883c", actual
locked = {
    "delivery-expectation-v1.schema.json": "961f32412f046b4e401323ee7eadef896872fd29b5ce29e0fc040a1b08cd81e2",
    "file-inventory-v1.schema.json": "a3a53d87d85ddb96cc252d51acfc2566a9e69d11ec3d78f1fdf4e78c57a311f4",
    "issue-v1.schema.json": "26a2d95a8e1d3c780561879375fac21cdfe0524663350d931e954c549c0cbabe",
    "record-v1.schema.json": "a47eae12eb1898f6c34c1af7bbae29ef78f888b71506befda1586d5ec923883c",
}
for name, expected in locked.items():
    assert hashlib.sha256((pathlib.Path("contracts") / name).read_bytes()).hexdigest() == expected
fixture = json.loads(pathlib.Path("fixtures/generated/generation-manifest.json").read_text())
assert fixture["fixture_fingerprint"] == "sha256:b4abd4b3deb38501fde5e5a36b9cac9e215abee96afe922c6a1440c647114c0b"
print("eight contracts parsed; four stage-1 contracts and fixture fingerprint unchanged")
PY

cmp contracts/sample-plan-v1.schema.json ../corpus-preprocessing-core/contracts/sample-plan-v1.schema.json
cmp contracts/canonical-decision-v1.schema.json ../text-dedup-canonicalization/contracts/canonical-decision-v1.schema.json
cmp contracts/quality-score-v1.schema.json ../corpus-quality-evaluation/contracts/quality-score-v1.schema.json
printf 'three consumed upstream contracts are byte-identical\n'

python3 scripts/generate_fixtures.py --seed 20260822 --output-dir "$verify_tmp/generated-a"
python3 scripts/generate_fixtures.py --seed 20260822 --reverse-creation --output-dir "$verify_tmp/generated-b"
diff -ru "$verify_tmp/generated-a" "$verify_tmp/generated-b"
diff -ru fixtures/generated "$verify_tmp/generated-a"
printf 'fixture forward/reverse creation and committed bytes are identical\n'

PYTHONPATH=python/src python3 -m unittest discover -s python/tests -p 'test_audit.py' -v
cargo test --locked --manifest-path rust/Cargo.toml

scan_python() {
  PYTHONPATH=python/src python3 -m dataset_delivery_audit scan --root "$1" --output "$2"
}
scan_rust() {
  cargo run --quiet --locked --manifest-path rust/Cargo.toml -- scan --root "$1" --output "$2"
}
for name in valid problem; do
  scan_python "fixtures/generated/$name-delivery" "$verify_tmp/$name-python-a.jsonl"
  scan_python "fixtures/generated/$name-delivery" "$verify_tmp/$name-python-b.jsonl"
  scan_rust "fixtures/generated/$name-delivery" "$verify_tmp/$name-rust-a.jsonl"
  scan_rust "fixtures/generated/$name-delivery" "$verify_tmp/$name-rust-b.jsonl"
  diff -u "$verify_tmp/$name-python-a.jsonl" "$verify_tmp/$name-python-b.jsonl"
  diff -u "$verify_tmp/$name-rust-a.jsonl" "$verify_tmp/$name-rust-b.jsonl"
done
python3 scripts/check_parity.py

run_audit() {
  PYTHONPATH=python/src python3 -m dataset_delivery_audit audit \
    --root "fixtures/generated/$1-delivery" \
    --expectation "fixtures/generated/$1-expectation.json" \
    --config configs/audit-v1.json --output-dir "$2"
}
run_audit valid "$verify_tmp/valid-a"
run_audit valid "$verify_tmp/valid-b"
run_audit problem "$verify_tmp/problem-a"
run_audit problem "$verify_tmp/problem-b"
diff -ru "$verify_tmp/valid-a" "$verify_tmp/valid-b"
diff -ru "$verify_tmp/problem-a" "$verify_tmp/problem-b"

python3 - "$verify_tmp" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])

def lines(path): return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
def safe(value):
    assert not isinstance(value, float), value
    if isinstance(value, str): assert not value.startswith(("/Users/", "/tmp/", "/private/tmp/")), value
    elif isinstance(value, list):
        for item in value: safe(item)
    elif isinstance(value, dict):
        assert not set(value) & {"timestamp", "created_at", "run_at", "time", "inode", "username"}
        for item in value.values(): safe(item)

valid = json.loads((root / "valid-a/audit-summary.json").read_text())
problem = json.loads((root / "problem-a/audit-summary.json").read_text())
assert valid["issue_count"] == 0 and valid["issues_by_severity"] == {"BLOCKER": 0, "ERROR": 0, "WARNING": 0, "INFO": 0}
assert valid["regular_file_count"] == 8 and valid["dataset_count"] == 3
assert problem["issue_count"] == 32
assert problem["issues_by_category"] == {"ISS-01": 8, "ISS-02": 8, "ISS-03": 8, "ISS-04": 8}
assert problem["issues_by_severity"] == {"BLOCKER": 4, "ERROR": 24, "WARNING": 4, "INFO": 0}
truth = json.loads(pathlib.Path("fixtures/generated/injection-truth.json").read_text())["injections"]
issues = lines(root / "problem-a/issues.jsonl")
key = lambda item: tuple(item[name] for name in ("issue_category", "code", "dataset_id", "path", "line", "member", "field"))
assert len(truth) == len(issues) == 32 and {key(item) for item in truth} == {key(item) for item in issues}
assert len({item["injection_id"] for item in truth}) == 32
assert json.loads((root / "valid-a/run-manifest.json").read_text())["output_fingerprint"] == "sha256:361e49103b88558ffb9227ee016d1950078f8677fb697ee8524cb1362d5f2244"
assert json.loads((root / "problem-a/run-manifest.json").read_text())["output_fingerprint"] == "sha256:e582bf3bfccf4822c8994b1c8a64e8d3bc1e7e1d700f2cab396fca21df8c610b"
inventory_required = {"delivery_id", "dataset_id", "path", "entry_type", "size_bytes", "sha256", "extension", "detected_format", "encoding_status", "empty", "archive", "duplicate_content_group", "expectation_match", "schema_version", "algorithm_version"}
issue_required = {"issue_id", "issue_category", "code", "severity", "delivery_id", "dataset_id", "path", "line", "member", "field", "expected", "observed", "evidence_fingerprint", "remediation_hint", "algorithm_version", "schema_version"}
for directory in (root / "valid-a", root / "problem-a"):
    assert {path.name for path in directory.iterdir()} == {"file-inventory.jsonl", "issues.jsonl", "audit-summary.json", "run-manifest.json"}
    for path in directory.iterdir():
        for value in lines(path): safe(value)
    for value in lines(directory / "file-inventory.jsonl"): assert set(value) == inventory_required
    for value in lines(directory / "issues.jsonl"): assert set(value) == issue_required
print("valid audit: 8 files, 3 datasets, 0 issues")
print("problem audit: 30 regular files, 32 issues, exact injection-truth match")
PY

python3 scripts/generate_content_fixtures.py --seed 20260822 --output-dir "$verify_tmp/content-a"
python3 scripts/generate_content_fixtures.py --seed 20260822 --reverse-creation --output-dir "$verify_tmp/content-b"
diff -ru "$verify_tmp/content-a" "$verify_tmp/content-b"
diff -ru fixtures/content-generated "$verify_tmp/content-a"
printf 'content fixtures forward/reverse creation and committed bytes are identical\n'

PYTHONPATH=python/src python3 -m unittest discover -s python/tests -p 'test_content.py' -v

run_content_audit() {
  PYTHONPATH=python/src python3 -m dataset_delivery_audit audit-content \
    --root "fixtures/content-generated/$1-delivery" \
    --expectation "fixtures/content-generated/$1-expectation.json" \
    --config configs/content-audit-v1.json \
    --sample-plan configs/content-sample-plan-v1.json \
    --canonical-decisions "fixtures/content-generated/$1-canonical-decisions.jsonl" \
    --quality-scores "fixtures/content-generated/$1-quality-scores.jsonl" \
    --output-dir "$2"
}
run_content_audit valid "$verify_tmp/content-valid-a"
run_content_audit valid "$verify_tmp/content-valid-b"
run_content_audit problem "$verify_tmp/content-problem-a"
run_content_audit problem "$verify_tmp/content-problem-b"
diff -ru "$verify_tmp/content-valid-a" "$verify_tmp/content-valid-b"
diff -ru "$verify_tmp/content-problem-a" "$verify_tmp/content-problem-b"

python3 - "$verify_tmp" <<'PY'
import collections, hashlib, json, pathlib, sys
root = pathlib.Path(sys.argv[1])

def lines(path): return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
def safe(value):
    assert not isinstance(value, float), value
    if isinstance(value, str):
        assert not value.startswith(("/Users/", "/tmp/", "/private/tmp/")), value
        assert "很长很长合成正文" not in value
    elif isinstance(value, list):
        for item in value: safe(item)
    elif isinstance(value, dict):
        assert not set(value) & {"timestamp", "created_at", "run_at", "time", "inode", "username"}
        for item in value.values(): safe(item)

valid = json.loads((root / "content-valid-a/content-summary.json").read_text())
problem = json.loads((root / "content-problem-a/content-summary.json").read_text())
assert valid["population_count"] == valid["sample_count"] == valid["stratum_count"] == 12
assert valid["issue_count"] == 0
assert problem["population_count"] == problem["sample_count"] == 54
assert problem["stratum_count"] == 23 and problem["issue_count"] == 58
assert problem["issues_by_category"] == {"ISS-05": 14, "ISS-06": 11, "ISS-07": 10, "ISS-08": 8, "ISS-09": 15}
assert problem["issues_by_severity"] == {"BLOCKER": 0, "ERROR": 41, "WARNING": 17, "INFO": 0}
assert problem["evidence_reconciliation"] == {"delivered_record_count": 54, "canonical_decision_count": 53, "quality_score_count": 54, "canonical_selected_matched_count": 52, "quality_record_matched_count": 53}
truth = json.loads(pathlib.Path("fixtures/content-generated/injection-truth.json").read_text())["injections"]
issues = lines(root / "content-problem-a/record-issues.jsonl")
truth_key = lambda i: (i["issue_category"], i["code"], i["expected_severity"], i["dataset_id"], i["path"], i["record_id"], i["line"], i["field"], i["reference"], i["expected_evidence_scope"])
issue_key = lambda i: (i["issue_category"], i["code"], i["severity"], i["dataset_id"], i["path"], i["record_id"], i["line"], i["field"], i["reference"], i["evidence_scope"])
assert len(truth) == len(issues) == 58 and {truth_key(i) for i in truth} == {issue_key(i) for i in issues}
assert len({i["injection_id"] for i in truth}) == 58
assert all(collections.Counter(i["issue_category"] for i in truth)[category] >= 8 for category in ("ISS-05", "ISS-06", "ISS-07", "ISS-08", "ISS-09"))
sampling_truth = json.loads(pathlib.Path("fixtures/content-generated/sampling-truth.json").read_text())
for name, expected in (("valid", sampling_truth["valid_population_count"]), ("problem", sampling_truth["problem_population_count"])):
    sampling = json.loads((root / f"content-{name}-a/sampling-manifest.json").read_text())
    assert sampling["population_count"] == sampling["sample_count"] == expected
    assert sum(item["population_count"] for item in sampling["strata"]) == expected
    assert sum(item["sample_count"] for item in sampling["strata"]) == expected
required = set(json.loads(pathlib.Path("contracts/issue-v2.schema.json").read_text())["required"])
for directory in (root / "content-valid-a", root / "content-problem-a"):
    assert {path.name for path in directory.iterdir()} == {"record-issues.jsonl", "sampling-manifest.json", "content-summary.json", "run-manifest.json"}
    for path in directory.iterdir():
        for value in lines(path): safe(value)
    for issue in lines(directory / "record-issues.jsonl"):
        assert set(issue) == required
manifest = json.loads(pathlib.Path("fixtures/content-generated/generation-manifest.json").read_text())
assert manifest["injection_count"] == 58 and manifest["deliveries"]["problem"]["record_count"] == 54
print("valid content audit: 12 records, 12 strata, 0 issues")
print("problem content audit: 54 records, 23 strata, 58 exact injection-truth issues")
print("content evidence reconciliation: 53 canonical decisions, 54 quality scores")
print("content output fingerprints:", json.loads((root / "content-valid-a/run-manifest.json").read_text())["output_fingerprint"], json.loads((root / "content-problem-a/run-manifest.json").read_text())["output_fingerprint"])
PY

check_no_nested_git() {
  local directory="$1" nested
  nested="$(cd "$directory" && find . -path './.git' -prune -o -path './fixtures/generated/problem-delivery/nested/.git' -prune -o -name .git -print -quit)"
  if [ -n "$nested" ]; then printf 'nested .git entry found: %s\n' "$nested" >&2; return 1; fi
}
check_no_nested_git .
test -f fixtures/generated/problem-delivery/nested/.git/config
test ! -e fixtures/generated/problem-delivery/nested/.git/HEAD
test ! -e fixtures/generated/problem-delivery/nested/.git/objects
test ! -e fixtures/generated/problem-delivery/nested/.git/refs
mkdir -p "$verify_tmp/git-probe/.git"
check_no_nested_git "$verify_tmp/git-probe"
mkdir -p "$verify_tmp/git-probe/child/.git"
if check_no_nested_git "$verify_tmp/git-probe" >/dev/null 2>&1; then printf 'child .git probe unexpectedly passed\n' >&2; exit 1; fi
printf 'nested Git probes passed: root .git and one locked non-repository injection allowed; child/.git rejected\n'

if find . -type f -iname 'LICENSE*' -print -quit | grep -q .; then printf 'LICENSE found\n' >&2; exit 1; fi
if rg -n '/Users/[[:alnum:]_.-]+/' . --glob '!rust/target/**' --glob '!**/__pycache__/**' --glob '!**/.pytest_cache/**'; then printf 'absolute user path found\n' >&2; exit 1; fi
if find . -type d \( -name target -o -name __pycache__ -o -name .pytest_cache \) -print -quit | grep -q .; then printf 'cache directory found\n' >&2; exit 1; fi
if find . -type f \( -name '*.pyc' -o -name '.DS_Store' \) -print -quit | grep -q .; then printf 'cache file found\n' >&2; exit 1; fi
secret_paths="$(rg -l '(gh[pousr]_[A-Za-z0-9]{20,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16})' . --glob '!fixtures/generated/**' || true)"
if [ -n "$secret_paths" ]; then printf 'possible credential files:\n%s\n' "$secret_paths" >&2; exit 1; fi
grep -q '^version = "0.2.0"' python/pyproject.toml
grep -q '^version = "0.2.0"' rust/Cargo.toml
grep -q '__version__ = "0.2.0"' python/src/dataset_delivery_audit/__init__.py
check_all_upstreams
printf 'all dataset delivery audit stage-1 and stage-2 verification checks passed\n'

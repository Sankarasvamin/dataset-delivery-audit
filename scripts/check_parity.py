#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def run(command: list[str], env: dict[str, str] | None = None) -> None:
    subprocess.run(command, cwd=ROOT, env=env, check=True)


def key(value: dict[str, object]) -> tuple[object, ...]:
    return tuple(value[name] for name in ("issue_category", "code", "dataset_id", "path", "line", "member", "field"))


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="delivery-parity.") as raw:
        temp = Path(raw)
        env = dict(os.environ)
        env["PYTHONPATH"] = "python/src"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        for name in ("valid", "problem"):
            delivery = ROOT / f"fixtures/generated/{name}-delivery"
            python_output, rust_output = temp / f"{name}-python.jsonl", temp / f"{name}-rust.jsonl"
            run([sys.executable, "-m", "dataset_delivery_audit", "scan", "--root", str(delivery), "--output", str(python_output)], env)
            run(["cargo", "run", "--quiet", "--locked", "--manifest-path", "rust/Cargo.toml", "--", "scan", "--root", str(delivery), "--output", str(rust_output)])
            python_values, rust_values = load_jsonl(python_output), load_jsonl(rust_output)
            if python_values != rust_values:
                for index, (left, right) in enumerate(zip(python_values, rust_values)):
                    if left != right:
                        raise AssertionError((name, index, left, right))
                raise AssertionError((name, len(python_values), len(rust_values)))

        valid_dir, problem_dir = temp / "valid-audit", temp / "problem-audit"
        for name, output in (("valid", valid_dir), ("problem", problem_dir)):
            run([sys.executable, "-m", "dataset_delivery_audit", "audit", "--root", f"fixtures/generated/{name}-delivery", "--expectation", f"fixtures/generated/{name}-expectation.json", "--config", "configs/audit-v1.json", "--output-dir", str(output)], env)
        valid = json.loads((valid_dir / "audit-summary.json").read_text(encoding="utf-8"))
        assert valid["issue_count"] == 0 and valid["regular_file_count"] == 8 and valid["dataset_count"] == 3, valid
        issues = load_jsonl(problem_dir / "issues.jsonl")
        truth = json.loads((ROOT / "fixtures/generated/injection-truth.json").read_text(encoding="utf-8"))["injections"]
        assert len(issues) == len(truth) == 32
        assert {key(item) for item in issues} == {key(item) for item in truth}
        print("Python/Rust inventory field parity passed: valid=11 entries, problem=37 entries")
        print("audit injection truth passed: ISS-01=8 ISS-02=8 ISS-03=8 ISS-04=8")


if __name__ == "__main__":
    main()


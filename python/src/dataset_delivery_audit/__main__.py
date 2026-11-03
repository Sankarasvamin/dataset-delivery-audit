from __future__ import annotations

import argparse
import sys

from .core import AuditError, audit, run_scan
from .content import audit_content


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="dataset-delivery-audit")
    commands = root.add_subparsers(dest="command", required=True)
    scan = commands.add_parser("scan")
    scan.add_argument("--root", required=True)
    scan.add_argument("--output", required=True)
    audit_command = commands.add_parser("audit")
    audit_command.add_argument("--root", required=True)
    audit_command.add_argument("--expectation")
    audit_command.add_argument("--config", required=True)
    audit_command.add_argument("--output-dir", required=True)
    content = commands.add_parser("audit-content")
    content.add_argument("--root", required=True)
    content.add_argument("--expectation", required=True)
    content.add_argument("--config", required=True)
    content.add_argument("--sample-plan", required=True)
    content.add_argument("--canonical-decisions", required=True)
    content.add_argument("--quality-scores", required=True)
    content.add_argument("--output-dir", required=True)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "scan":
            run_scan(args.root, args.output)
        elif args.command == "audit":
            audit(args.root, args.config, args.output_dir, args.expectation)
        else:
            audit_content(args.root, args.expectation, args.config, args.sample_plan, args.canonical_decisions, args.quality_scores, args.output_dir)
        return 0
    except (AuditError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

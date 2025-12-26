import argparse
import json
from pathlib import Path

from aws_audit.checks import run_checks
from aws_audit.report import render_markdown


DEFAULT_OUTDIR = Path(".") / "out"
DEFAULT_SCAN_FILE = DEFAULT_OUTDIR / "scan.json"
DEFAULT_REPORT_FILE = DEFAULT_OUTDIR / "report.md"


def cmd_scan(args: argparse.Namespace) -> int:
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    results = run_checks(profile=args.profile, region=args.region)

    out_path = Path(args.out) if args.out else (outdir / "scan.json")
    out_path.write_text(
    json.dumps(results, indent=2, ensure_ascii=False, default=str),
    encoding="utf-8",
)


    print(f"[OK] Scan written to: {out_path}")
    # show a short summary
    summary = results.get("summary", {})
    print(f"     PASS={summary.get('pass', 0)} WARN={summary.get('warn', 0)} FAIL={summary.get('fail', 0)}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    scan_path = Path(args.scan)
    if not scan_path.exists():
        print(f"[ERROR] Scan file not found: {scan_path}")
        return 2

    data = json.loads(scan_path.read_text(encoding="utf-8"))

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    fmt = args.format.lower().strip()
    if fmt != "markdown":
        print("[ERROR] Only --format markdown is supported right now.")
        return 2

    md = render_markdown(data)

    out_path = Path(args.out) if args.out else (outdir / "report.md")
    out_path.write_text(md, encoding="utf-8")
    print(f"[OK] Report written to: {out_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aws_audit", description="AWS Security Baseline Audit CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    scan = sub.add_parser("scan", help="Run checks and write scan.json")
    scan.add_argument("--profile", required=True, help="AWS CLI profile (SSO), e.g. cann65-adminaccess")
    scan.add_argument("--region", required=True, help="AWS region, e.g. eu-central-1")
    scan.add_argument("--outdir", default=str(DEFAULT_OUTDIR), help="Output directory (default: ./out)")
    scan.add_argument("--out", default="", help="Optional output file path (default: ./out/scan.json)")
    scan.set_defaults(func=cmd_scan)

    rep = sub.add_parser("report", help="Generate a report from scan.json")
    rep.add_argument("--scan", default=str(DEFAULT_SCAN_FILE), help="Path to scan.json (default: ./out/scan.json)")
    rep.add_argument("--format", default="markdown", help="Report format (markdown)")
    rep.add_argument("--outdir", default=str(DEFAULT_OUTDIR), help="Output directory (default: ./out)")
    rep.add_argument("--out", default="", help="Optional output file path (default: ./out/report.md)")
    rep.set_defaults(func=cmd_report)

    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    return int(args.func(args))

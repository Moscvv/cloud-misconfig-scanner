#!/usr/bin/env python3
"""
Cloud Misconfiguration Scanner
Audits an AWS account for common security misconfigurations.
"""

import argparse
import json
import sys
from datetime import datetime

import boto3
from botocore.exceptions import NoCredentialsError, ClientError

from scanners.s3_scanner import scan_s3
from scanners.sg_scanner import scan_security_groups
from scanners.iam_scanner import scan_iam
from scanners.report import generate_report


BANNER = """
╔═══════════════════════════════════════════════╗
║       Cloud Misconfiguration Scanner          ║
║       AWS Security Audit Tool                 ║
╚═══════════════════════════════════════════════╝
"""


def get_account_info(session):
    sts = session.client("sts")
    identity = sts.get_caller_identity()
    return {
        "account_id": identity["Account"],
        "arn": identity["Arn"],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Scan an AWS account for common misconfigurations."
    )
    parser.add_argument(
        "--region",
        default="ap-northeast-1",
        help="AWS region to scan (default: ap-northeast-1)",
    )
    parser.add_argument(
        "--output",
        choices=["terminal", "json", "html"],
        default="terminal",
        help="Output format (default: terminal)",
    )
    parser.add_argument(
        "--checks",
        nargs="+",
        choices=["s3", "sg", "iam", "all"],
        default=["all"],
        help="Which checks to run (default: all)",
    )
    args = parser.parse_args()

    print(BANNER)

    # Validate AWS credentials
    try:
        session = boto3.Session(region_name=args.region)
        account = get_account_info(session)
    except NoCredentialsError:
        print("[ERROR] No AWS credentials found. Run 'aws configure' first.")
        sys.exit(1)
    except ClientError as e:
        print(f"[ERROR] Could not connect to AWS: {e}")
        sys.exit(1)

    print(f"  Account : {account['account_id']}")
    print(f"  Identity: {account['arn']}")
    print(f"  Region  : {args.region}")
    print(f"  Started : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print()

    run_all = "all" in args.checks
    findings = []

    # --- S3 ---
    if run_all or "s3" in args.checks:
        print("─" * 48)
        print("  [1/3] Scanning S3 Buckets...")
        print("─" * 48)
        s3_findings = scan_s3(session)
        findings.extend(s3_findings)
        _print_findings(s3_findings)

    # --- Security Groups ---
    if run_all or "sg" in args.checks:
        print("─" * 48)
        print("  [2/3] Scanning Security Groups...")
        print("─" * 48)
        sg_findings = scan_security_groups(session)
        findings.extend(sg_findings)
        _print_findings(sg_findings)

    # --- IAM ---
    if run_all or "iam" in args.checks:
        print("─" * 48)
        print("  [3/3] Scanning IAM Policies...")
        print("─" * 48)
        iam_findings = scan_iam(session)
        findings.extend(iam_findings)
        _print_findings(iam_findings)

    # --- Summary ---
    print()
    print("═" * 48)
    _print_summary(findings)
    print("═" * 48)

    # --- Output ---
    if args.output in ("json", "html"):
        generate_report(findings, account, args.region, args.output)


def _print_findings(findings):
    if not findings:
        print("  ✅  No issues found.\n")
        return
    for f in findings:
        icon = "🔴" if f["severity"] == "HIGH" else "🟡"
        print(f"  {icon}  [{f['severity']}] {f['resource']}")
        print(f"       {f['issue']}")
        if f.get("detail"):
            print(f"       → {f['detail']}")
        print()


def _print_summary(findings):
    high = sum(1 for f in findings if f["severity"] == "HIGH")
    medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
    total = len(findings)
    print(f"  TOTAL FINDINGS : {total}")
    print(f"  🔴 HIGH        : {high}")
    print(f"  🟡 MEDIUM      : {medium}")


if __name__ == "__main__":
    main()

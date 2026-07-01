"""
S3 Scanner — checks for:
  - Buckets with public bucket policies (Principal: *)
  - Buckets missing Block Public Access settings
  - Buckets without versioning enabled
"""

import json
from botocore.exceptions import ClientError


def scan_s3(session):
    findings = []
    s3 = session.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        print(f"  [WARN] Could not list S3 buckets: {e}")
        return findings

    if not buckets:
        print("  No S3 buckets found in this account.")
        return findings

    print(f"  Found {len(buckets)} bucket(s). Checking each...\n")

    for bucket in buckets:
        name = bucket["Name"]

        # Check 1: Block Public Access settings
        try:
            bpa = s3.get_public_access_block(Bucket=name)
            config = bpa["PublicAccessBlockConfiguration"]
            if not all(config.values()):
                disabled = [k for k, v in config.items() if not v]
                findings.append({
                    "check": "s3_public_access_block",
                    "severity": "HIGH",
                    "resource": f"s3://{name}",
                    "issue": "Block Public Access is not fully enabled",
                    "detail": f"Disabled settings: {', '.join(disabled)}",
                })
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                findings.append({
                    "check": "s3_public_access_block",
                    "severity": "HIGH",
                    "resource": f"s3://{name}",
                    "issue": "No Block Public Access configuration found (all settings are OFF)",
                    "detail": "Bucket has no public access block — policy or ACL could expose it publicly",
                })

        # Check 2: Bucket policy allowing public access
        try:
            policy_str = s3.get_bucket_policy(Bucket=name)["Policy"]
            policy = json.loads(policy_str)
            for stmt in policy.get("Statement", []):
                principal = stmt.get("Principal", "")
                effect = stmt.get("Effect", "")
                if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                    actions = stmt.get("Action", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    findings.append({
                        "check": "s3_public_policy",
                        "severity": "HIGH",
                        "resource": f"s3://{name}",
                        "issue": "Bucket policy allows public access (Principal: *)",
                        "detail": f"Actions exposed: {', '.join(actions)}",
                    })
        except ClientError as e:
            if e.response["Error"]["Code"] != "NoSuchBucketPolicy":
                print(f"  [WARN] Could not read policy for {name}: {e}")

        # Check 3: Versioning not enabled
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            status = versioning.get("Status", "Disabled")
            if status != "Enabled":
                findings.append({
                    "check": "s3_versioning",
                    "severity": "MEDIUM",
                    "resource": f"s3://{name}",
                    "issue": "Bucket versioning is not enabled",
                    "detail": "Without versioning, deleted or overwritten objects cannot be recovered",
                })
        except ClientError as e:
            print(f"  [WARN] Could not check versioning for {name}: {e}")

    return findings

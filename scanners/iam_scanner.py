"""
IAM Scanner — checks for:
  - Customer-managed policies with wildcard Action + Resource (Action: *, Resource: *)
  - IAM users without MFA enabled
  - IAM users with access keys older than 90 days
"""

import json
from datetime import datetime, timezone
from botocore.exceptions import ClientError


def scan_iam(session):
    findings = []
    iam = session.client("iam")

    # Check 1: Wildcard policies
    findings.extend(_check_wildcard_policies(iam))

    # Check 2: Users without MFA
    findings.extend(_check_mfa(iam))

    # Check 3: Old access keys
    findings.extend(_check_old_access_keys(iam))

    return findings


def _check_wildcard_policies(iam):
    findings = []
    try:
        paginator = iam.get_paginator("list_policies")
        # Scope=Local = customer-managed only (not AWS managed)
        pages = paginator.paginate(Scope="Local")
        policies = [p for page in pages for p in page["Policies"]]
    except ClientError as e:
        print(f"  [WARN] Could not list IAM policies: {e}")
        return findings

    print(f"  Found {len(policies)} customer-managed policy/policies. Checking...\n")

    for policy in policies:
        arn = policy["Arn"]
        name = policy["PolicyName"]
        version_id = policy["DefaultVersionId"]

        try:
            version = iam.get_policy_version(
                PolicyArn=arn, VersionId=version_id
            )
            document = version["PolicyVersion"]["Document"]

            # document may be pre-decoded or a string
            if isinstance(document, str):
                document = json.loads(document)

            for stmt in document.get("Statement", []):
                effect = stmt.get("Effect", "")
                actions = stmt.get("Action", [])
                resources = stmt.get("Resource", [])

                if isinstance(actions, str):
                    actions = [actions]
                if isinstance(resources, str):
                    resources = [resources]

                if effect == "Allow" and "*" in actions and "*" in resources:
                    findings.append({
                        "check": "iam_wildcard_policy",
                        "severity": "HIGH",
                        "resource": f"policy/{name}",
                        "issue": "Policy grants Action:* on Resource:* (full admin wildcard)",
                        "detail": f"ARN: {arn}",
                    })
        except ClientError as e:
            print(f"  [WARN] Could not read policy version for {name}: {e}")

    return findings


def _check_mfa(iam):
    findings = []
    try:
        paginator = iam.get_paginator("list_users")
        users = [u for page in paginator.paginate() for u in page["Users"]]
    except ClientError as e:
        print(f"  [WARN] Could not list IAM users: {e}")
        return findings

    for user in users:
        username = user["UserName"]
        try:
            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
            if not mfa_devices:
                findings.append({
                    "check": "iam_no_mfa",
                    "severity": "HIGH",
                    "resource": f"iam/user/{username}",
                    "issue": "IAM user has no MFA device configured",
                    "detail": "Accounts without MFA are vulnerable to credential stuffing attacks",
                })
        except ClientError as e:
            print(f"  [WARN] Could not check MFA for {username}: {e}")

    return findings


def _check_old_access_keys(iam):
    findings = []
    MAX_KEY_AGE_DAYS = 90

    try:
        paginator = iam.get_paginator("list_users")
        users = [u for page in paginator.paginate() for u in page["Users"]]
    except ClientError as e:
        print(f"  [WARN] Could not list IAM users for key age check: {e}")
        return findings

    now = datetime.now(timezone.utc)

    for user in users:
        username = user["UserName"]
        try:
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
            for key in keys:
                created = key["CreateDate"]
                age_days = (now - created).days
                if age_days > MAX_KEY_AGE_DAYS:
                    findings.append({
                        "check": "iam_old_access_key",
                        "severity": "MEDIUM",
                        "resource": f"iam/user/{username}",
                        "issue": f"Access key is {age_days} days old (limit: {MAX_KEY_AGE_DAYS} days)",
                        "detail": f"Key ID: {key['AccessKeyId']} | Status: {key['Status']}",
                    })
        except ClientError as e:
            print(f"  [WARN] Could not check access keys for {username}: {e}")

    return findings


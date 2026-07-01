"""
Security Group Scanner — checks for:
  - Inbound rules open to 0.0.0.0/0 or ::/0 on sensitive ports
  - Security groups with ALL traffic allowed from anywhere
"""

from botocore.exceptions import ClientError

# Ports considered sensitive — open to the world is a finding
SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    6379: "Redis",
    27017: "MongoDB",
    9200: "Elasticsearch",
}

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def scan_security_groups(session):
    findings = []
    ec2 = session.client("ec2")

    try:
        paginator = ec2.get_paginator("describe_security_groups")
        pages = paginator.paginate()
        groups = [sg for page in pages for sg in page["SecurityGroups"]]
    except ClientError as e:
        print(f"  [WARN] Could not list security groups: {e}")
        return findings

    if not groups:
        print("  No security groups found.")
        return findings

    print(f"  Found {len(groups)} security group(s). Checking each...\n")

    for sg in groups:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", "unnamed")
        label = f"{sg_id} ({sg_name})"

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)
            protocol = rule.get("IpProtocol", "-1")

            # Collect open CIDRs
            open_ranges = []
            for ip_range in rule.get("IpRanges", []):
                if ip_range.get("CidrIp") in OPEN_CIDRS:
                    open_ranges.append(ip_range["CidrIp"])
            for ip_range in rule.get("Ipv6Ranges", []):
                if ip_range.get("CidrIpv6") in OPEN_CIDRS:
                    open_ranges.append(ip_range["CidrIpv6"])

            if not open_ranges:
                continue

            # All traffic open
            if protocol == "-1":
                findings.append({
                    "check": "sg_all_traffic_open",
                    "severity": "HIGH",
                    "resource": label,
                    "issue": "Security group allows ALL inbound traffic from the internet",
                    "detail": f"CIDRs: {', '.join(open_ranges)}",
                })
                continue

            # Check sensitive port ranges
            for port, service in SENSITIVE_PORTS.items():
                if from_port <= port <= to_port:
                    findings.append({
                        "check": "sg_sensitive_port_open",
                        "severity": "HIGH",
                        "resource": label,
                        "issue": f"Port {port} ({service}) is open to the internet",
                        "detail": f"CIDRs: {', '.join(open_ranges)} | Rule: {from_port}-{to_port}/{protocol}",
                    })

    return findings

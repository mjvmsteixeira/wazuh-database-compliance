#!/usr/bin/env python3
"""
TheHive SOAR Integration — Database Audit Alerts
Wazuh 4.14.4 | Database Activity Monitoring

Referência: Wazuh custom integrations documentation
  https://documentation.wazuh.com/current/user-manual/manager/manual-integration.html

Referências regulatórias:
  - RGPD Art. 33: Notificação de violação de dados à autoridade de controlo
  - NIS2 Art. 23: Obrigações de notificação de incidentes
  - PCI-DSS 12.10: Plano de resposta a incidentes

Configuração no ossec.conf do Manager:
  <integration>
    <name>custom-thehive.py</name>
    <hook_url>http://thehive:9000</hook_url>
    <api_key>/var/ossec/etc/thehive-token</api_key>
    <rule_id>100202,100203,100212,100213,100220,100231,100233,100235,100271,100272,100273,100274</rule_id>
    <alert_format>json</alert_format>
  </integration>
"""

import json
import os
import sys
import urllib.request
import urllib.error

THEHIVE_URL = os.environ.get("THEHIVE_URL", "http://thehive:9000")
TOKEN_PATH = "/var/ossec/etc/thehive-token"

DB_RULE_IDS = {
    100202, 100203, 100212, 100213, 100220,
    100231, 100233, 100235,
    100271, 100272, 100273, 100274,
}

SEVERITY_MAP = {
    range(0, 4): 1,    # Low
    range(4, 8): 2,    # Medium
    range(8, 12): 3,   # High
    range(12, 16): 4,  # Critical
}

TAGS = ["database", "wazuh", "compliance", "rgpd", "nis2"]


def read_token():
    try:
        with open(TOKEN_PATH, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        print(f"ERROR: Token file not found: {TOKEN_PATH}", file=sys.stderr)
        sys.exit(1)
    except PermissionError:
        print(f"ERROR: Cannot read token file: {TOKEN_PATH}", file=sys.stderr)
        sys.exit(1)


def get_severity(level):
    for level_range, severity in SEVERITY_MAP.items():
        if level in level_range:
            return severity
    return 2


def create_case(alert):
    token = read_token()
    rule = alert.get("rule", {})
    rule_id = rule.get("id", "unknown")
    level = rule.get("level", 5)
    description = rule.get("description", "No description")
    agent = alert.get("agent", {})
    agent_name = agent.get("name", "unknown")

    case = {
        "title": f"[DB AUDIT] {description}",
        "description": (
            f"**Wazuh Alert — Database Activity Monitoring**\n\n"
            f"- **Rule ID:** {rule_id}\n"
            f"- **Level:** {level}\n"
            f"- **Agent:** {agent_name} ({agent.get('id', 'N/A')})\n"
            f"- **Description:** {description}\n"
            f"- **Groups:** {', '.join(rule.get('groups', []))}\n"
            f"- **Full alert:** ```{json.dumps(alert, indent=2)}```"
        ),
        "severity": get_severity(level),
        "tags": TAGS + [f"rule:{rule_id}", f"agent:{agent_name}"],
        "flag": level >= 10,
        "tlp": 3,
        "pap": 2,
    }

    data = json.dumps(case).encode("utf-8")
    req = urllib.request.Request(
        f"{THEHIVE_URL}/api/case",
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            result = json.loads(resp.read())
            print(f"Case created: {result.get('id', 'unknown')}")
    except urllib.error.HTTPError as e:
        print(f"ERROR: TheHive API returned {e.code}: {e.read().decode()}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"ERROR: Cannot connect to TheHive at {THEHIVE_URL}: {e.reason}", file=sys.stderr)
        sys.exit(1)


def main():
    if len(sys.argv) < 2:
        print("ERROR: No alert file path provided", file=sys.stderr)
        sys.exit(1)

    alert_file = sys.argv[1]

    try:
        with open(alert_file, "r") as f:
            alert = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"ERROR: Cannot read alert file {alert_file}: {e}", file=sys.stderr)
        sys.exit(1)

    rule_id = int(alert.get("rule", {}).get("id", 0))
    if rule_id not in DB_RULE_IDS:
        sys.exit(0)

    create_case(alert)


if __name__ == "__main__":
    main()

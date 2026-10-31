"""Map Wazuh alerts.json lines to the lab schema and print rule-engine verdicts.

    python scripts/wazuh_tail.py data/sample/wazuh_alerts.json
    python scripts/wazuh_tail.py /var/ossec/logs/alerts/alerts.json     # on a Wazuh manager

Only the fields the rules need are mapped; everything else stays in `msg`.
`count` comes from Wazuh's `previous_output` (the earlier events a frequency rule
grouped), which is how rule 5712 "sshd brute force" carries its evidence.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from triage import rules  # noqa: E402

GROUP_TO_EVENT = {"authentication_failed": "auth_fail", "authentication_failures": "auth_fail",
                  "authentication_success": "auth_success", "smb": "smb_session"}


def _int(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def to_alert(w: dict) -> dict:
    data, rule, agent = w.get("data") or {}, w.get("rule") or {}, w.get("agent") or {}
    groups = rule.get("groups") or []
    ts = str(w.get("timestamp") or "")
    event_type = next((GROUP_TO_EVENT[g] for g in groups if g in GROUP_TO_EVENT), groups[0] if groups else "unknown")
    return {
        "id": str(w.get("id") or ""), "ts": ts, "source": "wazuh", "event_type": event_type,
        "host": str(agent.get("name") or ""), "src_ip": str(data.get("srcip") or ""), "dst_ip": str(agent.get("ip") or ""),
        "dst_port": _int(data.get("dstport"), 22 if "sshd" in groups else 0), "proto": "tcp",
        "user": str(data.get("srcuser") or data.get("dstuser") or ""),
        "count": 1 + len([l for l in (w.get("previous_output") or "").splitlines() if l.strip()]),
        "window_s": 120, "unique_dst_ports": 0, "bytes_out": 0, "interval_std_s": 0.0,
        "dns_qname": "", "dns_qname_len": 0, "dns_entropy": 0.0, "dst_domain": "", "share": "",
        "hour": _int(ts[11:13]), "msg": str(w.get("full_log") or rule.get("description") or ""),
        "wazuh_rule": str(rule.get("id") or ""), "wazuh_mitre": (rule.get("mitre") or {}).get("id") or [],
    }


def main(path: str) -> None:
    rs = rules.load_rules(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules"))
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                w = json.loads(line)
                if not isinstance(w, dict):
                    raise ValueError("line is not a JSON object")
                a = to_alert(w)
                v = rules.triage(a, rs)
            except Exception as e:  # one bad line must not stop the tail
                print(f"skip line {n}: {type(e).__name__}: {e}")
                continue
            print(f"{a['ts'][:19]:19} {a['host']:12} wazuh {a['wazuh_rule']:>5} {str(a['wazuh_mitre']):14} -> "
                  f"{v.category:15} {v.severity:8} {v.technique:10} {'REVIEW' if v.malicious else 'close'}  {v.reason}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join("data", "sample", "wazuh_alerts.json"))

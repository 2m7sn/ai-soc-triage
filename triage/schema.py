"""Shared vocabulary: alert categories, ATT&CK mapping, severities, L1 actions.

Technique IDs checked against MITRE ATT&CK Enterprise v20.0 (attack.mitre.org, 2026-10-30).
"""
from dataclasses import dataclass, asdict

# category -> MITRE ATT&CK technique. "benign" has no technique.
TECHNIQUE = {
    "port_scan": "T1046",
    "ssh_bruteforce": "T1110.001",
    "beaconing": "T1071.001",
    "dns_tunnel": "T1071.004",
    "lateral_smb": "T1021.002",
    "benign": "-",
}
CATEGORIES = list(TECHNIQUE)

SEVERITY = {
    "port_scan": "medium",
    "ssh_bruteforce": "high",
    "beaconing": "critical",
    "dns_tunnel": "high",
    "lateral_smb": "critical",
    "benign": "info",
}

ACTION = {
    "port_scan": "Block source at perimeter if external; if internal, open ticket to host owner and check for prior compromise.",
    "ssh_bruteforce": "Check for a successful login after the failures; if found, isolate host and reset the account. Else block source IP.",
    "beaconing": "Isolate host, pull process list and network connections, submit destination to threat intel, escalate to L2.",
    "dns_tunnel": "Block the domain at the resolver, isolate the host, capture DNS queries for L2, escalate.",
    "lateral_smb": "Isolate source host, disable the account used, check destination for new services/scheduled tasks, escalate to L2 immediately.",
    "benign": "Close as benign. No action.",
}


@dataclass
class Verdict:
    category: str
    malicious: bool
    severity: str
    technique: str
    action: str
    engine: str
    needs_review: bool = False  # analyst must look regardless of malicious flag
    reason: str = ""

    def to_dict(self):
        return asdict(self)


def verdict_for(category: str, engine: str, reason: str = "", needs_review: bool = False) -> Verdict:
    """Build a Verdict from a category using the fixed maps above."""
    if category not in TECHNIQUE:
        category = "benign"
        needs_review = True
        reason = (reason + " | unknown category -> needs_review").strip(" |")
    return Verdict(
        category=category,
        malicious=category != "benign",
        severity=SEVERITY[category],
        technique=TECHNIQUE[category],
        action=ACTION[category],
        engine=engine,
        needs_review=needs_review,
        reason=reason,
    )

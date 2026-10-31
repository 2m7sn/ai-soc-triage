"""Rule-based baseline: Sigma-like YAML rules evaluated against flat alert dicts.

Rule format (rules/*.yml):
    id, title, category, detection:
      all:  [ {field, op: value}, ... ]   # every condition must hold
      none: [ {field, op: value}, ... ]   # no condition may hold (allowlists)
Ops: eq, ne, in, gte, lte, contains, endswith, empty (bool).
"""
import glob
import os
import yaml

from .schema import Verdict, verdict_for

OPS = {
    "eq": lambda v, x: v == x,
    "ne": lambda v, x: v != x,
    "in": lambda v, x: v in x,
    "gte": lambda v, x: v >= x,
    "lte": lambda v, x: v <= x,
    "contains": lambda v, x: str(x).lower() in str(v).lower(),
    "endswith": lambda v, x: any(str(v).lower().endswith(s.lower()) for s in (x if isinstance(x, list) else [x])),
    "empty": lambda v, x: (v in ("", 0, None, [])) == x,
}


def load_rules(path: str) -> list[dict]:
    rules = []
    for f in sorted(glob.glob(os.path.join(path, "*.yml"))):
        with open(f, encoding="utf-8") as fh:
            rules.append(yaml.safe_load(fh))
    return rules


def _cond(alert: dict, c: dict) -> bool:
    field = c["field"]
    for op, fn in OPS.items():
        if op in c:
            return fn(alert.get(field), c[op])
    raise ValueError(f"no operator in condition {c}")


def match(rule: dict, alert: dict) -> bool:
    det = rule["detection"]
    return all(_cond(alert, c) for c in det.get("all", [])) and not any(_cond(alert, c) for c in det.get("none", []))


def triage(alert: dict, rules: list[dict]) -> Verdict:
    for r in rules:  # first match wins; rules are ordered by filename
        if match(r, alert):
            return verdict_for(r["category"], "rules", reason=f"{r['id']} {r['title']}")
    return verdict_for("benign", "rules", reason="no rule matched")

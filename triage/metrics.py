"""Evaluation against ground truth. `flagged` = malicious or needs_review (what an L1 must open)."""
from .schema import CATEGORIES, Verdict


def evaluate(alerts: list[dict], verdicts: list[Verdict], seconds: float) -> dict:
    assert len(alerts) == len(verdicts)
    tp = fp = fn = tn = 0
    technique_hits = 0
    missed_injected = 0
    cols = CATEGORIES + ["needs_review"]
    confusion = {t: {p: 0 for p in cols} for t in CATEGORIES}
    for a, v in zip(alerts, verdicts):
        truth = a["label"]
        flagged = v.malicious or v.needs_review
        if truth["malicious"] and flagged:
            tp += 1
            technique_hits += v.technique == truth["technique"]
        elif truth["malicious"]:
            fn += 1
            missed_injected += bool(truth.get("injected"))
        elif flagged:
            fp += 1
        else:
            tn += 1
        confusion[truth["category"]]["needs_review" if v.needs_review else v.category] += 1
    pos, neg, n = tp + fn, fp + tn, len(alerts)
    injected = sum(bool(a["label"].get("injected")) for a in alerts)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / pos if pos else 0.0
    return {
        "n": n, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(2 * precision * recall / (precision + recall), 4) if precision + recall else 0.0,
        "fpr": round(fp / neg, 4) if neg else 0.0,
        "attack_mapping_acc": round(technique_hits / tp, 4) if tp else 0.0,  # among true positives
        "mean_ms_per_alert": round(1000 * seconds / n, 3) if n else 0.0,
        "workload": tp + fp,                 # alerts an L1 still has to open
        "workload_pct": round(100 * (tp + fp) / n, 1) if n else 0.0,
        "missed_attacks": fn,
        "injected": injected,
        "missed_injected": missed_injected,
        # share of injected (attacker-text) alerts the engine let through as benign
        "injection_success_rate": round(missed_injected / injected, 4) if injected else 0.0,
        "confusion": confusion,
    }

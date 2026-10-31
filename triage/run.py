"""End-to-end run: load alerts -> split -> triage with each engine -> evaluate -> report.

    python -m triage.run                       # rules + ML on data/sample/alerts.jsonl
    python -m triage.run --llm --llm-limit 100 # also run the LLM engine if a key is set
"""
import argparse
import json
import os
import random
import time
from datetime import datetime, timezone

from . import llm, metrics, ml, report, rules

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def split(alerts, test_frac, seed):
    """Stratified by category so every attack type appears in both halves."""
    rng = random.Random(seed)
    by_cat = {}
    for a in alerts:
        by_cat.setdefault(a["label"]["category"], []).append(a)
    train, test = [], []
    for items in by_cat.values():
        rng.shuffle(items)
        k = int(len(items) * test_frac)
        test += items[:k]
        train += items[k:]
    return train, test


def timed(fn, *args):
    t = time.perf_counter()
    out = fn(*args)
    return out, time.perf_counter() - t


def run(data, out_dir, rules_dir, use_llm=False, llm_limit=100, seed=0, test_frac=0.3):
    alerts = load(data)
    train, test = split(alerts, test_frac, seed)
    results, verdicts = {}, {}

    rs = rules.load_rules(rules_dir)
    verdicts["rules"], dt = timed(lambda: [rules.triage(a, rs) for a in test])
    results["rules"] = metrics.evaluate(test, verdicts["rules"], dt)

    model = ml.train(train, seed)
    verdicts["ml"], dt = timed(ml.triage_many, model, test)
    results["ml"] = metrics.evaluate(test, verdicts["ml"], dt)

    notes = [
        "Data is SYNTHETIC (triage/generate.py): Wazuh/Suricata-style alerts with ground-truth labels. Numbers show engine behaviour on this generator, not on a real network.",
        f"Same stratified {int(test_frac*100)}% test split for every engine ({len(test)} alerts). ML trained on the other {len(train)}. Rules and LLM need no training.",
        "ATT&CK mapping accuracy is measured among true positives only. Workload = alerts flagged malicious or needs_review.",
    ]
    call = llm.client_from_env() if use_llm else None
    if use_llm and call is None:
        notes.append("LLM engine requested but no ANTHROPIC_API_KEY / OPENAI_API_KEY was set: not run, no numbers reported.")
    elif call is None:
        notes.append("LLM engine not run (pass --llm with an API key). No LLM numbers are reported because none were measured.")
    else:
        sub = test[:llm_limit]
        verdicts["llm"], dt = timed(lambda: [llm.triage(a, call) for a in sub])
        results["llm"] = metrics.evaluate(sub, verdicts["llm"], dt)
        notes.append(f"LLM engine ran on the first {len(sub)} test alerts only (cost cap --llm-limit).")

    rows = []
    for name, vs in verdicts.items():
        for a, v in zip(test, vs):
            rows.append({"alert_id": a["id"], "ts": a["ts"], "host": a["host"], "src_ip": a["src_ip"], "engine": name, "truth_category": a["label"]["category"],
                         "truth_malicious": a["label"]["malicious"], "injected": bool(a["label"].get("injected")),
                         **{k: val for k, val in v.to_dict().items() if k not in ("action", "engine")}})
    meta = {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "data": (os.path.relpath(data, HERE) if data.startswith(HERE) else data).replace("\\", "/"),
            "n_total": len(alerts), "n_train": len(train), "n_test": len(test), "seed": seed, "synthetic": True,
            "subtitle": f"Rule-based vs ML vs LLM triage on {len(test)} labelled test alerts (synthetic data)", "notes": notes}
    report.write_all(out_dir, results, rows, meta)
    return results, meta


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data", default=os.path.join(HERE, "data", "sample", "alerts.jsonl"))
    p.add_argument("--out", default=os.path.join(HERE, "reports"))
    p.add_argument("--rules", default=os.path.join(HERE, "rules"))
    p.add_argument("--llm", action="store_true", help="run the LLM engine if an API key is set")
    p.add_argument("--llm-limit", type=int, default=100, help="max alerts sent to the LLM (cost cap)")
    p.add_argument("--seed", type=int, default=0)
    a = p.parse_args()
    results, meta = run(a.data, a.out, a.rules, a.llm, a.llm_limit, a.seed)
    print(f"{'engine':8} {'prec':>6} {'rec':>6} {'f1':>6} {'fpr':>6} {'attck':>6} {'ms':>8} {'work':>6} {'miss':>5}")
    for name, m in results.items():
        print(f"{name:8} {m['precision']:6.3f} {m['recall']:6.3f} {m['f1']:6.3f} {m['fpr']:6.3f} {m['attack_mapping_acc']:6.3f} {m['mean_ms_per_alert']:8.3f} {m['workload']:6d} {m['missed_attacks']:5d}")
    print(f"report: {os.path.join(a.out, 'report.html')}")


if __name__ == "__main__":
    main()

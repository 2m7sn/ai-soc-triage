"""Classic ML triage: one multiclass RandomForest over the alert category."""
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.pipeline import Pipeline

from .schema import Verdict, verdict_for

NUMERIC = ["dst_port", "count", "window_s", "unique_dst_ports", "bytes_out", "interval_std_s", "dns_qname_len", "dns_entropy", "hour"]
CATEGORICAL = ["event_type", "proto", "share", "src_ip", "user", "dst_domain"]


def featurize(a: dict) -> dict:
    f = {k: float(a.get(k) or 0) for k in NUMERIC}
    f.update({k: str(a.get(k) or "") for k in CATEGORICAL})
    f["user"] = f["user"].split()[0] if f["user"].split() else ""  # first token only: injected text appended to a username must not become a label leak
    # ponytail: src_ip as a category memorises fixed IPs (scanners, jump hosts); that is the intended "learn the allowlist" effect and will not generalise to new IPs
    f["src_internal"] = float(str(a.get("src_ip", "")).startswith("10."))
    f["dst_internal"] = float(str(a.get("dst_ip", "")).startswith("10."))
    # ponytail: no free-text tokens from `msg`; it is attacker-controlled and would let the model learn the label from the message string
    return f


def train(alerts: list[dict], seed: int = 0) -> Pipeline:
    model = Pipeline([("vec", DictVectorizer()), ("clf", RandomForestClassifier(n_estimators=200, random_state=seed, n_jobs=-1))])
    model.fit([featurize(a) for a in alerts], [a["label"]["category"] for a in alerts])
    return model


def triage_many(model: Pipeline, alerts: list[dict]) -> list[Verdict]:
    preds = model.predict([featurize(a) for a in alerts])
    probs = model.predict_proba([featurize(a) for a in alerts]).max(axis=1)
    return [verdict_for(p, "ml", reason=f"RandomForest p={pr:.2f}") for p, pr in zip(preds, probs)]

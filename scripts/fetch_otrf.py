"""Fetch a real, MIT-licensed OTRF Security-Datasets atomic dataset into data/raw (gitignored).

Source: https://github.com/OTRF/Security-Datasets (LICENSE: MIT, checked 2026-10-30).
Each dataset is one adversary technique run in a lab, shipped as a zip of JSON event
logs plus a metadata YAML whose `attack_mappings` give the ATT&CK technique.

    python scripts/fetch_otrf.py SDWIN-190301174830      # Empire DCSync, T1003.006
    python scripts/fetch_otrf.py SDLIN-201110074812      # arp cache discovery, T1018

Note: labels are per DATASET, not per event. Most events in a capture are normal
system noise around the technique, so these files are not yet per-alert ground
truth for the pipeline. See README -> Roadmap.
"""
import io
import json
import os
import sys
import urllib.request
import zipfile

import yaml

RAW = "https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/_metadata/{}.yaml"
OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "raw", "otrf")


def fetch(dataset_id: str) -> None:
    meta = yaml.safe_load(urllib.request.urlopen(RAW.format(dataset_id), timeout=60).read())
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, f"{dataset_id}.yaml"), "w", encoding="utf-8") as f:
        yaml.safe_dump(meta, f, sort_keys=False)
    mappings = ", ".join(f"T{m['technique'][1:]}" + (f".{m['sub-technique']}" if m.get("sub-technique") else "") for m in meta["attack_mappings"])
    print(f"{meta['id']}  {meta['title']}  ATT&CK: {mappings}")
    for file in meta["files"]:
        if file["type"] != "Host":
            continue
        data = urllib.request.urlopen(file["link"], timeout=120).read()
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            z.extractall(os.path.join(OUT, dataset_id))
            for name in z.namelist():
                with z.open(name) as fh:
                    n = sum(1 for line in fh if line.strip())
                print(f"  {name}: {len(data)//1024} KB zip, {n} JSON events -> {os.path.join(OUT, dataset_id, name)}")


if __name__ == "__main__":
    for ds in sys.argv[1:] or ["SDWIN-190301174830"]:
        fetch(ds)

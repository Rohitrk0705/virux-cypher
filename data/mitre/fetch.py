"""Download MITRE ATT&CK (Enterprise, STIX 2.1) and extract what we use.

  python data/mitre/fetch.py [--offline]

Writes:
  raw/enterprise-attack.json  - the full STIX bundle (large, gitignored)
  techniques.json             - {technique_id: {id, name, tactics, description,
                                 is_subtechnique, parent}}
  groups.json                 - [{group_id, name, techniques: [ids]}], the
                                 techniques each ATT&CK Group is reported to use
  tactics.json                - tactics in kill-chain (matrix) order
  revoked.json                - {revoked technique id: replacement id}
  VERSION                     - ATT&CK version and extraction counts

Revoked and deprecated objects are dropped. --offline re-extracts from an
already downloaded bundle.
"""

import argparse
import json
import ssl
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
RAW = HERE / "raw" / "enterprise-attack.json"
URL = ("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
       "master/enterprise-attack/enterprise-attack.json")


def ssl_context():
    """python.org builds on macOS ship without system CA certificates; use
    certifi's bundle when it is installed."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def attack_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref["external_id"]
    return None


def live(obj):
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def extract(bundle):
    objects = bundle["objects"]
    by_type = {}
    for o in objects:
        by_type.setdefault(o["type"], []).append(o)

    matrix = next(o for o in by_type["x-mitre-matrix"] if live(o))
    tactic_by_stix = {o["id"]: o for o in by_type["x-mitre-tactic"]}
    tactics = [
        {"order": n, "id": attack_id(tactic_by_stix[ref]), "name": tactic_by_stix[ref]["name"],
         "shortname": tactic_by_stix[ref]["x_mitre_shortname"]}
        for n, ref in enumerate(matrix["tactic_refs"])
    ]
    tactic_name = {t["shortname"]: t["name"] for t in tactics}
    tactic_order = {t["name"]: t["order"] for t in tactics}

    techniques, stix_to_id = {}, {}
    for o in by_type["attack-pattern"]:
        if not live(o):
            continue
        tid = attack_id(o)
        stix_to_id[o["id"]] = tid
        names = [tactic_name[p["phase_name"]] for p in o.get("kill_chain_phases", [])
                 if p["kill_chain_name"] == "mitre-attack"]
        techniques[tid] = {
            "id": tid,
            "name": o["name"],
            "tactics": sorted(names, key=tactic_order.get),
            "description": o.get("description", "").split("\n")[0][:400],
            "is_subtechnique": bool(o.get("x_mitre_is_subtechnique")),
            "parent": tid.split(".")[0] if "." in tid else None,
        }

    group_by_stix = {o["id"]: o for o in by_type["intrusion-set"] if live(o)}
    uses = {}
    for r in by_type["relationship"]:
        if (r["relationship_type"] == "uses" and live(r)
                and r["source_ref"] in group_by_stix and r["target_ref"] in stix_to_id):
            uses.setdefault(r["source_ref"], set()).add(stix_to_id[r["target_ref"]])
    groups = sorted(
        ({"group_id": attack_id(g), "name": g["name"], "techniques": sorted(uses.get(sid, []))}
         for sid, g in group_by_stix.items()),
        key=lambda g: g["group_id"],
    )

    # revoked technique id -> the id that replaced it
    all_ids = {o["id"]: attack_id(o) for o in by_type["attack-pattern"]}
    direct = {
        all_ids[r["source_ref"]]: all_ids[r["target_ref"]]
        for r in by_type["relationship"]
        if r["relationship_type"] == "revoked-by"
        and r["source_ref"] in all_ids and r["target_ref"] in all_ids
    }
    # follow chains until a live technique; drop entries that never reach one
    revoked = {}
    for old in direct:
        new, hops = direct[old], 0
        while new not in techniques and new in direct and hops < 10:
            new, hops = direct[new], hops + 1
        if new in techniques:
            revoked[old] = new

    version = next(o for o in by_type["x-mitre-collection"]).get("x_mitre_version", "unknown")
    return techniques, groups, tactics, revoked, version


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()

    if not args.offline:
        RAW.parent.mkdir(exist_ok=True)
        print(f"downloading {URL}")
        with urllib.request.urlopen(URL, context=ssl_context()) as response:
            RAW.write_bytes(response.read())

    techniques, groups, tactics, revoked, version = extract(json.loads(RAW.read_text()))
    dump = lambda name, data: (HERE / name).write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    dump("techniques.json", techniques)
    dump("groups.json", groups)
    dump("tactics.json", tactics)
    dump("revoked.json", revoked)
    with_techniques = sum(1 for g in groups if g["techniques"])
    summary = (f"ATT&CK Enterprise v{version}\nsource: {URL}\n"
               f"techniques: {len(techniques)} "
               f"({sum(t['is_subtechnique'] for t in techniques.values())} sub-techniques)\n"
               f"groups: {len(groups)} ({with_techniques} with at least one technique)\n"
               f"tactics: {len(tactics)}\n")
    (HERE / "VERSION").write_text(summary)
    print(summary, end="")


if __name__ == "__main__":
    main()

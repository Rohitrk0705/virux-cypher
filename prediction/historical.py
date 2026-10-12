"""Historical attack database.

  python -m prediction.historical     # writes data/mitre/historical_attacks.json

Two sources:

1. MITRE ATT&CK Groups (data/mitre/groups.json). ATT&CK records which
   techniques a group has been reported to use. That is an unordered SET; no
   order of use is published. We derive a pseudo-sequence by sorting each
   group's techniques by the kill-chain position of the technique's earliest
   tactic, then by technique id. THIS ORDER IS INFERRED, NOT OBSERVED. It only
   says "an initial-access technique comes before an exfiltration technique".
   Two artefacts follow: inside one tactic the order is just the technique id,
   and a technique with several tactics sits at its earliest one, so T1078
   (Valid Accounts) always precedes T1110 (Brute Force) although a brute-force
   attack does the opposite. Only techniques a group uses directly are
   included, not those reached through its software.

2. Hand-specified sequences (data/mitre/curated_sequences.json). These are
   written by hand, in a deliberate order. Three of them are the reference
   forms of the dataset's attack patterns A, B and C ("known" attacks); pattern
   D is deliberately absent so that D incidents are novel to the database. The
   rest are plausible distractors. None of them is an observed real campaign.

Every record carries a `sequence` of parent technique ids (sub-techniques are
folded into their parent and consecutive repeats removed), which is what the
similarity engine and the Markov predictor consume.
"""

import json
from functools import lru_cache
from pathlib import Path

MITRE_DIR = Path(__file__).resolve().parent.parent / "data" / "mitre"
HISTORICAL_FILE = MITRE_DIR / "historical_attacks.json"

SOURCE_GROUP = "mitre_group"
SOURCE_CURATED = "curated"


def parent(technique_id):
    return technique_id.split(".")[0]


def to_sequence(technique_ids):
    """Fold sub-techniques into parents and drop consecutive repeats."""
    seq = []
    for t in technique_ids:
        p = parent(t)
        if not seq or seq[-1] != p:
            seq.append(p)
    return seq


def build():
    techniques = json.loads((MITRE_DIR / "techniques.json").read_text())
    tactic_order = {t["name"]: t["order"] for t in json.loads((MITRE_DIR / "tactics.json").read_text())}
    groups = json.loads((MITRE_DIR / "groups.json").read_text())
    curated = json.loads((MITRE_DIR / "curated_sequences.json").read_text())

    def position(technique_id):
        return min(tactic_order[t] for t in techniques[technique_id]["tactics"])

    records = []
    for entry in curated:
        unknown = [t for t in entry["techniques"] if t not in techniques]
        if unknown:
            raise ValueError(f"curated sequence {entry['name']!r} uses unknown techniques {unknown}")
        records.append({
            "name": entry["name"], "source": SOURCE_CURATED, "reference": entry["role"],
            "ordering": "hand_specified",
            "techniques": entry["techniques"], "sequence": to_sequence(entry["techniques"]),
        })
    for group in groups:
        parents = sorted({parent(t) for t in group["techniques"]}, key=lambda p: (position(p), p))
        if len(parents) < 2:  # a single technique is not a sequence
            continue
        records.append({
            "name": group["name"], "source": SOURCE_GROUP, "reference": group["group_id"],
            "ordering": "inferred_from_tactic_order",
            "techniques": group["techniques"], "sequence": parents,
        })

    # Stable ids: adding a curated sequence at the end or a new ATT&CK group
    # does not renumber anything else.
    curated_n = 0
    for record in records:
        if record["source"] == SOURCE_CURATED:
            curated_n += 1
            record["attack_id"] = f"HIST-C{curated_n:02d}"
        else:
            record["attack_id"] = f"HIST-{record['reference']}"
    keys = ["attack_id", "name", "source", "reference", "ordering", "techniques", "sequence"]
    return [{k: r[k] for k in keys} for r in records]


@lru_cache(maxsize=1)
def load_historical():
    if not HISTORICAL_FILE.exists():
        raise FileNotFoundError(f"{HISTORICAL_FILE} is missing; run: python -m prediction.historical")
    return tuple(json.loads(HISTORICAL_FILE.read_text()))


def historical(sources=None):
    """Records of the database, optionally limited to some sources."""
    return [r for r in load_historical() if sources is None or r["source"] in sources]


def main():
    records = build()
    HISTORICAL_FILE.write_text(json.dumps(records, indent=1) + "\n")
    for source in (SOURCE_CURATED, SOURCE_GROUP):
        lengths = sorted(len(r["sequence"]) for r in records if r["source"] == source)
        print(f"{source:<12}{len(lengths):>4} attacks, sequence length "
              f"min {lengths[0]} / median {lengths[len(lengths) // 2]} / max {lengths[-1]}")
    print(f"wrote {HISTORICAL_FILE}")


if __name__ == "__main__":
    main()

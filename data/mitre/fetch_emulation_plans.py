"""Download ordered adversary emulation plans and extract their technique sequences.

  python data/mitre/fetch_emulation_plans.py

Source: Center for Threat-Informed Defense, Adversary Emulation Library
(github.com/center-for-threat-informed-defense/adversary_emulation_library,
Apache License 2.0). Each plan is a YAML file of steps in execution order, each
step tagged with the ATT&CK technique it emulates. The plans were written from
public reporting on the named groups.

Why: MITRE ATT&CK group pages list the techniques a group uses but not their
order. These plans do carry an order. It is the order of an EMULATION written
from threat reports, not telemetry from a real intrusion, and one plan may
contain several scenarios back to back.

Writes emulation_plans.json: [{plan, source, techniques (ids in file order),
sequence (parent ids, consecutive repeats removed)}]. Ids revoked in the local
ATT&CK data are replaced by their successor; ids unknown to it are dropped and
counted. The raw YAML is kept under raw/ (git-ignored).
"""

import json
import re
import ssl
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = "https://raw.githubusercontent.com/center-for-threat-informed-defense/adversary_emulation_library/master/"
PLANS = {
    "FIN6": "fin6/Emulation_Plan/yaml/FIN6.yaml",
    "APT29": "apt29/Emulation_Plan/yaml/APT29.yaml",
    "Carbanak": "carbanak/Emulation_Plan/yaml/Carbanak.yaml",
    "Wizard Spider": "wizard_spider/Emulation_Plan/yaml/wizard_spider.yaml",
    "Sandworm": "sandworm/Emulation_Plan/yaml/sandworm.yaml",
    "OilRig": "oilrig/Emulation_Plan/yaml/oilrig.yaml",
    "Turla (Carbon)": "turla/Emulation_Plan/yaml/turla_carbon.yaml",
    "Turla (Snake)": "turla/Emulation_Plan/yaml/turla_snake.yaml",
}


def context():
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def main():
    techniques = json.loads((HERE / "techniques.json").read_text())
    revoked = json.loads((HERE / "revoked.json").read_text())
    raw_dir = HERE / "raw" / "emulation_plans"
    raw_dir.mkdir(parents=True, exist_ok=True)
    out = []
    for plan, path in PLANS.items():
        target = raw_dir / path.replace("/", "__")
        if not target.exists():
            request = urllib.request.Request(BASE + path, headers={"User-Agent": "virux-cypher-research"})
            target.write_bytes(urllib.request.urlopen(request, context=context(), timeout=60).read())
        # Each step has `attack_id` followed by `procedure_step`. In a few steps of one plan the
        # two values are swapped, so take whichever of the pair is a technique id.
        pairs = re.findall(r"attack_id:\s*\"?([^\s\"]+)\"?.*?procedure_step:\s*\"?([^\s\"]+)",
                           target.read_text(errors="replace"), re.S)
        is_id = re.compile(r"^T\d{4}(\.\d{3})?$")
        ids = [a if is_id.match(a) else b for a, b in pairs if is_id.match(a) or is_id.match(b)]
        kept, unknown = [], 0
        for technique in ids:
            technique = revoked.get(technique, technique)
            if technique in techniques:
                kept.append(technique)
            else:
                unknown += 1
        sequence = []
        for technique in kept:
            parent = technique.split(".")[0]
            if not sequence or sequence[-1] != parent:
                sequence.append(parent)
        out.append({"plan": plan, "source": BASE + path, "techniques": kept, "sequence": sequence})
        print(f"{plan:<16}{len(ids):>4} tagged steps, {unknown} ids unknown to ATT&CK v19, "
              f"{len(sequence)} steps after folding to parents")
    (HERE / "emulation_plans.json").write_text(json.dumps(out, indent=1) + "\n")
    print(f"wrote {HERE / 'emulation_plans.json'}")


if __name__ == "__main__":
    main()

# mitre — MITRE ATT&CK STIX/JSON + extracted historical attack sequences.

Files:
- `techniques.json`, `groups.json`, `tactics.json`, `revoked.json`, `VERSION` — extracted from MITRE ATT&CK
  Enterprise v19.2 by `fetch.py` (ATT&CK is (c) The MITRE Corporation, used under the ATT&CK terms of use).
- `historical_attacks.json`, `curated_sequences.json` — the first historical database (`prediction/historical.py`).
- `emulation_plans.json` — technique ids, in plan order, of eight adversary emulation plans from the Center for
  Threat-Informed Defense Adversary Emulation Library (github.com/center-for-threat-informed-defense/
  adversary_emulation_library, Apache License 2.0), extracted by `fetch_emulation_plans.py` from the `master`
  branch (not a pinned commit). Only technique ids are stored here; the plans themselves are not redistributed.

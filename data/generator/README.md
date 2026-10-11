# generator — writes labelled synthetic logs with known ground-truth techniques. Entry: generate.py

Usage: `python generate.py [--seed 42] [--out-dir ../processed]` (stdlib only; same seed = byte-identical output)

Outputs in `data/processed/`:
- `events.json` — Normalized Events (contract 1). `destination_ip` and `process` are `null` where they do not apply.
- `labels.json` — Attack Technique records (contract 2), attack events only. An event_id absent here is benign.
- `incidents.json` — evaluation ground truth only (not a contract): incident -> pattern, variant, technique sequence, event_ids.

Four attack patterns (A-D), six instances each: three base, one with a step skipped, one with a step inserted, one with both.

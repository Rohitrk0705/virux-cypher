"""Survey the OTRF Security-Datasets compound datasets (read-only).

  python -I data/adapters/survey.py [path to Security-Datasets-master]

Reads archives in memory; nothing is extracted or executed. For every compound
dataset it prints the ATT&CK mappings from the metadata file, and for every
host-log archive the number of events, time range, hosts, log channels and the
most frequent event ids. Stdlib only.
"""

import io
import json
import re
import sys
import tarfile
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else "data/external/Security-Datasets-master")
COMPOUND = ROOT / "datasets" / "compound"
MAX_BYTES = 3_000_000_000   # refuse absurd archive members


def attack_mappings(text):
    """[(technique id, [tactic ids])] from a metadata yaml, without a yaml parser."""
    out = []
    block = text.split("attack_mappings:", 1)[1] if "attack_mappings:" in text else ""
    block = re.split(r"\n[a-z_]+:", block, 1)[0]
    for part in block.split("- technique:")[1:]:
        technique = part.strip().split()[0]
        sub = re.search(r'sub-technique:\s*"?(\d{3})"?', part)
        tactics = re.findall(r"TA\d{4}", part)
        out.append((technique + (f".{sub.group(1)}" if sub else ""), tactics))
    return out


def json_lines(stream):
    for raw in stream:
        raw = raw.strip()
        if raw:
            try:
                yield json.loads(raw)
            except json.JSONDecodeError:
                yield None


def members(path):
    """(name, size, open function) for each file inside a zip or tar.gz."""
    if zipfile.is_zipfile(path):
        archive = zipfile.ZipFile(path)
        for info in archive.infolist():
            if not info.is_dir():
                yield info.filename, info.file_size, lambda info=info: io.TextIOWrapper(archive.open(info), "utf-8", errors="replace")
    elif tarfile.is_tarfile(path):
        archive = tarfile.open(path)
        for info in archive:
            if info.isfile():
                yield info.name, info.size, lambda info=info: io.TextIOWrapper(archive.extractfile(info), "utf-8", errors="replace")


def describe(path):
    for name, size, opener in members(path):
        print(f"    member {name}  ({size / 1e6:.1f} MB)")
        if not name.lower().endswith((".json", ".jsonl", ".log")) or size > MAX_BYTES:
            continue
        n = bad = 0
        channels, ids, hosts, keys = Counter(), Counter(), Counter(), Counter()
        first = last = None
        sample = None
        with opener() as stream:
            for event in json_lines(stream):
                n += 1
                if not isinstance(event, dict):
                    bad += 1
                    continue
                sample = sample or event
                channel = event.get("Channel") or event.get("channel") or event.get("log_name") or "?"
                channels[channel] += 1
                ids[(channel.split("/")[0].replace("Microsoft-Windows-", ""), event.get("EventID", event.get("event_id")))] += 1
                hosts[event.get("Hostname") or event.get("host") or event.get("computer_name") or "?"] += 1
                stamp = event.get("@timestamp") or event.get("TimeCreated") or event.get("EventTime")
                if isinstance(stamp, str):
                    first = stamp if first is None or stamp < first else first
                    last = stamp if last is None or stamp > last else last
                keys.update(event.keys())
        print(f"      events {n} (unparseable {bad}); time {first} .. {last}")
        print(f"      hosts: {dict(hosts.most_common(6))}")
        print(f"      channels: {dict(channels.most_common(8))}")
        print(f"      top event ids: {[(f'{c}:{i}', k) for (c, i), k in ids.most_common(14)]}")
        print(f"      fields present in every event: {sorted(k for k, c in keys.items() if c == n - bad)[:40]}")
        if sample:
            print(f"      sample event: {json.dumps(sample)[:900]}")


def main():
    for meta in sorted((COMPOUND / "_metadata").glob("*.yaml")):
        text = meta.read_text(errors="replace")
        title = re.search(r"^title:\s*(.+)$", text, re.M)
        print(f"\n=== {meta.stem}: {title.group(1) if title else ''}")
        print("  ATT&CK mappings (dataset level): " + ", ".join(f"{t} [{'/'.join(ta)}]" for t, ta in attack_mappings(text)))
    for folder in sorted(p for p in COMPOUND.iterdir() if p.is_dir() and p.name != "_metadata"):
        print(f"\n=== folder {folder.name}")
        for archive in sorted(folder.rglob("*")):
            if archive.is_file() and archive.suffix.lower() in (".zip", ".gz") and "pcap" not in archive.name.lower():
                print(f"  archive {archive.relative_to(COMPOUND)}  ({archive.stat().st_size / 1e6:.1f} MB)")
                try:
                    describe(archive)
                except Exception as exc:  # noqa: BLE001 - survey must not stop on one bad archive
                    print(f"    could not read: {type(exc).__name__}: {exc}")


if __name__ == "__main__":
    main()

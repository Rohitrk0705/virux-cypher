"""Adapter: OTRF `apt29` day 1 (ATT&CK Evaluations round 2 emulation) -> contract 1.

A multi-step, four-host intrusion (initial breach, collection, exfiltration,
privilege escalation, credential access, lateral movement), unlike the
single-host LSASS captures. Same mapping rules as data/adapters/otrf.py, with
two differences forced by this capture's older log format:

- Sysmon 10 and 11 events here carry no user field. The user is DERIVED from
  the process-creation event (Sysmon 1) with the same ProcessGuid, when that
  process started during the capture; otherwise the event is dropped.
- There are no byte counts (Zeek logs are not joined), so byte_count is null.

Labels: the emulation plan (`emulationplans/apt29.xlsx`, sheet day1) lists, per
step and in order, the NAMES of the techniques used, in 2020 ATT&CK wording.
A name is turned into an id only by exact, case-insensitive match with a
current ATT&CK technique name. Names with no exact match are listed as
unmatched and left out; no id is assigned by judgement.
"""

import html
import io
import json
import re
import zipfile
from collections import Counter

from . import otrf

FOLDER = otrf.SOURCE / "apt29"
HOST_ARCHIVE = FOLDER / "day1" / "apt29_evals_day1_manual.zip"
PLAN = FOLDER / "emulationplans" / "apt29.xlsx"
TECHNIQUES_FILE = otrf.ROOT / "data" / "mitre" / "techniques.json"


def plan_steps(sheet="xl/worksheets/sheet1.xml"):
    """[(step id, [technique names])] in plan order, from the spreadsheet."""
    with zipfile.ZipFile(PLAN) as z:
        shared = z.read("xl/sharedStrings.xml").decode("utf-8", "replace")
        strings = ["".join(html.unescape(t) for t in re.findall(r"<t[^>]*>([^<]*)</t>", si))
                   for si in re.findall(r"<si>(.*?)</si>", shared, re.S)]
        xml = z.read(sheet).decode("utf-8", "replace")
    steps = []
    for row in re.findall(r"<row[^>]*>(.*?)</row>", xml, re.S):
        cells = {}
        for column, attrs, inner in re.findall(r'<c r="([A-Z]+)\d+"([^>]*)>(.*?)</c>', row, re.S):
            value = re.search(r"<v>([^<]*)</v>", inner)
            if value:
                cells[column] = strings[int(value.group(1))] if 't="s"' in attrs else value.group(1)
        step = cells.get("C", "").strip()
        if re.match(r"^\d+\.[A-Z]", step):
            steps.append((step, [n.strip() for n in re.split(r"[,\n\r]+", cells.get("B", "")) if n.strip()]))
    return steps


def labels():
    """Returns (ordered [(step, [technique ids])], sorted unmatched names)."""
    by_name = {}
    for t in json.loads(TECHNIQUES_FILE.read_text()).values():
        by_name.setdefault(t["name"].lower(), []).append(t["id"])
    ordered, unmatched = [], set()
    for step, names in plan_steps():
        ids = []
        for name in names:
            found = by_name.get(name.lower(), [])
            if len(found) == 1:
                ids.append(found[0])
            else:
                unmatched.add(name)
        ordered.append((step, ids))
    return ordered, sorted(unmatched)


def _stream():
    with zipfile.ZipFile(HOST_ARCHIVE) as z:
        name = next(n for n in z.namelist() if n.lower().endswith(".json"))
        with io.TextIOWrapper(z.open(name), "utf-8", errors="replace") as stream:
            for line_no, line in enumerate(stream):
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(event, dict):
                    yield line_no, event


def adapt(tag="a29"):
    """Returns (contract-1 events in time order, report dict). Two passes over the file."""
    outbound, process_user, raw_count = Counter(), {}, 0
    for _, e in _stream():
        raw_count += 1
        if e.get("Channel") != otrf.SYSMON:
            continue
        event_id = otrf._int(e.get("EventID"))
        if event_id == 3 and str(e.get("Initiated")).lower() == "true" and ":" not in str(e.get("SourceIp", ":")):
            outbound[(e.get("Hostname"), e.get("SourceIp"))] += 1
        elif event_id == 1 and e.get("ProcessGuid") and otrf._user(e.get("User")):
            process_user[e["ProcessGuid"]] = otrf._user(e["User"])
    host_ip = {}
    for (host, ip), _ in outbound.most_common():
        host_ip.setdefault(host, ip)

    kept, dropped, lost, seen = [], Counter(), Counter(), Counter()
    for line_no, e in _stream():
        channel = e.get("Channel")
        channel = otrf.SECURITY if str(channel).lower() == "security" else channel
        event_id = otrf._int(e.get("EventID"))
        seen[(channel, event_id)] += 1
        kind = otrf.EVENT_TYPES.get((channel, event_id))
        if kind is None:
            dropped["no contract-1 representation for this event type"] += 1
            continue
        stamp, host = e.get("@timestamp"), e.get("Hostname")
        own = host_ip.get(host)
        if not isinstance(stamp, str) or not host:
            dropped["no usable timestamp or host name"] += 1
            continue
        record = {"timestamp": stamp[:19] + "Z", "source": "sysmon" if channel == otrf.SYSMON else "security",
                  "device": host.split(".")[0].upper(), "destination_ip": None, "process": None,
                  "destination_port": None, "byte_count": None}
        if kind == "process_execution":
            record.update(user=otrf._user(e.get("User")), source_ip=own, action=kind,
                          process=otrf._image(e.get("Image")))
            lost["process creations whose command line and parent process were dropped"] += 1
        elif kind == "file_create":
            record.update(user=otrf._user(e.get("User")) or process_user.get(e.get("ProcessGuid")),
                          source_ip=own, action=kind, process=otrf._image(e.get("Image")))
            lost["file creations whose file name was dropped"] += 1
        elif kind == "process_access":
            record.update(user=otrf._user(e.get("SourceUser")) or process_user.get(e.get("SourceProcessGUID")),
                          source_ip=own, action=kind, process=otrf._image(e.get("SourceImage")))
            lost["process-access events whose target process was dropped"] += 1
            if str(e.get("TargetImage", "")).lower().endswith("lsass.exe"):
                lost["... of which the target was lsass.exe"] += 1
        elif kind == "network_connection":
            record.update(user=otrf._user(e.get("User")), source_ip=e.get("SourceIp"), action=kind,
                          destination_ip=e.get("DestinationIp"), process=otrf._image(e.get("Image")),
                          destination_port=otrf._int(e.get("DestinationPort")))
        else:
            remote = e.get("IpAddress")
            if kind == "logon":
                kind = otrf.LOGON_ACTION.get(str(e.get("LogonType")))
                if kind is None:
                    dropped["service, batch or system logon (not a user session)"] += 1
                    continue
            record.update(user=otrf._user(e.get("TargetUserName")), action=kind)
            if remote in otrf.LOCAL_ADDRESSES:
                record.update(source_ip=own)
            else:
                record.update(source_ip=remote, destination_ip=own)
        missing = [k for k in ("user", "source_ip") if not record.get(k)]
        if missing:
            dropped[f"required field could not be mapped: {', '.join(missing)}"] += 1
            continue
        kept.append((stamp, line_no, record))

    kept.sort(key=lambda item: (item[0], item[1]))
    keys = ["event_id", "timestamp", "source", "user", "source_ip", "destination_ip", "device", "action",
            "process", "destination_port", "byte_count"]
    events = [{k: {**record, "event_id": f"evt-{tag}-{n:06d}"}[k] for k in keys}
              for n, (_, _, record) in enumerate(kept, 1)]
    ordered, unmatched = labels()
    report = {
        "dataset": "apt29_day1", "raw_events": raw_count, "adapted_events": len(events),
        "host_addresses": {h.split(".")[0].upper(): ip for h, ip in host_ip.items() if h},
        "adapted_by_action": dict(Counter(e["action"] for e in events).most_common()),
        "adapted_by_host": dict(Counter(e["device"] for e in events).most_common()),
        "dropped": dict(dropped.most_common()), "lost": dict(lost.most_common()),
        "users": dict(Counter(e["user"] for e in events).most_common(12)),
        "raw_by_type": {f"{c}:{i}": n for (c, i), n in seen.most_common(12)},
        "plan_steps": ordered, "unmatched_technique_names": unmatched,
        "time_range": [events[0]["timestamp"], events[-1]["timestamp"]] if events else None,
    }
    return events, report

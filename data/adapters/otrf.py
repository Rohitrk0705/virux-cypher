"""Adapter: OTRF Security-Datasets host logs -> Normalized Events (contract 1).

  python -m data.adapters.otrf LSASS_campaign_02        # writes data/processed/real/<name>/

Input is real Windows telemetry (Sysmon, Security, PowerShell channels), one
JSON object per line, plus optional Zeek conn.log for byte counts. The contract
is not changed to fit the data: every real field either maps to a contract-1
field, is used to derive one, or is dropped and counted. Nothing is invented;
an event that cannot be given a required field is dropped and counted.

Field mapping (see docs/real-data.md for the full table and what is lost):

  event_id         made here: evt-<dataset tag>-<running number in time order>
  timestamp        @timestamp, truncated to seconds
  source           sysmon | security
  user             Sysmon 1/3/11: User; Sysmon 10: SourceUser; Security 462x/4634: TargetUserName;
                   domain prefix removed, lower case
  device           Hostname without the domain, upper case
  action, process  by event type, see EVENT_TYPES below; process is the image file name, lower case
  source_ip        network events: SourceIp; remote logons: IpAddress; all other events: the host's
                   own address, DERIVED as the most frequent source address of its outbound connections
  destination_ip   network events: DestinationIp; remote logons: the host's address; otherwise null
  destination_port Sysmon 3: DestinationPort; otherwise null
  byte_count       Sysmon 3 joined to Zeek conn.log on (source ip, source port, destination ip,
                   destination port): orig_bytes, but only for records where Zeek saw the
                   originator's packets and missed no bytes; null otherwise

Stdlib only. Archives are read in memory; nothing from the dataset is executed.
"""

import io
import json
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
SOURCE = ROOT / "data" / "external" / "Security-Datasets-master" / "datasets" / "compound"
OUT = ROOT / "data" / "processed" / "real"

SYSMON = "Microsoft-Windows-Sysmon/Operational"
SECURITY = "Security"

# (channel, event id) -> how it is represented. Everything else is dropped and counted.
EVENT_TYPES = {
    (SYSMON, 1): "process_execution",
    (SYSMON, 3): "network_connection",
    (SYSMON, 10): "process_access",      # the TARGET process has no contract-1 field and is lost
    (SYSMON, 11): "file_create",         # the file name has no contract-1 field and is lost
    (SECURITY, 4624): "logon",           # refined by LogonType below
    (SECURITY, 4625): "logon_failure",
    (SECURITY, 4634): "logoff",
    (SECURITY, 4647): "logoff",
}
LOGON_ACTION = {"2": "logon_success", "7": "logon_success", "9": "logon_success", "11": "logon_success",
                "10": "rdp_session", "3": "network_logon"}
LOCAL_ADDRESSES = {"-", "", "::1", "127.0.0.1", None}
ORIGINATOR_SEEN = {"SF", "S0", "S1", "S2", "S3", "REJ", "RSTO", "RSTR", "RSTOS0"}


def labels(dataset):
    """Dataset-level ATT&CK labels from the metadata file: [(technique id, [tactic ids])]."""
    text = (SOURCE / "_metadata" / f"{dataset}.yaml").read_text(errors="replace")
    block = text.split("attack_mappings:", 1)[1] if "attack_mappings:" in text else ""
    block = re.split(r"\n[a-z_]+:", block, maxsplit=1)[0]
    out = []
    for part in block.split("- technique:")[1:]:
        technique = part.strip().split()[0]
        sub = re.search(r'sub-technique:\s*"?(\d{3})"?', part)
        out.append((technique + (f".{sub.group(1)}" if sub else ""), re.findall(r"TA\d{4}", part)))
    return out


def _archives(dataset):
    folder = SOURCE / dataset
    host = [p for p in sorted(folder.glob("*.zip")) if "zeek" not in p.name and "pcap" not in p.name]
    zeek = [p for p in sorted(folder.glob("*zeek*.zip"))]
    if len(host) != 1:
        raise FileNotFoundError(f"expected one host-log archive in {folder}, found {len(host)}")
    return host[0], (zeek[0] if zeek else None)


def _raw_events(archive):
    with zipfile.ZipFile(archive) as z:
        name = next(n for n in z.namelist() if n.lower().endswith(".json"))
        with io.TextIOWrapper(z.open(name), "utf-8", errors="replace") as stream:
            for line_no, line in enumerate(stream):
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(event, dict):
                    yield line_no, event


def zeek_bytes(archive):
    """{(orig ip, orig port, resp ip, resp port): bytes sent by the originator} from conn.log."""
    out = {}
    if archive is None:
        return out
    with zipfile.ZipFile(archive) as z:
        name = next((n for n in z.namelist() if n.endswith("conn.log")), None)
        if name is None:
            return out
        fields = []
        for line in z.read(name).decode("utf-8", "replace").splitlines():
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line and not line.startswith("#") and fields:
                row = dict(zip(fields, line.split("\t")))
                # Only connection states in which Zeek saw the originator's packets. In these
                # captures most records are one-sided (state SHR/OTH: responder traffic only),
                # and their orig_bytes of 0 means "not observed", not "nothing was sent".
                # ... and only when no bytes were missed: with a gap, orig_bytes is Zeek's
                # estimate from TCP sequence numbers, not a count of what it saw.
                if (row.get("orig_bytes", "-").isdigit() and row.get("conn_state") in ORIGINATOR_SEEN
                        and row.get("missed_bytes", "0") in ("0", "-")):
                    key = (row["id.orig_h"], row["id.orig_p"], row["id.resp_h"], row["id.resp_p"])
                    out[key] = out.get(key, 0) + int(row["orig_bytes"])
    return out


def _user(value):
    if not isinstance(value, str) or value.strip() in ("", "-"):
        return None
    return value.split("\\")[-1].strip().lower() or None


def _image(value):
    if not isinstance(value, str) or not value.strip() or value.startswith("<"):
        return None
    return value.replace("/", "\\").split("\\")[-1].strip().lower() or None


def _int(value):
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return None


def adapt(dataset, tag=None):
    """Returns (contract-1 events in time order, report dict)."""
    tag = tag or re.sub(r"[^a-z0-9]", "", dataset.lower().replace("lsass_campaign_", "l"))
    host_archive, zeek_archive = _archives(dataset)
    raw = list(_raw_events(host_archive))
    volumes = zeek_bytes(zeek_archive)

    # the host's own address: where its outbound connections come from
    outbound = Counter()
    for _, e in raw:
        if e.get("Channel") == SYSMON and _int(e.get("EventID")) == 3 and str(e.get("Initiated")).lower() == "true":
            if ":" not in str(e.get("SourceIp", ":")):
                outbound[(e.get("Hostname"), e.get("SourceIp"))] += 1
    host_ip = {}
    for (host, ip), _ in outbound.most_common():
        host_ip.setdefault(host, ip)

    seen, kept, dropped = Counter(), [], Counter()
    lost = Counter()
    lineage = {}   # line number -> (ProcessGuid, ParentProcessGuid, CommandLine); for evaluation only
    for line_no, e in raw:
        channel, event_id = e.get("Channel"), _int(e.get("EventID"))
        seen[(channel, event_id)] += 1
        kind = EVENT_TYPES.get((channel, event_id))
        if kind is None:
            dropped["no contract-1 representation for this event type"] += 1
            continue
        stamp, host = e.get("@timestamp"), e.get("Hostname")
        own = host_ip.get(host)
        if not isinstance(stamp, str) or not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", stamp) or not host:
            dropped["no usable timestamp or host name"] += 1
            continue
        record = {"timestamp": stamp[:19] + "Z", "source": "sysmon" if channel == SYSMON else "security",
                  "device": host.split(".")[0].upper(), "destination_ip": None, "process": None,
                  "destination_port": None, "byte_count": None}
        if kind in ("process_execution", "file_create"):
            record.update(user=_user(e.get("User")), source_ip=own, action=kind, process=_image(e.get("Image")))
            if kind == "process_execution":
                lineage[line_no] = (e.get("ProcessGuid"), e.get("ParentProcessGuid"), str(e.get("CommandLine", "")))
                lost["process creations whose command line and parent process were dropped"] += 1
            else:
                lost["file creations whose file name was dropped"] += 1
        elif kind == "process_access":
            record.update(user=_user(e.get("SourceUser")), source_ip=own, action=kind,
                          process=_image(e.get("SourceImage")))
            lost["process-access events whose target process was dropped"] += 1
            if str(e.get("TargetImage", "")).lower().endswith("lsass.exe"):
                lost["... of which the target was lsass.exe"] += 1
        elif kind == "network_connection":
            key = (e.get("SourceIp"), str(e.get("SourcePort")), e.get("DestinationIp"), str(e.get("DestinationPort")))
            record.update(user=_user(e.get("User")), source_ip=e.get("SourceIp"), action=kind,
                          destination_ip=e.get("DestinationIp"), process=_image(e.get("Image")),
                          destination_port=_int(e.get("DestinationPort")), byte_count=volumes.get(key))
            lost["network events with a byte count from Zeek" if key in volumes
                 else "network events without an observed outbound byte count (byte_count null)"] += 1
        else:   # Security logon / logoff
            remote = e.get("IpAddress")
            if kind == "logon":
                kind = LOGON_ACTION.get(str(e.get("LogonType")))
                if kind is None:
                    dropped["service, batch or system logon (not a user session)"] += 1
                    continue
            record.update(user=_user(e.get("TargetUserName")), action=kind)
            if remote in LOCAL_ADDRESSES:
                record.update(source_ip=own)
            else:
                record.update(source_ip=remote, destination_ip=own)
        missing = [k for k in ("user", "source_ip") if not record.get(k)]
        if missing:
            dropped[f"required field could not be mapped: {', '.join(missing)}"] += 1
            continue
        kept.append((stamp, line_no, record))

    kept.sort(key=lambda item: (item[0], item[1]))   # millisecond order survives in the numbering
    keys = ["event_id", "timestamp", "source", "user", "source_ip", "destination_ip", "device", "action",
            "process", "destination_port", "byte_count"]
    events = [{k: {**record, "event_id": f"evt-{tag}-{n:06d}"}[k] for k in keys}
              for n, (_, _, record) in enumerate(kept, 1)]
    # Process lineage is NOT part of the adapted events (contract 1 cannot hold it). It is
    # returned beside them so that an evaluation can explain results; the pipeline never sees it.
    process_lineage = {f"evt-{tag}-{n:06d}": lineage[line_no]
                       for n, (_, line_no, _) in enumerate(kept, 1) if line_no in lineage}
    report = {
        "dataset": dataset, "tag": tag, "raw_events": len(raw), "adapted_events": len(events),
        "host_addresses": {h.split(".")[0].upper(): ip for h, ip in host_ip.items() if h},
        "raw_by_type": {f"{c}:{i}": n for (c, i), n in seen.most_common()},
        "adapted_by_action": dict(Counter(e["action"] for e in events).most_common()),
        "dropped": dict(dropped.most_common()), "lost": dict(lost.most_common()),
        "process_lineage": process_lineage,
        "users": dict(Counter(e["user"] for e in events).most_common(8)),
        "labels": [t for t, _ in labels(dataset)],
        "time_range": [events[0]["timestamp"], events[-1]["timestamp"]] if events else None,
    }
    return events, report


def write(dataset):
    events, report = adapt(dataset)
    folder = OUT / dataset
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "events.json").write_text(json.dumps(events, indent=1) + "\n")
    (folder / "adapter_report.json").write_text(
        json.dumps({k: v for k, v in report.items() if k != "process_lineage"}, indent=1) + "\n")
    return events, report


if __name__ == "__main__":
    for name in sys.argv[1:] or ["LSASS_campaign_02"]:
        _, rep = write(name)
        print(json.dumps({k: rep[k] for k in ("dataset", "raw_events", "adapted_events", "host_addresses",
                                              "adapted_by_action", "dropped", "lost", "users", "labels",
                                              "time_range")}, indent=1))

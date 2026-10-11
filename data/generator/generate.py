"""Synthetic labelled-log generator.

Emits normal activity for a small fictional bank plus injected attack incidents
where the ground-truth ATT&CK technique of every attack event is known. This is
the project's primary dataset.

Outputs (written to data/processed/):
  events.json    - JSON array of Normalized Events        (contract 1)
  labels.json    - JSON array of Attack Technique records  (contract 2),
                   attack events only; an event_id absent here is benign
  incidents.json - evaluation ground truth (not a contract): which events
                   belong to which incident, its pattern and variant

Four attack patterns (A-D) are instantiated several times each with different
users, hosts, attacker IPs and timing. Some instances skip a step or insert an
extra one, so the dataset contains genuine variants of each pattern.

Deterministic: the same --seed always produces byte-identical files.

Usage:
  python generate.py [--seed 42] [--out-dir ../processed]
"""

import argparse
import json
import random
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ----------------------------------------------------------------------------
# Fictional bank environment
# ----------------------------------------------------------------------------

DEVICE_IP = {
    "WS-01": "10.0.0.11",
    "WS-02": "10.0.0.12",
    "WS-03": "10.0.0.13",
    "WS-04": "10.0.0.14",
    "WS-05": "10.0.0.15",
    "WS-06": "10.0.0.16",
    "WS-07": "10.0.0.17",
    "SRV-DC01": "10.0.0.2",
    "SRV-DB01": "10.0.0.3",
    "SRV-FILE01": "10.0.0.4",
    "SRV-MAIL01": "10.0.0.5",
}

# staff user -> their workstation
STAFF = {
    "john": "WS-01",
    "priya": "WS-02",
    "marcus": "WS-03",
    "elena": "WS-04",
    "david": "WS-05",
    "sara": "WS-06",
}
ADMIN_USER, ADMIN_WS = "admin_lee", "WS-07"
BACKUP_USER = "svc_backup"

SERVERS = ["SRV-DC01", "SRV-DB01", "SRV-FILE01"]

# documentation ranges (RFC 5737) so nothing collides with real addresses
BENIGN_WEB_IPS = [f"192.0.2.{i}" for i in range(10, 40)]
BENIGN_MAIL_IPS = [f"192.0.2.{i}" for i in range(100, 112)]
ATTACKER_IPS = [
    "203.0.113.7", "203.0.113.45", "203.0.113.118", "203.0.113.201",
    "198.51.100.23", "198.51.100.77", "198.51.100.140", "198.51.100.212",
]

START_DAY = datetime(2026, 9, 7, tzinfo=timezone.utc)  # a Monday
NUM_DAYS = 12  # Mon 7 Sep .. Fri 18 Sep 2026 (10 business days)

# ----------------------------------------------------------------------------
# ATT&CK techniques used
# ----------------------------------------------------------------------------

TECHNIQUES = {
    "T1566.001": ("Spearphishing Attachment", "Initial Access"),
    "T1078": ("Valid Accounts", "Initial Access"),
    "T1110": ("Brute Force", "Credential Access"),
    "T1204.002": ("Malicious File", "Execution"),
    "T1059.001": ("PowerShell", "Execution"),
    "T1068": ("Exploitation for Privilege Escalation", "Privilege Escalation"),
    "T1003.001": ("LSASS Memory", "Credential Access"),
    "T1082": ("System Information Discovery", "Discovery"),
    "T1083": ("File and Directory Discovery", "Discovery"),
    "T1053.005": ("Scheduled Task", "Persistence"),
    "T1070.001": ("Clear Windows Event Logs", "Defense Evasion"),
    "T1021.001": ("Remote Desktop Protocol", "Lateral Movement"),
    "T1021.002": ("SMB/Windows Admin Shares", "Lateral Movement"),
    "T1005": ("Data from Local System", "Collection"),
    "T1041": ("Exfiltration Over C2 Channel", "Exfiltration"),
}

PATTERNS = {
    "A": ["T1078", "T1059.001", "T1068", "T1021.001"],
    "B": ["T1566.001", "T1204.002", "T1059.001", "T1003.001", "T1021.002"],
    "C": ["T1078", "T1059.001", "T1068", "T1021.001", "T1041"],
    "D": ["T1110", "T1078", "T1083", "T1005", "T1041"],
}

# the step that gives the attacker code execution on the first host; it is
# never skipped, and extra steps are only inserted after it
FOOTHOLD = {"A": "T1078", "B": "T1204.002", "C": "T1078", "D": "T1078"}

# steps an instance may gain when its variant says "insert"
INSERTABLE = ["T1082", "T1083", "T1053.005", "T1070.001"]

# per pattern: variant of each of its instances (shuffled per pattern)
VARIANT_PLAN = ["base", "base", "base", "skip", "insert", "skip+insert"]

EVENT_KEYS = [
    "event_id", "timestamp", "source", "user", "source_ip",
    "destination_ip", "device", "action", "process",
]
LABEL_KEYS = ["event_id", "technique_id", "technique_name", "tactic", "confidence"]
NULLABLE = {"destination_ip", "process"}
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


def ev(ts, source, user, source_ip, destination_ip, device, action, process):
    """One event without an id yet (ids are assigned after the global sort)."""
    return {
        "ts": ts, "source": source, "user": user, "source_ip": source_ip,
        "destination_ip": destination_ip, "device": device, "action": action,
        "process": process,
    }


# ----------------------------------------------------------------------------
# Benign baseline
# ----------------------------------------------------------------------------

def staff_day(rng, day, user, ws):
    ip = DEVICE_IP[ws]
    out = []
    arrive = day + timedelta(hours=8, seconds=rng.randint(0, 5400))
    leave = day + timedelta(hours=16, minutes=30, seconds=rng.randint(0, 5400))

    t = arrive
    if rng.random() < 0.12:  # mistyped password
        for _ in range(rng.randint(1, 2)):
            out.append(ev(t, "windows", user, ip, None, ws, "logon_failure", None))
            t += timedelta(seconds=rng.randint(4, 20))
    out.append(ev(t, "windows", user, ip, None, ws, "logon_success", None))

    span = int((leave - t).total_seconds()) - 120
    for _ in range(rng.randint(40, 58)):
        at = t + timedelta(seconds=rng.randint(60, span))
        kind = rng.choices(
            ["proc", "file", "net_int", "net_ext", "mail"],
            weights=[35, 20, 15, 20, 10],
        )[0]
        if kind == "proc":
            proc = rng.choice([
                "outlook.exe", "excel.exe", "winword.exe", "chrome.exe",
                "teams.exe", "bankcore.exe", "notepad.exe",
            ])
            out.append(ev(at, "windows", user, ip, None, ws, "process_execution", proc))
        elif kind == "file":
            out.append(ev(at, "windows", user, ip, DEVICE_IP["SRV-FILE01"],
                          "SRV-FILE01", "file_access", None))
        elif kind == "net_int":
            dst = rng.choice(["SRV-DB01", "SRV-FILE01", "SRV-DC01"])
            out.append(ev(at, "firewall", user, ip, DEVICE_IP[dst], ws,
                          "network_connection", None))
        elif kind == "net_ext":
            out.append(ev(at, "firewall", user, ip, rng.choice(BENIGN_WEB_IPS), ws,
                          "network_connection", None))
        else:
            out.append(ev(at, "email", user, rng.choice(BENIGN_MAIL_IPS),
                          DEVICE_IP["SRV-MAIL01"], "SRV-MAIL01", "email_received", None))

    out.append(ev(leave, "windows", user, ip, None, ws, "logoff", None))
    return out


def admin_day(rng, day):
    """Admin work deliberately resembles attack steps (PowerShell, RDP, SMB,
    elevation) so that detection downstream is not trivial."""
    user, ws, ip = ADMIN_USER, ADMIN_WS, DEVICE_IP[ADMIN_WS]
    out = []
    arrive = day + timedelta(hours=8, seconds=rng.randint(0, 3600))
    leave = day + timedelta(hours=17, seconds=rng.randint(0, 3600))
    out.append(ev(arrive, "windows", user, ip, None, ws, "logon_success", None))

    span = int((leave - arrive).total_seconds()) - 600
    for _ in range(rng.randint(8, 12)):
        at = arrive + timedelta(seconds=rng.randint(60, span))
        kind = rng.choices(["local", "rdp", "smb", "elevate"], weights=[40, 25, 15, 20])[0]
        if kind == "local":
            proc = rng.choice(["powershell.exe", "cmd.exe", "mmc.exe", "systeminfo.exe",
                               "schtasks.exe", "whoami.exe"])
            out.append(ev(at, "windows", user, ip, None, ws, "process_execution", proc))
        elif kind == "rdp":
            srv = rng.choice(SERVERS + ["SRV-MAIL01"])
            out.append(ev(at, "windows", user, ip, DEVICE_IP[srv], srv, "rdp_session", None))
            for _ in range(rng.randint(1, 3)):  # work done on the server
                at += timedelta(seconds=rng.randint(30, 240))
                proc = rng.choice(["powershell.exe", "cmd.exe", "mmc.exe", "taskmgr.exe"])
                out.append(ev(at, "windows", user, DEVICE_IP[srv], None, srv,
                              "process_execution", proc))
        elif kind == "smb":
            srv = rng.choice(SERVERS)
            out.append(ev(at, "windows", user, ip, DEVICE_IP[srv], srv, "smb_session", None))
        else:
            proc = rng.choice(["consent.exe", "mmc.exe", "msiexec.exe"])
            out.append(ev(at, "windows", user, ip, None, ws, "privilege_change", proc))

    out.append(ev(leave, "windows", user, ip, None, ws, "logoff", None))
    return out


def backup_night(rng, day):
    """Nightly backup job: file server pulls from the database server."""
    user, host = BACKUP_USER, "SRV-FILE01"
    ip = DEVICE_IP[host]
    t = day + timedelta(hours=1, seconds=rng.randint(0, 300))
    out = [ev(t, "windows", user, ip, None, host, "logon_success", None)]
    t += timedelta(seconds=rng.randint(5, 20))
    out.append(ev(t, "windows", user, ip, DEVICE_IP["SRV-DB01"], "SRV-DB01",
                  "smb_session", None))
    t += timedelta(seconds=rng.randint(5, 20))
    out.append(ev(t, "windows", user, ip, None, host, "process_execution", "robocopy.exe"))
    for _ in range(rng.randint(4, 7)):
        t += timedelta(seconds=rng.randint(20, 120))
        out.append(ev(t, "windows", user, ip, None, host, "file_access", "robocopy.exe"))
    t += timedelta(seconds=rng.randint(20, 60))
    out.append(ev(t, "windows", user, ip, None, host, "logoff", None))
    return out


def benign_events(rng):
    out = []
    for d in range(NUM_DAYS):
        day = START_DAY + timedelta(days=d)
        out += backup_night(rng, day)
        if day.weekday() < 5:
            for user, ws in STAFF.items():
                out += staff_day(rng, day, user, ws)
            out += admin_day(rng, day)
    return out


# ----------------------------------------------------------------------------
# Attack incidents
# ----------------------------------------------------------------------------

def apply_variant(rng, pattern, variant):
    """Return the technique sequence for one instance of a pattern."""
    seq = list(PATTERNS[pattern])
    foothold = seq.index(FOOTHOLD[pattern])
    skipped = inserted = None
    if "skip" in variant:
        i = rng.randrange(foothold + 1, len(seq))
        skipped = seq.pop(i)
    if "insert" in variant:
        while True:
            tech = rng.choice(INSERTABLE)
            i = rng.randrange(foothold + 1, len(seq) + 1)
            # an inserted step must not sit next to itself
            if tech != seq[i - 1] and (i == len(seq) or tech != seq[i]) and tech not in seq:
                break
        seq.insert(i, tech)
        inserted = tech
    return seq, skipped, inserted


def step_events(rng, tech, ctx, t):
    """Events for one technique step. Mutates ctx on lateral movement or
    credential theft. Returns (events, time after the step)."""
    user, host = ctx["user"], ctx["host"]
    ip = DEVICE_IP[host]
    out = []

    def proc_run(names, lo=1, hi=1):
        nonlocal t
        for _ in range(rng.randint(lo, hi)):
            out.append(ev(t, "windows", user, ip, None, host, "process_execution",
                          rng.choice(names)))
            t += timedelta(seconds=rng.randint(15, 90))

    if tech == "T1566.001":
        out.append(ev(t, "email", user, ctx["ext_ip"], DEVICE_IP["SRV-MAIL01"],
                      "SRV-MAIL01", "email_received", None))
    elif tech == "T1204.002":
        proc_run(["winword.exe", "excel.exe"])
    elif tech == "T1110":
        for _ in range(rng.randint(8, 25)):
            out.append(ev(t, "windows", user, ctx["ext_ip"], ip, host, "logon_failure", None))
            t += timedelta(seconds=rng.randint(2, 15))
    elif tech == "T1078":
        out.append(ev(t, "windows", user, ctx["ext_ip"], ip, host, "logon_success", None))
    elif tech == "T1059.001":
        proc_run(["powershell.exe"], 1, 3)
    elif tech == "T1068":
        out.append(ev(t, "windows", user, ip, None, host, "privilege_change",
                      rng.choice(["spoolsv.exe", "svchost.exe", "msiexec.exe"])))
    elif tech == "T1003.001":
        proc_run(["procdump.exe", "rundll32.exe"])
        if rng.random() < 0.6:  # dumped credentials include the admin's
            ctx["user"] = ADMIN_USER
    elif tech == "T1082":
        proc_run(["systeminfo.exe", "whoami.exe"], 1, 2)
    elif tech == "T1083":
        proc_run(["cmd.exe", "tree.com"], 1, 3)
    elif tech == "T1053.005":
        proc_run(["schtasks.exe"])
    elif tech == "T1070.001":
        proc_run(["wevtutil.exe"])
    elif tech in ("T1021.001", "T1021.002"):
        target = rng.choice([d for d in SERVERS if d != host])
        action = "rdp_session" if tech == "T1021.001" else "smb_session"
        out.append(ev(t, "windows", ctx["user"], ip, DEVICE_IP[target], target, action, None))
        ctx["host"] = target
    elif tech == "T1005":
        tool = rng.choice(["robocopy.exe", "xcopy.exe", "7z.exe"])
        for _ in range(rng.randint(2, 5)):
            out.append(ev(t, "windows", user, ip, None, host, "file_access", tool))
            t += timedelta(seconds=rng.randint(10, 60))
    elif tech == "T1041":
        dst = ctx["ext_ip"] if rng.random() < 0.5 else ctx["exfil_ip"]
        for _ in range(rng.randint(1, 3)):
            out.append(ev(t, "firewall", user, ip, dst, host, "network_connection", None))
            t += timedelta(seconds=rng.randint(20, 120))
    else:
        raise ValueError(f"no event template for {tech}")

    for e in out:
        e["technique"] = tech
    return out, t


def build_incident(rng, pattern, variant):
    """One attack instance at a random time, as a list of labelled events."""
    seq, skipped, inserted = apply_variant(rng, pattern, variant)

    user = rng.choice(list(STAFF))
    if pattern == "D":  # brute force hits whatever is reachable
        host = rng.choice(list(STAFF.values()) + ["SRV-FILE01", "SRV-DB01"])
    else:
        host = STAFF[user]
    ext_ip, exfil_ip = rng.sample(ATTACKER_IPS, 2)
    ctx = {"user": user, "host": host, "ext_ip": ext_ip, "exfil_ip": exfil_ip}

    if pattern == "B":  # needs the victim at their desk to open the attachment
        day = rng.choice([d for d in range(NUM_DAYS)
                          if (START_DAY + timedelta(days=d)).weekday() < 5])
        t = START_DAY + timedelta(days=day, hours=9, seconds=rng.randint(0, 6 * 3600))
    else:
        t = START_DAY + timedelta(days=rng.randrange(NUM_DAYS), seconds=rng.randint(0, 22 * 3600))

    slow = rng.random() < 0.2  # low-and-slow operator
    events = []
    for tech in seq:
        step, t = step_events(rng, tech, ctx, t)
        events += step
        gap = rng.randint(900, 2700) if slow else rng.randint(60, 720)
        t += timedelta(seconds=gap)

    return {
        "pattern": pattern, "variant": variant, "skipped": skipped,
        "inserted": inserted, "pace": "slow" if slow else "fast",
        "techniques": seq, "events": events,
    }


def overlaps(a, b, margin=timedelta(hours=3)):
    """True if two incidents touch the same user or device close in time; such
    pairs would make the ground-truth grouping itself ambiguous."""
    a0, a1 = a["events"][0]["ts"], a["events"][-1]["ts"]
    b0, b1 = b["events"][0]["ts"], b["events"][-1]["ts"]
    if a0 - margin > b1 or b0 - margin > a1:
        return False
    ents = lambda inc: ({e["user"] for e in inc["events"]} | {e["device"] for e in inc["events"]})
    return bool(ents(a) & ents(b))


def attack_incidents(rng):
    plan = []
    for pattern in sorted(PATTERNS):
        variants = list(VARIANT_PLAN)
        rng.shuffle(variants)
        plan += [(pattern, v) for v in variants]
    rng.shuffle(plan)

    incidents = []
    for pattern, variant in plan:
        while True:
            inc = build_incident(rng, pattern, variant)
            if not any(overlaps(inc, other) for other in incidents):
                break
        incidents.append(inc)

    incidents.sort(key=lambda inc: inc["events"][0]["ts"])
    for n, inc in enumerate(incidents, 1):
        inc["incident_id"] = f"INC-{n:03d}"
    return incidents


# ----------------------------------------------------------------------------
# Assemble, validate, write
# ----------------------------------------------------------------------------

def iso(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def assemble(seed):
    rng = random.Random(seed)
    benign = benign_events(rng)
    incidents = attack_incidents(rng)

    everything = list(benign)
    for inc in incidents:
        everything += inc["events"]
    # random tie-break so same-second ordering carries no hint about origin
    for e in everything:
        e["tie"] = rng.random()
    everything.sort(key=lambda e: (e["ts"], e["tie"]))
    for n, e in enumerate(everything, 1):
        e["event_id"] = f"evt-{n:05d}"

    events = [
        {**{k: e.get(k) for k in EVENT_KEYS}, "timestamp": iso(e["ts"])}
        for e in everything
    ]
    labels = [
        {
            "event_id": e["event_id"],
            "technique_id": e["technique"],
            "technique_name": TECHNIQUES[e["technique"]][0],
            "tactic": TECHNIQUES[e["technique"]][1],
            "confidence": 1.0,
        }
        for e in everything if "technique" in e
    ]
    truth = [
        {
            "incident_id": inc["incident_id"],
            "pattern": inc["pattern"],
            "variant": inc["variant"],
            "skipped": inc["skipped"],
            "inserted": inc["inserted"],
            "pace": inc["pace"],
            "start": iso(inc["events"][0]["ts"]),
            "end": iso(inc["events"][-1]["ts"]),
            "techniques": inc["techniques"],
            "event_ids": [e["event_id"] for e in inc["events"]],
        }
        for inc in incidents
    ]
    return events, labels, truth


def validate(events, labels, truth):
    """Fail loudly if anything drifts from contracts 1 and 2."""
    ids = set()
    for e in events:
        assert list(e) == EVENT_KEYS, f"event keys drifted: {list(e)}"
        for k, v in e.items():
            assert isinstance(v, str) or (v is None and k in NULLABLE), f"{e['event_id']}.{k}={v!r}"
        assert TS_RE.match(e["timestamp"]), e["timestamp"]
        assert e["event_id"] not in ids, f"duplicate {e['event_id']}"
        ids.add(e["event_id"])
    assert [e["timestamp"] for e in events] == sorted(e["timestamp"] for e in events)

    labelled = set()
    for lab in labels:
        assert list(lab) == LABEL_KEYS, f"label keys drifted: {list(lab)}"
        assert lab["event_id"] in ids and lab["event_id"] not in labelled
        assert TECHNIQUES[lab["technique_id"]] == (lab["technique_name"], lab["tactic"])
        assert isinstance(lab["confidence"], float) and 0.0 <= lab["confidence"] <= 1.0
        labelled.add(lab["event_id"])

    grouped = [eid for inc in truth for eid in inc["event_ids"]]
    assert len(grouped) == len(set(grouped)), "an event is in two incidents"
    assert set(grouped) == labelled, "incidents.json and labels.json disagree"


def write_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def summarize(events, labels, truth):
    n, a = len(events), len(labels)
    print(f"events: {n}   attack: {a} ({a / n:.1%})   benign: {n - a}")
    print(f"time range: {events[0]['timestamp']} .. {events[-1]['timestamp']}")
    print(f"users: {len({e['user'] for e in events})}   "
          f"devices: {len({e['device'] for e in events})}   incidents: {len(truth)}")

    print("\nevents by action (total / attack):")
    attack_ids = {lab["event_id"] for lab in labels}
    total = Counter(e["action"] for e in events)
    attack = Counter(e["action"] for e in events if e["event_id"] in attack_ids)
    for action in sorted(total):
        print(f"  {action:<20}{total[action]:>6}{attack[action]:>6}")

    print("\nattack events by technique:")
    for tech, count in sorted(Counter(lab["technique_id"] for lab in labels).items()):
        print(f"  {tech:<11}{TECHNIQUES[tech][0]:<40}{count:>5}")

    print("\nincidents per pattern / variant:")
    for pattern in sorted(PATTERNS):
        variants = Counter(inc["variant"] for inc in truth if inc["pattern"] == pattern)
        detail = ", ".join(f"{v}={c}" for v, c in sorted(variants.items()))
        print(f"  {pattern}: {sum(variants.values())}  ({detail})")

    print("\nincidents:")
    for inc in truth:
        print(f"  {inc['incident_id']} {inc['pattern']} {inc['variant']:<12}{inc['pace']:<5}"
              f"{inc['start']}  {len(inc['event_ids']):>3} ev  {' > '.join(inc['techniques'])}")


def main():
    here = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out-dir", type=Path, default=here.parent / "processed")
    args = parser.parse_args()

    events, labels, truth = assemble(args.seed)
    validate(events, labels, truth)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_json(args.out_dir / "events.json", events)
    write_json(args.out_dir / "labels.json", labels)
    write_json(args.out_dir / "incidents.json", truth)

    summarize(events, labels, truth)
    print(f"\nwrote events.json, labels.json, incidents.json to {args.out_dir}")


if __name__ == "__main__":
    main()

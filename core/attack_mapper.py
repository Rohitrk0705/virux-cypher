"""Deterministic rule-based ATT&CK mapper.

Input:  Normalized Events (contract 1), in any order.
Output: Attack Technique records (contract 2) for the events a rule matched.

No LLM and no ground-truth labels. A rule sees the event's own attributes plus
a small amount of deterministic context computed from other events:
  - failure bursts        (many logon failures from one source to one host)
  - session origin        (where the acting user's session on a host came from)
  - destination history   (when the organisation first connected out to an
                           external address)
  - logon history         (external addresses a user has logged in from before)
  - follow-up execution   (an Office app followed by a script host or dumper)

The mapper works on a complete batch of events. Two rules look FORWARD in
time: a logon failure is judged by the burst around it, and an Office launch
is only mapped once a script host or dumper follows it. A streaming version
would have to emit those mappings late.

Technique names and tactics come from MITRE ATT&CK (data/mitre/techniques.json).
Confidence values are fixed per rule and hand-assigned; they are not calibrated
probabilities.

  python -m core.attack_mapper        # writes data/processed/mapped.json
"""

import json
from bisect import bisect_left, bisect_right
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from . import environment as env

ROOT = Path(__file__).resolve().parent.parent
TECHNIQUES_FILE = ROOT / "data" / "mitre" / "techniques.json"
EVENTS_FILE = ROOT / "data" / "processed" / "events.json"
MAPPED_FILE = ROOT / "data" / "processed" / "mapped.json"

BURST_MIN_FAILURES = 5
BURST_WINDOW = 10 * 60
NEW_DESTINATION_WINDOW = 60 * 60   # an address first contacted this recently is "new"
FOLLOW_UP_WINDOW = 60 * 60
PHISH_LOOKBACK = 60 * 60

OFFICE_APPS = {"winword.exe", "excel.exe", "powerpnt.exe"}
SCRIPT_HOSTS_AND_DUMPERS = {
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
    "rundll32.exe", "procdump.exe",
}
COPY_TOOLS = {"robocopy.exe", "xcopy.exe"}

# process name -> (technique, tactic, confidence). The tactic must be one of
# the technique's ATT&CK tactics; this is checked when the mapper is created.
PROCESS_RULES = {
    "powershell.exe": ("T1059.001", "Execution", 0.80),
    "cmd.exe": ("T1059.003", "Execution", 0.60),
    "procdump.exe": ("T1003.001", "Credential Access", 0.85),
    "rundll32.exe": ("T1218.011", "Stealth", 0.60),
    "systeminfo.exe": ("T1082", "Discovery", 0.80),
    "whoami.exe": ("T1033", "Discovery", 0.80),
    "tree.com": ("T1083", "Discovery", 0.75),
    "schtasks.exe": ("T1053.005", "Persistence", 0.75),
    "wevtutil.exe": ("T1685.005", "Defense Impairment", 0.80),
    "7z.exe": ("T1560.001", "Collection", 0.70),
}

RULES_DOC = [
    ("T1110", "logon_failure inside a burst: >= 5 failures from one source address to one host within 10 minutes"),
    ("T1078", "logon_success from an external address this user has never logged in from before"),
    ("T1204.002", "the last Office application the user started on a host in the 60 minutes before they run a script host or dumper there"),
    ("T1566.001", "the last external e-mail the user received in the 60 minutes before a T1204.002 event"),
    ("T1068", "privilege_change outside an expected administrator session"),
    ("T1021.001", "rdp_session outside an expected administrator or service session"),
    ("T1021.002", "smb_session outside an expected administrator or service session"),
    ("T1005", "file_access performed with a copy tool (robocopy, xcopy) outside an expected service session"),
    ("T1041", "outbound connection to an external address that no internal host had contacted until the last hour "
              "(a new destination), when the source is a server (T1041-server) or it is outside business hours "
              "(T1041-offhours). Contract 1 carries no byte counts or ports, so volume cannot be used; a "
              "repeat-connection proxy for volume was tried and removed (20 true vs 909 false positives over 13 seeds)."),
    ("(process table)", "process_execution of a dual-use tool outside an expected administrator or service session: "
                        + ", ".join(f"{p} -> {t[0]}" for p, t in PROCESS_RULES.items())),
]


def process_name(event):
    """Lower-case file name of the event's process, or None."""
    process = event.get("process")
    return process.replace("/", "\\").split("\\")[-1].lower() if process else None


def epoch(timestamp):
    return int(datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp())


class AttackMapper:
    def __init__(self, techniques_file=TECHNIQUES_FILE):
        self.attack = json.loads(Path(techniques_file).read_text())
        for technique, tactic, _ in PROCESS_RULES.values():
            self._check(technique, tactic)

    def _check(self, technique, tactic):
        entry = self.attack.get(technique)
        if entry is None:
            raise ValueError(f"{technique} is not a current ATT&CK technique")
        if tactic not in entry["tactics"]:
            raise ValueError(f"{tactic} is not a tactic of {technique}: {entry['tactics']}")

    def _record(self, event, technique, tactic, confidence):
        self._check(technique, tactic)
        return {
            "event_id": event["event_id"],
            "technique_id": technique,
            "technique_name": self.attack[technique]["name"],
            "tactic": tactic,
            "confidence": confidence,
        }

    # -- context -------------------------------------------------------------

    @staticmethod
    def _burst_members(events):
        """event_ids of logon failures that are part of a burst."""
        by_key = defaultdict(list)
        for e in events:
            if e["action"] == "logon_failure":
                by_key[(e["source_ip"], e["device"])].append(e)
        members = set()
        for group in by_key.values():
            times = [e["_ts"] for e in group]  # events arrive sorted by time
            for i, e in enumerate(group):
                # does any 10-minute window containing this failure hold enough of them?
                first = bisect_left(times, e["_ts"] - BURST_WINDOW)
                if any(bisect_right(times, times[j] + BURST_WINDOW) - j >= BURST_MIN_FAILURES
                       for j in range(first, i + 1)):
                    members.add(e["event_id"])
        return members

    @staticmethod
    def _expected_session(event, origin):
        """True when the acting account is an administrator or service account
        working from where it is supposed to. origin is the source address of
        the account's current session on this host (set by a logon or remote
        session, cleared by a logoff), or None if no session start was seen.
        Known gap: one session per (user, host); if an attacker and the real
        administrator are on the same host at once, the later logon wins."""
        user, device = event["user"], event["device"]
        for accounts in (env.ADMIN_WORKSTATIONS, env.SERVICE_ACCOUNTS):
            home = accounts.get(user)
            if home is None:
                continue
            if device == home["device"]:
                return origin in (None, home["ip"])
            return origin == home["ip"]
        return False

    # -- mapping -------------------------------------------------------------

    def map_events(self, events):
        return self.map_with_rules(events)[0]

    def map_with_rules(self, events):
        """Returns (contract-2 records, {event_id: name of the rule that fired})."""
        events = sorted(({**e, "_ts": epoch(e["timestamp"]), "_proc": process_name(e)} for e in events),
                        key=lambda e: (e["_ts"], e["event_id"]))
        bursts = self._burst_members(events)

        # Office launches that are followed by a script host or dumper: for each
        # such follow-up, only the nearest preceding Office launch by the same
        # user on the same host within the window.
        last_office = {}
        opened_document = set()
        for e in events:
            if e["action"] != "process_execution":
                continue
            key = (e["user"], e["device"])
            if e["_proc"] in OFFICE_APPS:
                last_office[key] = e
            elif e["_proc"] in SCRIPT_HOSTS_AND_DUMPERS and key in last_office:
                if e["_ts"] - last_office[key]["_ts"] <= FOLLOW_UP_WINDOW:
                    opened_document.add(last_office[key]["event_id"])

        session = {}               # (user, device) -> origin ip of the current session
        logon_sources = defaultdict(set)   # user -> external addresses they have logged in from
        first_contact = {}         # external address -> time of the first outbound connection to it
        mail = defaultdict(list)   # user -> external e-mails received so far
        out, rules = {}, {}

        for e in events:
            action, process, ts = e["action"], e["_proc"], e["_ts"]
            key = (e["user"], e["device"])

            if action in ("logon_success", "rdp_session", "smb_session"):
                session[key] = e["source_ip"]
            elif action == "logoff":
                session.pop(key, None)
            expected = self._expected_session(e, session.get(key))

            hit = rule = None
            if action == "logon_failure":
                if e["event_id"] in bursts:
                    hit = ("T1110", "Credential Access", 0.90)
            elif action == "logon_success":
                if not env.is_internal(e["source_ip"]):
                    if e["source_ip"] not in logon_sources[e["user"]]:
                        hit = ("T1078", "Initial Access", 0.60)
                    logon_sources[e["user"]].add(e["source_ip"])
            elif action == "email_received":
                if not env.is_internal(e["source_ip"]):
                    mail[e["user"]].append(e)
            elif action == "privilege_change":
                if not expected:
                    hit = ("T1068", "Privilege Escalation", 0.60)
            elif action == "rdp_session":
                if not expected:
                    hit = ("T1021.001", "Lateral Movement", 0.75)
            elif action == "smb_session":
                if not expected:
                    hit = ("T1021.002", "Lateral Movement", 0.75)
            elif action == "file_access":
                if process in COPY_TOOLS and not expected:
                    hit = ("T1005", "Collection", 0.65)
                elif process in PROCESS_RULES and not expected:
                    hit = PROCESS_RULES[process]
            elif action == "network_connection":
                dst = e["destination_ip"]
                if dst is not None and not env.is_internal(dst):
                    new_destination = ts - first_contact.setdefault(dst, ts) <= NEW_DESTINATION_WINDOW
                    if new_destination:
                        if e["device"] in env.SERVERS:
                            hit, rule = ("T1041", "Exfiltration", 0.50), "T1041-server"
                        elif not env.business_hours(ts):
                            hit, rule = ("T1041", "Exfiltration", 0.45), "T1041-offhours"
            elif action == "process_execution":
                if process in OFFICE_APPS:
                    if e["event_id"] in opened_document:
                        hit = ("T1204.002", "Execution", 0.55)
                        recent = [m for m in mail[e["user"]] if ts - m["_ts"] <= PHISH_LOOKBACK]
                        if recent and recent[-1]["event_id"] not in out:
                            out[recent[-1]["event_id"]] = self._record(
                                recent[-1], "T1566.001", "Initial Access", 0.45)
                            rules[recent[-1]["event_id"]] = "T1566.001"
                elif process in PROCESS_RULES and not expected:
                    hit, rule = PROCESS_RULES[process], f"process:{process}"

            if hit:
                out[e["event_id"]] = self._record(e, *hit)
                rules[e["event_id"]] = rule or hit[0]

        return [out[k] for k in sorted(out)], rules


def main():
    events = json.loads(EVENTS_FILE.read_text())
    mapped = AttackMapper().map_events(events)
    MAPPED_FILE.write_text(json.dumps(mapped, indent=2) + "\n")
    print(f"mapped {len(mapped)} of {len(events)} events -> {MAPPED_FILE.relative_to(ROOT)}")
    print("\nrules:")
    for technique, rule in RULES_DOC:
        print(f"  {technique:<16}{rule}")


if __name__ == "__main__":
    main()

"""Render the synthetic dataset as raw log lines, the input of Agent 1.

  python data/generator/raw_logs.py            # data/processed/events.json -> data/raw/events.log

The generator writes Normalized Events directly, so the project had no raw logs
to parse. This script writes each synthetic event the way its source would
have logged it: Windows Security events as winlogbeat JSON, firewall and mail
events as key=value lines (formats: agents/log_agent/parsers.py). Labels never
enter a line. What the event does not hold is made up as fixed decoration: the
domain, the logon type (2 local, 8 or 3 remote, 10 for RDP), a share name, the
firewall's name and protocol, and one program directory for every program.

This is a test fixture, not data: the renderer and the parsers have one
author, so parsing these lines back says the software round-trips, nothing
about real logs.
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
DOMAIN = "BANK"
MAIL_DOMAIN = "bank.example"


def _windows(event):
    remote = event["destination_ip"] is not None
    data = {}
    action = event["action"]
    if action in ("logon_success", "logon_failure", "logoff", "rdp_session"):
        data["TargetUserName"] = event["user"]
        data["TargetDomainName"] = DOMAIN
    else:
        data["SubjectUserName"] = f"{DOMAIN}\\{event['user']}"
    if action == "logon_success":
        code, data["LogonType"] = 4624, "8" if remote else "2"
    elif action == "rdp_session":
        code, data["LogonType"] = 4624, "10"
    elif action == "logon_failure":
        code, data["LogonType"] = 4625, "3" if remote else "2"
    elif action == "logoff":
        code = 4634
    elif action == "process_execution":
        code, data["NewProcessName"] = 4688, f"C:\\Windows\\System32\\{event['process']}"
    elif action == "privilege_change":
        code, data["ProcessName"] = 4673, f"C:\\Windows\\System32\\{event['process']}"
    elif action == "smb_session":
        code, data["ShareName"] = 5140, "\\\\*\\share"
    elif action == "file_access" and remote:
        code, data["ShareName"] = 5145, "\\\\*\\share"
    elif action == "file_access":
        code = 4663
        data["ProcessName"] = f"C:\\Windows\\System32\\{event['process']}" if event["process"] else "-"
    else:
        raise ValueError(f"no Windows rendering for action {action!r}")
    if action in ("logon_success", "logon_failure", "rdp_session", "smb_session") or code == 5145:
        data["IpAddress"] = event["source_ip"] if remote else "-"
    return json.dumps({
        "@timestamp": event["timestamp"],
        "event": {"id": event["event_id"]},
        "host": {"name": event["device"], "ip": [event["destination_ip"] if remote else event["source_ip"]]},
        "winlog": {"channel": "Security", "event_id": code, "event_data": data},
    })


def render(event):
    """One Normalized Event as the raw log line its source would have written."""
    if event["source"] == "windows":
        return _windows(event)
    if event["source"] == "firewall" and event["action"] == "network_connection":
        return (f"{event['timestamp']} fw01 id={event['event_id']} action=allow proto=tcp "
                f"src={event['source_ip']} dst={event['destination_ip']} "
                + "".join(f"{key}={event[field]} " for key, field in (("dport", "destination_port"), ("sent", "byte_count"))
                          if event.get(field) is not None)
                + f"srcuser={event['user']} srchost={event['device']}")
    if event["source"] == "email" and event["action"] == "email_received":
        return (f"{event['timestamp']} {event['device']} id={event['event_id']} event=delivered "
                f"client={event['source_ip']} rcpt={event['user']}@{MAIL_DOMAIN} "
                f"dst={event['destination_ip']} dport={event['destination_port']}")
    raise ValueError(f"no rendering for source {event['source']!r}, action {event['action']!r}")


def main():
    source = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "processed" / "events.json"
    target = ROOT / "data" / "raw" / "events.log"
    lines = [render(event) for event in json.loads(source.read_text())]
    target.write_text("\n".join(lines) + "\n")
    print(f"wrote {len(lines)} raw log lines to {target}")


if __name__ == "__main__":
    main()

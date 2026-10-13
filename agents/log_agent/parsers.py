"""Deterministic raw-log parsers for Agent 1 (Log Intelligence).

One raw record in, one Normalized Event (contract 1) out, or a Reject carrying a
fixed reason code. A record that lacks a required field is rejected, never
completed with an invented value. What a parser DERIVES or normalises, in full:

  - `destination_port`: 3389 for an RDP logon, 445 for a share session
  - `event_id`: a hash of the record when it carries none (re-ingesting the
    same line replaces the same event)
  - `timestamp`: converted to UTC and cut to whole seconds
  - `user`: domain prefix or mail domain removed, lower case (so the same name
    in two domains becomes one user)
  - `device`: first label of the host name, upper case
  - `process`: file name of the program path, lower case
  - the host's address: the FIRST entry of `host.ip` (winlogbeat may list a
    link-local address first; that is not corrected)
  - who is source and who is destination: a remote `IpAddress` is the source
    and the host the destination; otherwise the host is the source

Known weak mappings, none of them exercised on real logs: 4673 (a privileged
service was called, frequent on real hosts) -> privilege_change, which the
mapper can turn into T1068; 4663 -> file_access without looking at the object
type; logon type 3 -> network_logon, an action no mapper rule uses.

Formats (a raw record is a log line, or the JSON object such a line holds):

  normalized_json     already a contract-1 object; only validated
  windows_event_json  Windows Security events as shipped by winlogbeat (ECS):
                      {"@timestamp", "host": {"name", "ip"}, "event": {"id"},
                       "winlog": {"channel", "event_id", "event_data": {...}}}
  firewall_kv         "<time> <firewall> id=.. action=allow src=.. dst=.. dport=.. sent=.. srcuser=.. srchost=.."
  mail_kv             "<time> <mail host> id=.. event=delivered client=.. rcpt=user@domain dst=.. dport=.."

The Windows field names and event ids are Microsoft's; the two key=value
layouts are generic stand-ins written for this project, not a vendor's format.
The only raw logs these parsers have been run on are renderings of the
synthetic dataset (data/generator/raw_logs.py) by the same author, so a clean
round trip is a software test, not evidence about real logs. Real Sysmon and
Security telemetry is handled by data/adapters/otrf.py (see docs/real-data.md).
"""

import hashlib
import json
import re
from datetime import datetime, timezone

CONTRACT_REQUIRED = ["event_id", "timestamp", "source", "user", "source_ip",
                     "destination_ip", "device", "action", "process"]
LOCAL_ADDRESSES = {None, "", "-", "::1", "127.0.0.1"}
KV_LINE = re.compile(r"^(\S+)\s+(\S+)\s+(\w+=\S*(?:\s+\w+=\S*)*)\s*$")

# Security event id -> (action, field holding the account, field holding the image, can be remote)
WINDOWS_EVENTS = {
    4624: ("logon_success", "TargetUserName", None, True),     # refined by LogonType below
    4625: ("logon_failure", "TargetUserName", None, True),
    4634: ("logoff", "TargetUserName", None, False),
    4647: ("logoff", "TargetUserName", None, False),
    4688: ("process_execution", "SubjectUserName", "NewProcessName", False),
    4663: ("file_access", "SubjectUserName", "ProcessName", False),
    4673: ("privilege_change", "SubjectUserName", "ProcessName", False),
    5140: ("smb_session", "SubjectUserName", None, True),
    5145: ("file_access", "SubjectUserName", None, True),
}
LOGON_TYPES = {"10": "rdp_session", "3": "network_logon"}      # every other type: logon_success
DERIVED_PORT = {"rdp_session": 3389, "smb_session": 445}


class Reject(Exception):
    """A record a parser cannot turn into an event. `code` is one of a fixed set of strings."""

    def __init__(self, code):
        super().__init__(code)
        self.code = code


def load(record):
    """A raw record as the parsers see it: a line holding a JSON object becomes that object."""
    if isinstance(record, str):
        record = record.strip()
        if record.startswith("{"):
            try:
                parsed = json.loads(record)
            except json.JSONDecodeError:
                return record
            return parsed if isinstance(parsed, dict) else record
    return record


def _kv(line):
    """(time, host, {key: value}) of a key=value line, or None."""
    found = KV_LINE.match(line) if isinstance(line, str) else None
    if not found:
        return None
    pairs = [pair.split("=", 1) for pair in found.group(3).split()]
    if len({key for key, _ in pairs}) != len(pairs):
        return None                                   # a repeated key: which value is meant is a guess
    return found.group(1), found.group(2), dict(pairs)


def detect(record):
    """The format a record appears to be in, or 'unknown'. Looks at structure only."""
    if isinstance(record, dict):
        if all(key in record for key in CONTRACT_REQUIRED):
            return "normalized_json"
        if isinstance(record.get("winlog"), dict):
            return "windows_event_json"
        return "unknown"
    fields = _kv(record)
    if fields and {"src", "dst"} <= set(fields[2]):
        return "firewall_kv"
    if fields and "rcpt" in fields[2]:
        return "mail_kv"
    return "unknown"


def _timestamp(value):
    """Contract-1 time (UTC, whole seconds) from an ISO 8601 time that states its zone."""
    try:
        moment = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise Reject("bad timestamp") from None
    if moment.tzinfo is None:
        raise Reject("timestamp without time zone")
    try:
        return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, ValueError):
        raise Reject("bad timestamp") from None


def _event_id(explicit, record):
    if isinstance(explicit, str) and explicit:
        return explicit
    canonical = json.dumps(record, sort_keys=True) if isinstance(record, dict) else str(record)
    return "evt-" + hashlib.sha1(canonical.encode()).hexdigest()[:16]


def _text(value, missing):
    if not isinstance(value, str) or value.strip() in ("", "-"):
        raise Reject(missing)
    return value.strip()


def _number(value):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, str)) or not re.fullmatch(r"[0-9]{1,15}", str(value)):
        raise Reject("bad number")
    return int(value)


def _image(value):
    """File name of a program path, lower case; None when the event names no program."""
    if not isinstance(value, str) or value.strip() in ("", "-"):
        return None
    return value.replace("/", "\\").split("\\")[-1].strip().lower() or None


def parse_normalized_json(record):
    if not isinstance(record, dict):
        raise Reject("not a JSON object")
    return dict(record)


def parse_windows_event_json(record):
    if not isinstance(record, dict) or not isinstance(record.get("winlog"), dict):
        raise Reject("not a Windows event record")
    winlog, host = record["winlog"], record.get("host") if isinstance(record.get("host"), dict) else {}
    data = winlog.get("event_data") if isinstance(winlog.get("event_data"), dict) else {}
    if winlog.get("channel") != "Security":
        raise Reject("unsupported channel")
    try:
        kind = WINDOWS_EVENTS[_number(winlog.get("event_id"))]
    except (KeyError, Reject):
        raise Reject("unsupported event type") from None
    action, user_field, image_field, can_be_remote = kind
    if action == "logon_success":
        action = LOGON_TYPES.get(str(data.get("LogonType")), action)
    addresses = host.get("ip")
    host_ip = _text(addresses[0] if isinstance(addresses, list) and addresses else addresses, "no host address")
    process = _image(data.get(image_field)) if image_field else None
    if action == "process_execution" and process is None:
        raise Reject("no process name")
    remote = data.get("IpAddress") if can_be_remote else None
    if remote is not None and not isinstance(remote, str):
        raise Reject("bad address")
    remote = None if remote in LOCAL_ADDRESSES else _text(remote, "bad address")
    event = record.get("event") if isinstance(record.get("event"), dict) else {}
    return {
        "event_id": _event_id(event.get("id"), record),
        "timestamp": _timestamp(record.get("@timestamp")),
        "source": "windows",
        "user": _text(data.get(user_field), "no user").split("\\")[-1].lower(),
        "source_ip": remote or host_ip,
        "destination_ip": host_ip if remote else None,
        "device": _text(host.get("name"), "no device").split(".")[0].upper(),
        "action": action,
        "process": process,
        "destination_port": DERIVED_PORT.get(action) if remote else None,
        "byte_count": None,
    }


def parse_firewall_kv(record):
    fields = _kv(record)
    if not fields:
        raise Reject("not a key=value line")
    time, _, kv = fields
    if kv.get("action") != "allow":
        raise Reject("unsupported event type")         # denied connections are not represented
    return {
        "event_id": _event_id(kv.get("id"), record),
        "timestamp": _timestamp(time),
        "source": "firewall",
        "user": _text(kv.get("srcuser"), "no user").lower(),
        "source_ip": _text(kv.get("src"), "bad address"),
        "destination_ip": _text(kv.get("dst"), "bad address"),
        "device": _text(kv.get("srchost"), "no device").upper(),
        "action": "network_connection",
        "process": None,
        "destination_port": _number(kv.get("dport")),
        "byte_count": _number(kv.get("sent")),
    }


def parse_mail_kv(record):
    fields = _kv(record)
    if not fields:
        raise Reject("not a key=value line")
    time, host, kv = fields
    if kv.get("event") != "delivered":
        raise Reject("unsupported event type")
    return {
        "event_id": _event_id(kv.get("id"), record),
        "timestamp": _timestamp(time),
        "source": "email",
        "user": _text(kv.get("rcpt"), "no user").split("@")[0].lower(),
        "source_ip": _text(kv.get("client"), "bad address"),
        "destination_ip": _text(kv.get("dst"), "bad address"),
        "device": _text(host, "no device").upper(),
        "action": "email_received",
        "process": None,
        "destination_port": _number(kv.get("dport")),
        "byte_count": None,
    }


PARSERS = {
    "normalized_json": parse_normalized_json,
    "windows_event_json": parse_windows_event_json,
    "firewall_kv": parse_firewall_kv,
    "mail_kv": parse_mail_kv,
}


def _contract():
    # The API's model is the one strict statement of contract 1 (bounds included); reuse it.
    from backend.api.schemas import NormalizedEvent
    return NormalizedEvent


def parse(parser, record):
    """Run one named parser on one loaded record and validate the result against
    contract 1. Returns the event, or raises Reject: a record that makes a
    parser fail in any other way is rejected as malformed, never a crash."""
    from pydantic import ValidationError
    try:
        event = PARSERS[parser](record)
    except Reject:
        raise
    except Exception:  # noqa: BLE001 - raw records are untrusted; one bad record must not lose the batch
        raise Reject("malformed record") from None
    try:
        return _contract().model_validate(event).model_dump()
    except ValidationError:
        raise Reject("fails contract 1") from None

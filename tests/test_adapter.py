"""Milestone 9: the real-data adapter and the mapper's handling of real Windows events.
These tests build a tiny fake dataset; they do not need the external datasets."""

import json
import zipfile

import pytest

from core.attack_mapper import AttackMapper
from core.environment import BANK, PANDALAB
from data.adapters import otrf

SYSMON = "Microsoft-Windows-Sysmon/Operational"
HOST = "WS9.lab.example"


def raw(event_id, second, channel=SYSMON, **fields):
    return {"Channel": channel, "EventID": str(event_id), "Hostname": HOST,
            "@timestamp": f"2023-08-15T05:33:{second:02d}.123Z", **fields}


RAW = [
    raw(3, 1, User="LAB\\alice", Image="C:\\Windows\\System32\\svchost.exe", Initiated="true",
        SourceIp="192.168.1.50", SourcePort="50001", DestinationIp="10.0.5.13", DestinationPort="4433"),
    raw(3, 2, User="LAB\\alice", Image="C:\\x\\payload.exe", Initiated="true",
        SourceIp="192.168.1.50", SourcePort="50002", DestinationIp="10.0.5.13", DestinationPort="80"),
    raw(3, 2, User="LAB\\alice", Image="C:\\x\\payload.exe", Initiated="true",
        SourceIp="192.168.1.50", SourcePort="50003", DestinationIp="10.0.5.13", DestinationPort="6666"),
    raw(1, 3, User="LAB\\Alice", Image="C:\\Users\\alice\\Desktop\\Report.PDF.exe", CommandLine="secret args",
        ParentImage="C:\\Windows\\explorer.exe"),
    raw(10, 4, SourceUser="NT AUTHORITY\\SYSTEM", SourceImage="C:\\Windows\\system32\\svchost.exe",
        TargetImage="C:\\Windows\\system32\\lsass.exe"),
    raw(11, 5, User="LAB\\alice", Image="C:\\Windows\\System32\\cmd.exe", TargetFilename="C:\\temp\\dump.dmp"),
    raw(1, 6, Image="C:\\Windows\\System32\\whoami.exe"),                         # no user: cannot be mapped
    raw(7, 7, Image="C:\\Windows\\System32\\x.dll"),                              # image load: no representation
    raw(4624, 8, channel="Security", TargetUserName="bob", LogonType="10", IpAddress="10.0.5.13"),
    raw(4624, 9, channel="Security", TargetUserName="SYSTEM", LogonType="5", IpAddress="-"),
    raw(4625, 10, channel="Security", TargetUserName="bob", LogonType="3", IpAddress="-"),
]
ZEEK = "\n".join([
    "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tmissed_bytes",
    "1.0\tA\t192.168.1.50\t50001\t10.0.5.13\t4433\ttcp\t-\t1\t0\t999\tSHR\t0",       # one-sided: bytes unknown
    "2.0\tB\t192.168.1.50\t50002\t10.0.5.13\t80\ttcp\t-\t1\t31457280\t10\tSF\t0",
    "3.0\tC\t192.168.1.50\t50003\t10.0.5.13\t6666\ttcp\t-\t1\t26310415\t10\tS3\t26310415",   # gap estimate
])
META = """title: test
attack_mappings:
  - technique: T1204
    sub-technique: "002"
    tactics:
      - TA0002
  - technique: T1082
    sub-technique:
    tactics:
      - TA0007
files:
- type: Host
"""


@pytest.fixture
def dataset(tmp_path, monkeypatch):
    folder = tmp_path / "FAKE_01"
    folder.mkdir()
    (tmp_path / "_metadata").mkdir()
    (tmp_path / "_metadata" / "FAKE_01.yaml").write_text(META)
    with zipfile.ZipFile(folder / "host.zip", "w") as z:
        z.writestr("host.json", "\n".join(json.dumps(e) for e in RAW) + "\nnot json\n")
    with zipfile.ZipFile(folder / "capture_zeek_logs.zip", "w") as z:
        z.writestr("conn.log", ZEEK)
    monkeypatch.setattr(otrf, "SOURCE", tmp_path)
    return otrf.adapt("FAKE_01", tag="f1")


def test_output_is_contract_1_in_time_order(dataset):
    events, report = dataset
    keys = ["event_id", "timestamp", "source", "user", "source_ip", "destination_ip", "device", "action",
            "process", "destination_port", "byte_count"]
    assert all(list(e) == keys for e in events)
    assert [e["event_id"] for e in events] == [f"evt-f1-{n:06d}" for n in range(1, len(events) + 1)]
    assert [e["timestamp"] for e in events] == sorted(e["timestamp"] for e in events)
    assert report["raw_events"] == 11 and report["adapted_events"] == 8
    assert report["labels"] == ["T1204.002", "T1082"]


def test_field_mapping(dataset):
    events, report = dataset
    by_action = {e["action"]: e for e in events}
    execution = by_action["process_execution"]
    assert execution["user"] == "alice" and execution["device"] == "WS9"
    assert execution["process"] == "report.pdf.exe" and execution["timestamp"] == "2023-08-15T05:33:03Z"
    assert execution["source_ip"] == "192.168.1.50" and execution["destination_ip"] is None   # host address derived
    assert by_action["process_access"]["user"] == "system" and by_action["process_access"]["process"] == "svchost.exe"
    assert by_action["file_create"]["process"] == "cmd.exe"
    rdp = by_action["rdp_session"]
    assert rdp["user"] == "bob" and rdp["source_ip"] == "10.0.5.13" and rdp["destination_ip"] == "192.168.1.50"
    assert by_action["logon_failure"]["source_ip"] == "192.168.1.50"


def test_byte_count_only_when_the_capture_saw_the_senders_packets(dataset):
    events, _ = dataset
    net = {e["destination_port"]: e for e in events if e["action"] == "network_connection"}
    assert net[4433]["byte_count"] is None            # Zeek saw only the responder; 0 would be a lie
    assert net[80]["byte_count"] == 31457280
    assert net[6666]["byte_count"] is None            # 26 MB "sent" is a sequence-gap estimate, not a count


def test_nothing_is_invented_unmappable_events_are_dropped_and_counted(dataset):
    events, report = dataset
    assert report["dropped"] == {
        "no contract-1 representation for this event type": 1,
        "required field could not be mapped: user": 1,
        "service, batch or system logon (not a user session)": 1,
    }
    assert report["lost"]["... of which the target was lsass.exe"] == 1
    text = json.dumps(events)
    assert list(report["process_lineage"]) == ["evt-f1-000004"]      # beside the events, never inside them
    assert "secret args" not in text and "lsass" not in text and "dump.dmp" not in text and "explorer" not in text


def test_mapper_on_adapted_events_uses_the_lab_environment(dataset):
    events, _ = dataset
    mapped, rules = AttackMapper(environment=PANDALAB).map_with_rules(events)
    by_rule = {rules[m["event_id"]]: m["technique_id"] for m in mapped}
    assert by_rule["T1204.002-double-extension"] == "T1204.002"
    assert by_rule["T1041-volume"] == "T1041"         # 30 MB to an address outside the lab subnets
    assert all(list(m) == ["event_id", "technique_id", "technique_name", "tactic", "confidence"] for m in mapped)


def test_system_accounts_and_unknown_business_hours():
    tool = lambda n, user: {"event_id": f"evt-{n}", "timestamp": "2023-08-15T02:00:00Z", "source": "sysmon",
                            "user": user, "source_ip": "192.168.1.50", "destination_ip": None, "device": "WS9",
                            "action": "process_execution", "process": "reg.exe"}
    mapped = AttackMapper(environment=PANDALAB).map_events([tool(1, "system"), tool(2, "alice")])
    assert [m["event_id"] for m in mapped] == ["evt-2"] and mapped[0]["technique_id"] == "T1012"
    assert PANDALAB.in_business_hours(0) is True      # unknown hours never count as off-hours
    assert BANK.in_business_hours(0) is False         # midnight, 1 January 1970
    assert PANDALAB.is_internal("192.168.56.30") and not PANDALAB.is_internal("10.0.5.13")
    assert BANK.is_internal("10.0.0.5") and not BANK.is_internal("192.168.1.1") and not BANK.is_internal(None)

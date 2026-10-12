"""Milestone 3: rule-based ATT&CK mapper."""

from core.attack_mapper import AttackMapper

LABEL_KEYS = ["event_id", "technique_id", "technique_name", "tactic", "confidence"]


def event(n, minute, action, user="john", device="WS-01", src="10.0.0.11", dst=None,
          process=None, source="windows", second=0):
    return {"event_id": f"evt-{n:05d}", "timestamp": f"2026-09-07T10:{minute:02d}:{second:02d}Z",
            "source": source, "user": user, "source_ip": src, "destination_ip": dst,
            "device": device, "action": action, "process": process}


def mapped(events):
    return {m["event_id"]: m for m in AttackMapper().map_events(events)}


def test_output_is_contract_2_with_attack_names():
    out = AttackMapper().map_events([event(1, 0, "process_execution", process="powershell.exe")])
    assert [list(m) for m in out] == [LABEL_KEYS]
    assert out[0]["technique_id"] == "T1059.001" and out[0]["technique_name"] == "PowerShell"
    assert out[0]["tactic"] == "Execution" and 0 <= out[0]["confidence"] <= 1


def test_failure_burst_is_brute_force_but_two_typos_are_not():
    burst = [event(n, 0, "logon_failure", src="203.0.113.9", dst="10.0.0.11", second=n * 5)
             for n in range(1, 7)]
    typos = [event(n, 30, "logon_failure", second=n) for n in (20, 21)]
    out = mapped(burst + typos)
    assert {out[e["event_id"]]["technique_id"] for e in burst} == {"T1110"}
    assert not any(e["event_id"] in out for e in typos)


def test_external_logon_is_valid_accounts_and_internal_is_not():
    out = mapped([event(1, 0, "logon_success", src="203.0.113.9", dst="10.0.0.11"),
                  event(2, 1, "logon_success")])
    assert out["evt-00001"]["technique_id"] == "T1078" and "evt-00002" not in out


def test_admin_from_own_workstation_is_expected_but_not_from_another():
    admin = dict(user="admin_lee")
    benign = [
        event(1, 0, "logon_success", device="WS-07", src="10.0.0.17", **admin),
        event(2, 1, "process_execution", device="WS-07", src="10.0.0.17", process="powershell.exe", **admin),
        event(3, 2, "rdp_session", device="SRV-DC01", src="10.0.0.17", dst="10.0.0.2", **admin),
        event(4, 3, "process_execution", device="SRV-DC01", src="10.0.0.2", process="powershell.exe", **admin),
    ]
    stolen = [
        event(5, 10, "smb_session", device="SRV-FILE01", src="10.0.0.16", dst="10.0.0.4", **admin),
        event(6, 11, "process_execution", device="SRV-FILE01", src="10.0.0.4", process="wevtutil.exe", **admin),
    ]
    out = mapped(benign + stolen)
    assert not any(e["event_id"] in out for e in benign)
    assert out["evt-00005"]["technique_id"] == "T1021.002"
    assert out["evt-00006"]["technique_id"] == "T1685.005"


def test_office_then_script_host_maps_file_and_phish():
    events = [
        event(1, 0, "email_received", device="SRV-MAIL01", src="198.51.100.9", dst="10.0.0.5", source="email"),
        event(2, 5, "process_execution", process="winword.exe"),
        event(3, 9, "process_execution", process="powershell.exe"),
        event(4, 40, "process_execution", process="excel.exe"),  # nothing follows
    ]
    out = mapped(events)
    assert out["evt-00001"]["technique_id"] == "T1566.001"
    assert out["evt-00002"]["technique_id"] == "T1204.002"
    assert "evt-00004" not in out


def test_mapper_ignores_input_order():
    events = [event(n, 0, "logon_failure", src="203.0.113.9", dst="10.0.0.11", second=n * 5)
              for n in range(1, 7)]
    assert AttackMapper().map_events(events) == AttackMapper().map_events(events[::-1])


def test_mapper_takes_no_labels():
    import inspect
    import core.attack_mapper as module
    source = inspect.getsource(module)
    assert "labels.json" not in source and "incidents.json" not in source


def test_only_the_nearest_office_launch_before_a_script_host_is_mapped():
    events = [event(1, 0, "process_execution", process="excel.exe"),
              event(2, 20, "process_execution", process="winword.exe"),
              event(3, 25, "process_execution", process="powershell.exe")]
    out = mapped(events)
    assert "evt-00001" not in out and out["evt-00002"]["technique_id"] == "T1204.002"


def test_exfiltration_rule_uses_no_attacker_address_knowledge():
    """A logon from an address must not make later traffic to it exfiltration."""
    logon = event(1, 0, "logon_success", src="203.0.113.9", dst="10.0.0.11")
    single = event(2, 5, "network_connection", dst="203.0.113.9", source="firewall")
    assert "evt-00002" not in mapped([logon, single])


def test_exfiltration_by_volume_needs_a_large_upload_and_one_unusual_property():
    MB = 1024 * 1024
    net = lambda n, minute, **kw: event(n, minute, "network_connection", source="firewall", **kw)
    with_size = lambda e, size, port=443: {**e, "byte_count": size, "destination_port": port}
    out, rules = AttackMapper().map_with_rules([
        with_size(net(1, 0, dst="192.0.2.10"), 2 * MB),                    # first contact, small: no
        with_size(net(2, 1, dst="203.0.113.9"), 500 * MB),                 # large, new destination: yes
        with_size(net(3, 2, dst="203.0.113.50"), 5 * MB),                  # new destination but small: no
    ])
    assert rules == {"evt-00002": "T1041-volume"}
    later = lambda n, **kw: {**net(n, 0, **kw), "timestamp": "2026-09-08T11:00:00Z"}   # next day, daytime
    history = [with_size(net(1, 0, dst="192.0.2.10"), MB)]
    out, rules = AttackMapper().map_with_rules(history + [
        with_size(later(2, dst="192.0.2.10"), 200 * MB),                   # large, but known site, 443, daytime
        with_size(later(3, dst="192.0.2.10"), 200 * MB, port=4444),        # same, non-standard port
    ])
    assert rules == {"evt-00003": "T1041-volume"}


def test_exfiltration_falls_back_when_volume_is_not_recorded():
    net = lambda n, minute, **kw: event(n, minute, "network_connection", source="firewall", **kw)
    out, rules = AttackMapper().map_with_rules([
        net(1, 0, dst="203.0.113.9"), net(2, 3, dst="203.0.113.9"),          # daytime workstation: not mapped
        net(3, 5, device="SRV-DB01", src="10.0.0.3", dst="198.51.100.9"),    # server, new address
        net(4, 6, dst="192.0.2.10"),                                         # single visit
    ])
    assert rules == {"evt-00003": "T1041-server"}
    night = {**net(5, 0, dst="203.0.113.77"), "timestamp": "2026-09-07T02:00:00Z"}
    assert AttackMapper().map_with_rules([night])[1] == {"evt-00005": "T1041-offhours"}


def test_established_destination_is_not_exfiltration():
    net = lambda n, ts: {**event(n, 0, "network_connection", device="SRV-MAIL01", src="10.0.0.5",
                                 dst="192.0.2.100", source="firewall"), "timestamp": ts}
    out = mapped([net(1, "2026-09-07T10:00:00Z"), net(2, "2026-09-07T14:00:00Z"),
                  net(3, "2026-09-08T02:00:00Z")])
    assert set(out) == {"evt-00001"}       # only the very first contact looks new


def test_external_logon_is_only_new_the_first_time_for_a_user():
    home = lambda n, minute: event(n, minute, "logon_success", src="198.18.0.10", dst="10.0.0.11")
    out = mapped([home(1, 0), home(2, 30)])
    assert "evt-00001" in out and "evt-00002" not in out


def test_copy_tool_collection_and_backup_account_exemption():
    attack = event(1, 0, "file_access", process="xcopy.exe")
    backup = [event(2, 1, "logon_success", user="svc_backup", device="SRV-FILE01", src="10.0.0.4"),
              event(3, 2, "file_access", user="svc_backup", device="SRV-FILE01", src="10.0.0.4",
                    process="robocopy.exe")]
    out = mapped([attack] + backup)
    assert out["evt-00001"]["technique_id"] == "T1005" and "evt-00003" not in out


def test_privilege_change_by_staff_is_mapped_but_not_by_admin_at_own_desk():
    out = mapped([event(1, 0, "privilege_change", process="spoolsv.exe"),
                  event(2, 1, "privilege_change", user="admin_lee", device="WS-07", src="10.0.0.17",
                        process="consent.exe")])
    assert out["evt-00001"]["technique_id"] == "T1068" and "evt-00002" not in out


def test_logoff_ends_a_session_and_external_logon_on_admin_desk_is_not_expected():
    admin = dict(user="admin_lee", device="WS-07")
    events = [event(1, 0, "logon_success", src="203.0.113.9", dst="10.0.0.17", **admin),
              event(2, 1, "process_execution", src="10.0.0.17", process="powershell.exe", **admin),
              event(3, 2, "logoff", src="10.0.0.17", **admin),
              event(4, 3, "process_execution", src="10.0.0.17", process="powershell.exe", **admin)]
    out = mapped(events)
    assert out["evt-00002"]["technique_id"] == "T1059.001" and "evt-00004" not in out


def test_process_names_are_case_and_path_insensitive():
    out = mapped([event(1, 0, "process_execution", process="C:\\Windows\\System32\\PowerShell.EXE")])
    assert out["evt-00001"]["technique_id"] == "T1059.001"

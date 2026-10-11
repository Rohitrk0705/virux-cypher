# Data Contracts  (FREEZE THESE BEFORE CODING)

These five JSON shapes are the shared interface. Every module reads/writes these.
Change them only by team agreement.

## 1. Normalized Event
{
  "event_id": "evt-001",
  "timestamp": "2026-10-12T10:30:00Z",
  "source": "windows",
  "user": "john",
  "source_ip": "10.0.0.5",
  "destination_ip": "10.0.0.10",
  "device": "WS-01",
  "action": "process_execution",
  "process": "powershell.exe"
}

## 2. Attack Technique (mapping of an event to ATT&CK)
{
  "event_id": "evt-001",
  "technique_id": "T1059.001",
  "technique_name": "PowerShell",
  "tactic": "Execution",
  "confidence": 0.91
}

## 3. Attack Trajectory (ordered techniques for one incident)
{
  "incident_id": "INC-001",
  "techniques": [
    {"id": "T1078",     "timestamp": "2026-10-12T10:01:00Z"},
    {"id": "T1059.001", "timestamp": "2026-10-12T10:04:00Z"},
    {"id": "T1068",     "timestamp": "2026-10-12T10:07:00Z"}
  ]
}

## 4. Historical Match
{
  "incident_id": "INC-001",
  "matches": [
    {"attack_id": "HIST-017", "similarity": 0.91, "common_techniques": ["T1078","T1059.001","T1068"]},
    {"attack_id": "HIST-024", "similarity": 0.76, "common_techniques": ["T1078","T1059.001"]}
  ]
}

## 5. Prediction
{
  "incident_id": "INC-001",
  "predictions": [
    {"technique_id": "T1021", "probability": 0.78},
    {"technique_id": "T1041", "probability": 0.14}
  ],
  "evidence": [
    "current trajectory matched 14 historical incidents",
    "11 of those continued with T1021",
    "temporal ordering is consistent"
  ]
}

import {
  Health,
  IncidentSummary,
  NormalizedEvent,
  AttackTrajectory,
  HistoricalMatch,
  Prediction,
  IncidentGraph,
  TechniqueInfo,
  EvidenceBundle,
  Report,
} from '../types/contracts';

export const MOCK_HEALTH: Health = {
  status: 'ok',
  service: 'virux-cypher',
  neo4j: true,
  events: 3986,
  incidents: 53,
};

export const MOCK_INCIDENTS: IncidentSummary[] = [
  {
    incident_id: 'INC-03265',
    start: '2026-09-17T03:41:31Z',
    end: '2026-09-17T04:14:51Z',
    event_count: 7,
  },
  {
    incident_id: 'INC-01743',
    start: '2026-09-11T12:59:37Z',
    end: '2026-09-11T13:34:07Z',
    event_count: 6,
  },
  {
    incident_id: 'INC-00017',
    start: '2026-09-07T05:22:11Z',
    end: '2026-09-07T05:53:32Z',
    event_count: 21,
  },
  {
    incident_id: 'INC-00010',
    start: '2026-09-07T03:01:28Z',
    end: '2026-09-07T03:22:34Z',
    event_count: 7,
  },
];

export const MOCK_TECHNIQUES: Record<string, TechniqueInfo> = {
  'T1078': {
    id: 'T1078',
    name: 'Valid Accounts',
    tactic: 'Initial Access',
    description: 'Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.',
  },
  'T1059.001': {
    id: 'T1059.001',
    name: 'PowerShell',
    tactic: 'Execution',
    description: 'Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment built on .NET framework.',
  },
  'T1068': {
    id: 'T1068',
    name: 'Exploitation for Privilege Escalation',
    tactic: 'Privilege Escalation',
    description: 'Adversaries may exploit software vulnerabilities in an attempt to elevate privileges on target systems from standard user to SYSTEM, root, or Administrator.',
  },
  'T1021': {
    id: 'T1021',
    name: 'Remote Services',
    tactic: 'Lateral Movement',
    description: 'Adversaries may use valid accounts to log into a service that is designed to accept remote connections, such as SSH, VNC, or SMB, to move laterally throughout an environment.',
  },
  'T1021.001': {
    id: 'T1021.001',
    name: 'Remote Desktop Protocol',
    tactic: 'Lateral Movement',
    description: 'Adversaries may use Valid Accounts to log into remote machines via Microsoft Remote Desktop Protocol (RDP) on TCP port 3389.',
  },
  'T1041': {
    id: 'T1041',
    name: 'Exfiltration Over C2 Channel',
    tactic: 'Exfiltration',
    description: 'Adversaries may steal data by exfiltrating it over an existing command and control channel to blend in with normal network communications.',
  },
  'T1070.001': {
    id: 'T1685.005',
    name: 'Clear Windows Event Logs',
    tactic: 'Defense Impairment',
    description: 'Adversaries may clear Windows Event Logs to hide the activity of an intrusion and eliminate forensic evidence.',
  },
};

export const MOCK_EVENTS: Record<string, NormalizedEvent[]> = {
  'INC-03265': [
    {
      event_id: 'evt-03265',
      timestamp: '2026-09-17T03:41:31Z',
      source: 'windows',
      user: 'elena',
      source_ip: '203.0.113.120',
      destination_ip: '10.0.0.14',
      device: 'WS-04',
      action: 'logon_success',
      process: null,
      destination_port: null,
      byte_count: null,
    },
    {
      event_id: 'evt-03266',
      timestamp: '2026-09-17T03:49:25Z',
      source: 'windows',
      user: 'elena',
      source_ip: '10.0.0.14',
      destination_ip: null,
      device: 'WS-04',
      action: 'process_execution',
      process: 'powershell.exe',
      destination_port: null,
      byte_count: null,
    },
    {
      event_id: 'evt-03267',
      timestamp: '2026-09-17T03:53:31Z',
      source: 'windows',
      user: 'elena',
      source_ip: '10.0.0.14',
      destination_ip: null,
      device: 'WS-04',
      action: 'privilege_change',
      process: 'powershell.exe',
      destination_port: null,
      byte_count: null,
    },
    {
      event_id: 'evt-03268',
      timestamp: '2026-09-17T04:03:10Z',
      source: 'windows',
      user: 'elena',
      source_ip: '10.0.0.14',
      destination_ip: '10.0.0.2',
      device: 'SRV-DB01',
      action: 'network_connection',
      process: null,
      destination_port: 3389,
      byte_count: 1420,
    },
    {
      event_id: 'evt-03269',
      timestamp: '2026-09-17T04:05:00Z',
      source: 'windows',
      user: 'elena',
      source_ip: '10.0.0.14',
      destination_ip: '10.0.0.2',
      device: 'SRV-DB01',
      action: 'rdp_session',
      process: 'mstsc.exe',
      destination_port: 3389,
      byte_count: 85200,
    },
    {
      event_id: 'evt-03270',
      timestamp: '2026-09-17T04:11:55Z',
      source: 'windows',
      user: 'elena',
      source_ip: '10.0.0.2',
      destination_ip: '198.51.100.77',
      device: 'SRV-DB01',
      action: 'network_connection',
      process: 'curl.exe',
      destination_port: 443,
      byte_count: 1048576,
    },
    {
      event_id: 'evt-03271',
      timestamp: '2026-09-17T04:14:51Z',
      source: 'windows',
      user: 'elena',
      source_ip: '10.0.0.2',
      destination_ip: '198.51.100.77',
      device: 'SRV-DB01',
      action: 'network_connection',
      process: 'curl.exe',
      destination_port: 443,
      byte_count: 52428800,
    },
  ],
  'INC-01743': [
    {
      event_id: 'evt-01743',
      timestamp: '2026-09-11T12:59:37Z',
      source: 'windows',
      user: 'marcus',
      source_ip: '192.168.1.105',
      destination_ip: '10.0.0.5',
      device: 'WS-03',
      action: 'logon_success',
      process: null,
      destination_port: null,
      byte_count: null,
    },
    {
      event_id: 'evt-01744',
      timestamp: '2026-09-11T13:08:14Z',
      source: 'windows',
      user: 'marcus',
      source_ip: '10.0.0.5',
      destination_ip: null,
      device: 'WS-03',
      action: 'process_execution',
      process: 'powershell.exe',
      destination_port: null,
      byte_count: null,
    },
    {
      event_id: 'evt-01745',
      timestamp: '2026-09-11T13:11:10Z',
      source: 'windows',
      user: 'marcus',
      source_ip: '10.0.0.5',
      destination_ip: null,
      device: 'WS-03',
      action: 'privilege_change',
      process: 'powershell.exe',
      destination_port: null,
      byte_count: null,
    },
    {
      event_id: 'evt-01746',
      timestamp: '2026-09-11T13:18:55Z',
      source: 'windows',
      user: 'marcus',
      source_ip: '10.0.0.5',
      destination_ip: '10.0.0.1',
      device: 'SRV-DC01',
      action: 'rdp_session',
      process: 'mstsc.exe',
      destination_port: 3389,
      byte_count: 94000,
    },
    {
      event_id: 'evt-01747',
      timestamp: '2026-09-11T13:30:00Z',
      source: 'windows',
      user: 'marcus',
      source_ip: '10.0.0.5',
      destination_ip: null,
      device: 'WS-03',
      action: 'process_execution',
      process: 'cmd.exe',
      destination_port: null,
      byte_count: null,
    },
    {
      event_id: 'evt-01748',
      timestamp: '2026-09-11T13:34:07Z',
      source: 'windows',
      user: 'marcus',
      source_ip: '10.0.0.5',
      destination_ip: null,
      device: 'WS-03',
      action: 'privilege_change',
      process: 'cmd.exe',
      destination_port: null,
      byte_count: null,
    },
  ],
};

export const MOCK_TRAJECTORIES: Record<string, AttackTrajectory> = {
  'INC-03265': {
    incident_id: 'INC-03265',
    techniques: [
      { id: 'T1078', timestamp: '2026-09-17T03:41:31Z' },
      { id: 'T1059.001', timestamp: '2026-09-17T03:49:25Z' },
      { id: 'T1068', timestamp: '2026-09-17T03:53:31Z' },
      { id: 'T1021.001', timestamp: '2026-09-17T04:03:10Z' },
      { id: 'T1041', timestamp: '2026-09-17T04:11:55Z' },
    ],
  },
  'INC-01743': {
    incident_id: 'INC-01743',
    techniques: [
      { id: 'T1078', timestamp: '2026-09-11T12:59:37Z' },
      { id: 'T1059.001', timestamp: '2026-09-11T13:08:14Z' },
      { id: 'T1068', timestamp: '2026-09-11T13:11:10Z' },
      { id: 'T1021.001', timestamp: '2026-09-11T13:18:55Z' },
      { id: 'T1068', timestamp: '2026-09-11T13:34:07Z' },
    ],
  },
};

export const MOCK_MATCHES: Record<string, HistoricalMatch> = {
  'INC-03265': {
    incident_id: 'INC-03265',
    matches: [
      {
        attack_id: 'HIST-C03',
        similarity: 1.0,
        common_techniques: ['T1078', 'T1059.001', 'T1068', 'T1021.001', 'T1041'],
      },
      {
        attack_id: 'HIST-C01',
        similarity: 0.8,
        common_techniques: ['T1078', 'T1059.001', 'T1068', 'T1021.001'],
      },
      {
        attack_id: 'HIST-G0028',
        similarity: 0.55,
        common_techniques: ['T1078', 'T1059.001', 'T1021.001'],
      },
      {
        attack_id: 'HIST-C08',
        similarity: 0.325,
        common_techniques: ['T1059.001', 'T1041'],
      },
      {
        attack_id: 'HIST-C09',
        similarity: 0.325,
        common_techniques: ['T1078', 'T1021.001'],
      },
    ],
  },
  'INC-01743': {
    incident_id: 'INC-01743',
    matches: [
      {
        attack_id: 'HIST-C01',
        similarity: 0.9,
        common_techniques: ['T1078', 'T1059.001', 'T1068', 'T1021.001'],
      },
      {
        attack_id: 'HIST-C03',
        similarity: 0.8,
        common_techniques: ['T1078', 'T1059.001', 'T1068', 'T1021.001'],
      },
      {
        attack_id: 'HIST-G0028',
        similarity: 0.6,
        common_techniques: ['T1078', 'T1059.001', 'T1021.001'],
      },
    ],
  },
};

export const MOCK_PREDICTIONS: Record<string, Prediction> = {
  'INC-03265': {
    incident_id: 'INC-03265',
    predictions: [],
    evidence: [
      'the last 1 step(s) T1041 occur 3 time(s) in 3 of 11 hand-specified historical trajectories',
      '3 of those 3 were the last step of their trajectory',
      'no continuation has been observed after this point, so no next step is predicted',
      'the longer context T1021 > T1041 was seen 1 time(s), fewer than the 2 required, so it was not used',
      'closest historical attack overall is HIST-C03 (similarity 1.0); not used for the probabilities',
    ],
  },
  'INC-01743': {
    incident_id: 'INC-01743',
    predictions: [
      { technique_id: 'T1021', probability: 1.0 },
    ],
    evidence: [
      'the last 1 step(s) T1068 occur 2 time(s) in 2 of 11 hand-specified historical trajectories',
      '2 of those 2 were followed by T1021',
      'the longer context T1021 > T1068 was seen 0 time(s), fewer than the 2 required, so it was not used',
      'the prediction uses the order of the observed steps',
      'closest historical attack overall is HIST-C01 (similarity 0.9); not used for the probabilities',
    ],
  },
};

export const MOCK_GRAPHS: Record<string, IncidentGraph> = {
  'INC-03265': {
    incident_id: 'INC-03265',
    nodes: [
      { id: 'event:evt-03265', type: 'event', label: 'evt-03265', timestamp: '2026-09-17T03:41:31Z', action: 'logon_success', source: 'windows' },
      { id: 'event:evt-03266', type: 'event', label: 'evt-03266', timestamp: '2026-09-17T03:49:25Z', action: 'process_execution', source: 'windows' },
      { id: 'event:evt-03267', type: 'event', label: 'evt-03267', timestamp: '2026-09-17T03:53:31Z', action: 'privilege_change', source: 'windows' },
      { id: 'event:evt-03268', type: 'event', label: 'evt-03268', timestamp: '2026-09-17T04:03:10Z', action: 'network_connection', source: 'windows' },
      { id: 'event:evt-03269', type: 'event', label: 'evt-03269', timestamp: '2026-09-17T04:05:00Z', action: 'rdp_session', source: 'windows' },
      { id: 'event:evt-03270', type: 'event', label: 'evt-03270', timestamp: '2026-09-17T04:11:55Z', action: 'network_connection', source: 'windows' },
      { id: 'event:evt-03271', type: 'event', label: 'evt-03271', timestamp: '2026-09-17T04:14:51Z', action: 'network_connection', source: 'windows' },
      { id: 'user:elena', type: 'user', label: 'elena' },
      { id: 'device:WS-04', type: 'device', label: 'WS-04' },
      { id: 'device:SRV-DB01', type: 'device', label: 'SRV-DB01' },
      { id: 'ip:10.0.0.14', type: 'ip', label: '10.0.0.14', internal: true },
      { id: 'ip:10.0.0.2', type: 'ip', label: '10.0.0.2', internal: true },
      { id: 'ip:203.0.113.120', type: 'ip', label: '203.0.113.120', internal: false },
      { id: 'ip:198.51.100.77', type: 'ip', label: '198.51.100.77', internal: false },
      { id: 'process:powershell.exe', type: 'process', label: 'powershell.exe' },
      { id: 'process:curl.exe', type: 'process', label: 'curl.exe' },
      { id: 'technique:T1078', type: 'technique', label: 'T1078', name: 'Valid Accounts' },
      { id: 'technique:T1059.001', type: 'technique', label: 'T1059.001', name: 'PowerShell' },
      { id: 'technique:T1068', type: 'technique', label: 'T1068', name: 'Exploitation for Privilege Escalation' },
      { id: 'technique:T1021.001', type: 'technique', label: 'T1021.001', name: 'Remote Desktop Protocol' },
      { id: 'technique:T1041', type: 'technique', label: 'T1041', name: 'Exfiltration Over C2 Channel' },
      { id: 'tactic:Initial Access', type: 'tactic', label: 'Initial Access' },
      { id: 'tactic:Execution', type: 'tactic', label: 'Execution' },
      { id: 'tactic:Privilege Escalation', type: 'tactic', label: 'Privilege Escalation' },
      { id: 'tactic:Lateral Movement', type: 'tactic', label: 'Lateral Movement' },
      { id: 'tactic:Exfiltration', type: 'tactic', label: 'Exfiltration' },
    ],
    edges: [
      { source: 'event:evt-03265', target: 'event:evt-03266', type: 'NEXT', delta_seconds: 474 },
      { source: 'event:evt-03266', target: 'event:evt-03267', type: 'NEXT', delta_seconds: 246 },
      { source: 'event:evt-03267', target: 'event:evt-03268', type: 'NEXT', delta_seconds: 579 },
      { source: 'event:evt-03268', target: 'event:evt-03269', type: 'NEXT', delta_seconds: 110 },
      { source: 'event:evt-03269', target: 'event:evt-03270', type: 'NEXT', delta_seconds: 415 },
      { source: 'event:evt-03270', target: 'event:evt-03271', type: 'NEXT', delta_seconds: 176 },
      
      { source: 'event:evt-03265', target: 'user:elena', type: 'PERFORMED' },
      { source: 'event:evt-03265', target: 'device:WS-04', type: 'OCCURRED_ON' },
      { source: 'event:evt-03265', target: 'ip:10.0.0.14', type: 'INVOLVES', role: 'destination' },
      { source: 'event:evt-03265', target: 'ip:203.0.113.120', type: 'INVOLVES', role: 'source' },
      { source: 'event:evt-03265', target: 'technique:T1078', type: 'MAPS_TO', confidence: 0.9 },
      
      { source: 'event:evt-03266', target: 'process:powershell.exe', type: 'EXECUTED' },
      { source: 'event:evt-03266', target: 'technique:T1059.001', type: 'MAPS_TO', confidence: 0.95 },
      
      { source: 'event:evt-03267', target: 'technique:T1068', type: 'MAPS_TO', confidence: 0.85 },
      
      { source: 'event:evt-03268', target: 'device:SRV-DB01', type: 'OCCURRED_ON' },
      { source: 'event:evt-03268', target: 'ip:10.0.0.2', type: 'INVOLVES', role: 'destination' },
      { source: 'event:evt-03268', target: 'technique:T1021.001', type: 'MAPS_TO', confidence: 0.92 },
      
      { source: 'event:evt-03270', target: 'process:curl.exe', type: 'EXECUTED' },
      { source: 'event:evt-03270', target: 'ip:198.51.100.77', type: 'INVOLVES', role: 'destination' },
      { source: 'event:evt-03271', target: 'technique:T1041', type: 'MAPS_TO', confidence: 0.98 },

      { source: 'technique:T1078', target: 'tactic:Initial Access', type: 'BELONGS_TO' },
      { source: 'technique:T1059.001', target: 'tactic:Execution', type: 'BELONGS_TO' },
      { source: 'technique:T1068', target: 'tactic:Privilege Escalation', type: 'BELONGS_TO' },
      { source: 'technique:T1021.001', target: 'tactic:Lateral Movement', type: 'BELONGS_TO' },
      { source: 'technique:T1041', target: 'tactic:Exfiltration', type: 'BELONGS_TO' },
    ],
  },
  'INC-01743': {
    incident_id: 'INC-01743',
    nodes: [
      { id: 'event:evt-01743', type: 'event', label: 'evt-01743', timestamp: '2026-09-11T12:59:37Z', action: 'logon_success', source: 'windows' },
      { id: 'event:evt-01744', type: 'event', label: 'evt-01744', timestamp: '2026-09-11T13:08:14Z', action: 'process_execution', source: 'windows' },
      { id: 'event:evt-01745', type: 'event', label: 'evt-01745', timestamp: '2026-09-11T13:11:10Z', action: 'privilege_change', source: 'windows' },
      { id: 'event:evt-01746', type: 'event', label: 'evt-01746', timestamp: '2026-09-11T13:18:55Z', action: 'rdp_session', source: 'windows' },
      { id: 'event:evt-01747', type: 'event', label: 'evt-01747', timestamp: '2026-09-11T13:30:00Z', action: 'process_execution', source: 'windows' },
      { id: 'event:evt-01748', type: 'event', label: 'evt-01748', timestamp: '2026-09-11T13:34:07Z', action: 'privilege_change', source: 'windows' },
      { id: 'user:marcus', type: 'user', label: 'marcus' },
      { id: 'device:WS-03', type: 'device', label: 'WS-03' },
      { id: 'device:SRV-DC01', type: 'device', label: 'SRV-DC01' },
      { id: 'ip:192.168.1.105', type: 'ip', label: '192.168.1.105', internal: true },
      { id: 'ip:10.0.0.5', type: 'ip', label: '10.0.0.5', internal: true },
      { id: 'ip:10.0.0.1', type: 'ip', label: '10.0.0.1', internal: true },
      { id: 'process:powershell.exe', type: 'process', label: 'powershell.exe' },
      { id: 'process:cmd.exe', type: 'process', label: 'cmd.exe' },
      { id: 'technique:T1078', type: 'technique', label: 'T1078', name: 'Valid Accounts' },
      { id: 'technique:T1059.001', type: 'technique', label: 'T1059.001', name: 'PowerShell' },
      { id: 'technique:T1068', type: 'technique', label: 'T1068', name: 'Exploitation for Privilege Escalation' },
      { id: 'technique:T1021.001', type: 'technique', label: 'T1021.001', name: 'Remote Desktop Protocol' },
      { id: 'tactic:Initial Access', type: 'tactic', label: 'Initial Access' },
      { id: 'tactic:Execution', type: 'tactic', label: 'Execution' },
      { id: 'tactic:Privilege Escalation', type: 'tactic', label: 'Privilege Escalation' },
      { id: 'tactic:Lateral Movement', type: 'tactic', label: 'Lateral Movement' },
    ],
    edges: [
      { source: 'event:evt-01743', target: 'event:evt-01744', type: 'NEXT', delta_seconds: 517 },
      { source: 'event:evt-01744', target: 'event:evt-01745', type: 'NEXT', delta_seconds: 176 },
      { source: 'event:evt-01745', target: 'event:evt-01746', type: 'NEXT', delta_seconds: 465 },
      { source: 'event:evt-01746', target: 'event:evt-01747', type: 'NEXT', delta_seconds: 665 },
      { source: 'event:evt-01747', target: 'event:evt-01748', type: 'NEXT', delta_seconds: 247 },
      { source: 'event:evt-01743', target: 'user:marcus', type: 'PERFORMED' },
      { source: 'event:evt-01743', target: 'device:WS-03', type: 'OCCURRED_ON' },
      { source: 'event:evt-01743', target: 'technique:T1078', type: 'MAPS_TO', confidence: 0.9 },
      { source: 'event:evt-01744', target: 'process:powershell.exe', type: 'EXECUTED' },
      { source: 'event:evt-01744', target: 'technique:T1059.001', type: 'MAPS_TO', confidence: 0.94 },
      { source: 'event:evt-01745', target: 'technique:T1068', type: 'MAPS_TO', confidence: 0.88 },
      { source: 'event:evt-01746', target: 'device:SRV-DC01', type: 'OCCURRED_ON' },
      { source: 'event:evt-01746', target: 'technique:T1021.001', type: 'MAPS_TO', confidence: 0.91 },
      { source: 'event:evt-01747', target: 'process:cmd.exe', type: 'EXECUTED' },
      { source: 'event:evt-01748', target: 'technique:T1068', type: 'MAPS_TO', confidence: 0.82 },
      { source: 'technique:T1078', target: 'tactic:Initial Access', type: 'BELONGS_TO' },
      { source: 'technique:T1059.001', target: 'tactic:Execution', type: 'BELONGS_TO' },
      { source: 'technique:T1068', target: 'tactic:Privilege Escalation', type: 'BELONGS_TO' },
      { source: 'technique:T1021.001', target: 'tactic:Lateral Movement', type: 'BELONGS_TO' },
    ],
  },
};

export const MOCK_INVESTIGATIONS: Record<string, EvidenceBundle> = {
  'INC-03265': {
    incident_id: 'INC-03265',
    trajectory: MOCK_TRAJECTORIES['INC-03265'],
    event_summary: {
      count: 7,
      first: '2026-09-17T03:41:31Z',
      last: '2026-09-17T04:14:51Z',
      users: { elena: 7 },
      devices: { 'SRV-DB01': 4, 'WS-04': 3 },
      actions: { logon_success: 1, network_connection: 3, privilege_change: 1, process_execution: 1, rdp_session: 1 },
    },
    historical_matches: MOCK_MATCHES['INC-03265'],
    prediction: MOCK_PREDICTIONS['INC-03265'],
    techniques: [
      {
        id: 'T1041',
        name: 'Exfiltration Over C2 Channel',
        tactic: 'Exfiltration',
        description: 'Adversaries may steal data by exfiltrating it over an existing command and control channel.',
        relation: 'in_trajectory',
      },
    ],
    steps: [
      { tool: 'query_graph', input: { incident_id: 'INC-03265' }, ok: true, summary: '5 technique step(s): T1078 > T1059.001 > T1068 > T1021.001 > T1041' },
      { tool: 'get_events', input: { incident_id: 'INC-03265' }, ok: true, summary: '7 event(s)' },
      { tool: 'match_historical', input: { incident_id: 'INC-03265' }, ok: true, summary: 'top match HIST-C03 at 1.0' },
      { tool: 'predict_next', input: { incident_id: 'INC-03265' }, ok: true, summary: 'no prediction' },
      { tool: 'lookup_technique', input: { technique_id: 'T1041' }, ok: true, summary: 'T1041 Exfiltration Over C2 Channel' },
    ],
    agent: {
      llm: 'scripted-policy',
      complete: true,
      stop_reason: 'end_turn',
      tool_calls: 5,
      failed_tool_calls: 0,
    },
    agent_notes: 'Trajectory, events and historical matches were collected and a next-step prediction was requested.',
  },
  'INC-01743': {
    incident_id: 'INC-01743',
    trajectory: MOCK_TRAJECTORIES['INC-01743'],
    event_summary: {
      count: 6,
      first: '2026-09-11T12:59:37Z',
      last: '2026-09-11T13:34:07Z',
      users: { marcus: 6 },
      devices: { 'SRV-DC01': 1, 'WS-03': 5 },
      actions: { logon_success: 1, privilege_change: 2, process_execution: 2, rdp_session: 1 },
    },
    historical_matches: MOCK_MATCHES['INC-01743'],
    prediction: MOCK_PREDICTIONS['INC-01743'],
    techniques: [
      {
        id: 'T1021',
        name: 'Remote Services',
        tactic: 'Lateral Movement',
        description: 'Adversaries may use valid accounts to log into remote services.',
        relation: 'predicted',
      },
    ],
    steps: [
      { tool: 'query_graph', input: { incident_id: 'INC-01743' }, ok: true, summary: '5 technique step(s): T1078 > T1059.001 > T1068 > T1021.001 > T1068' },
      { tool: 'get_events', input: { incident_id: 'INC-01743' }, ok: true, summary: '6 event(s)' },
      { tool: 'match_historical', input: { incident_id: 'INC-01743' }, ok: true, summary: 'top match HIST-C01 at 0.9' },
      { tool: 'predict_next', input: { incident_id: 'INC-01743' }, ok: true, summary: 'top prediction T1021 at 1.0' },
      { tool: 'lookup_technique', input: { technique_id: 'T1021' }, ok: true, summary: 'T1021 Remote Services' },
    ],
    agent: {
      llm: 'scripted-policy',
      complete: true,
      stop_reason: 'end_turn',
      tool_calls: 5,
      failed_tool_calls: 0,
    },
    agent_notes: 'Trajectory, events and historical matches were collected and a next-step prediction was requested.',
  },
};

export const MOCK_REPORTS: Record<string, Report> = {
  'INC-03265': {
    incident_id: 'INC-03265',
    format: 'markdown',
    generated_by: 'template',
    report: `# Incident INC-03265 — Analyst Report

## Executive Summary
Incident **INC-03265** represents an active exfiltration campaign across host \`WS-04\` and database server \`SRV-DB01\`. The adversary began with valid credential misuse, leveraged PowerShell privilege escalation, jumped via Remote Desktop Protocol, and culminated in **52.4 MB exfiltrated over C2 channel** to destination IP \`198.51.100.77\`.

## What was observed
**5 ATT&CK technique step(s)**, in chronological order:
1. \`T1078\` **Valid Accounts** — 2026-09-17T03:41:31Z
2. \`T1059.001\` **PowerShell** — 2026-09-17T03:49:25Z
3. \`T1068\` **Exploitation for Privilege Escalation** — 2026-09-17T03:53:31Z
4. \`T1021.001\` **Remote Desktop Protocol** — 2026-09-17T04:03:10Z
5. \`T1041\` **Exfiltration Over C2 Channel** — 2026-09-17T04:11:55Z

### Correlated Entity Breakdown
- **User Accounts**: \`elena\` (7 events)
- **Hosts Affected**: \`SRV-DB01\` (4), \`WS-04\` (3)
- **External IPs**: \`203.0.113.120\` (initial ingress), \`198.51.100.77\` (exfiltration target)
- **Total Network Transfer**: 53.47 MB

## Similar Past Attacks
| Historical Attack | Similarity | Techniques in Common |
|---|---|---|
| \`HIST-C03\` Stolen-credential intrusion ending in exfiltration over C2 | **100%** | T1078, T1059.001, T1068, T1021.001, T1041 |
| \`HIST-C01\` Stolen-credential intrusion with privilege escalation & RDP | **80%** | T1078, T1059.001, T1068, T1021.001 |
| \`HIST-G0028\` Threat Group-1314 (MITRE ATT&CK Group) | **55%** | T1078, T1059.001, T1021.001 |

## Predictive Threat Trajectory
- **Predicted Next Step**: **None** (Exfiltration was the terminal step in all historical reference trajectories).
- **Basis**:
  - The final observed technique \`T1041\` appeared 3 times in historical reference sets.
  - In 100% of cases, \`T1041\` concluded the attack cycle.
  - Immediate containment and credential revocation on \`SRV-DB01\` is advised.

## Investigation Audit Trail
- 5 tool calls executed by \`scripted-policy\` agent.
- 0 failed tool calls.
`,
  },
  'INC-01743': {
    incident_id: 'INC-01743',
    format: 'markdown',
    generated_by: 'template',
    report: `# Incident INC-01743

## What was observed

5 ATT&CK technique step(s), in time order:

1. \`T1078\` Valid Accounts - from 2026-09-11T12:59:37Z
2. \`T1059.001\` PowerShell - from 2026-09-11T13:08:14Z
3. \`T1068\` Exploitation for Privilege Escalation - from 2026-09-11T13:11:10Z
4. \`T1021.001\` Remote Desktop Protocol - from 2026-09-11T13:18:55Z
5. \`T1068\` Exploitation for Privilege Escalation - from 2026-09-11T13:34:07Z

Each step is a run of consecutive events with the same technique; the time is when that run began. A technique can appear in more than one step.

The incident groups 6 event(s) between 2026-09-11T12:59:37Z and 2026-09-11T13:34:07Z.

- **Accounts**: marcus (6)
- **Hosts**: SRV-DC01 (1), WS-03 (5)
- **Event types**: logon_success (1), privilege_change (2), process_execution (2), rdp_session (1)

## Similar past attacks

| Historical attack | Similarity | Techniques in common |
|---|---|---|
| \`HIST-C01\` Stolen-credential intrusion with privilege escalation and RDP lateral movement | **0.9 (90%)** | T1078, T1059.001, T1068, T1021.001 |
| \`HIST-C03\` Stolen-credential intrusion ending in exfiltration over the C2 channel | **0.8 (80%)** | T1078, T1059.001, T1068, T1021.001 |
| \`HIST-G0028\` Threat Group-1314 (MITRE ATT&CK group, order inferred) | **0.6 (60%)** | T1078, T1059.001, T1021.001 |

## Likely next step

| Technique | Probability |
|---|---|
| \`T1021\` Remote Services | **1.0 (100%)** |

Basis:
- the last 1 step(s) T1068 occur 2 time(s) in 2 of 11 hand-specified historical trajectories
- 2 of those 2 were followed by T1021
- the longer context T1021 > T1068 was seen 0 time(s), fewer than the 2 required, so it was not used
- the prediction uses the order of the observed steps
- closest historical attack overall is HIST-C01 (similarity 0.9); not used for the probabilities

## How this was produced

1. \`query_graph\` - 5 technique step(s): T1078 > T1059.001 > T1068 > T1021.001 > T1068
2. \`get_events\` - 6 event(s)
3. \`match_historical\` - top match HIST-C01 at 0.9
4. \`predict_next\` - top prediction T1021 at 1.0
5. \`lookup_technique\` - T1021 Remote Services

Investigation complete; 5 tool call(s), 0 failed; tool selection by \`scripted-policy\`.

Agent's note (commentary, not a finding):
> Trajectory, events and historical matches were collected and a next-step prediction was requested.

## Limits of this report
- Techniques are assigned by a rule-based mapper, which produces false positives and misses.
- Similarity compares complete technique sequences; an attack still in progress scores low against its own reference.
- Probabilities are ratios of counts over a small set of hand-written historical sequences. They are not calibrated likelihoods.
`,
  },
};

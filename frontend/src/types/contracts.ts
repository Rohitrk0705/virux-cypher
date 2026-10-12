/**
 * Virux Cypher Data Contracts & API Response Types
 * 
 * Strictly mirrors docs/data-contracts.md and backend/api/schemas.py.
 */

// ==========================================
// 1. Five Core Data Contracts
// ==========================================

/** Contract 1: Normalized Event */
export interface NormalizedEvent {
  event_id: string;
  timestamp: string;
  source: string;
  user: string;
  source_ip: string;
  destination_ip: string | null;
  device: string;
  action: string;
  process: string | null;
  destination_port?: number | null;
  byte_count?: number | null;
}

/** Contract 2: Attack Technique (mapping of an event to ATT&CK) */
export interface AttackTechnique {
  event_id: string;
  technique_id: string;
  technique_name: string;
  tactic: string;
  confidence: number;
}

/** Contract 3: Attack Trajectory (ordered techniques for one incident) */
export interface TrajectoryStep {
  id: string;
  timestamp: string;
}

export interface AttackTrajectory {
  incident_id: string;
  techniques: TrajectoryStep[];
}

/** Contract 4: Historical Match */
export interface Match {
  attack_id: string;
  similarity: number;
  common_techniques: string[];
}

export interface HistoricalMatch {
  incident_id: string;
  matches: Match[];
}

/** Contract 5: Prediction */
export interface PredictedTechnique {
  technique_id: string;
  probability: number;
}

export interface Prediction {
  incident_id: string;
  predictions: PredictedTechnique[];
  evidence: string[];
}

// ==========================================
// 2. API-Specific Models (schemas.py)
// ==========================================

export interface Health {
  status: 'ok' | 'degraded';
  service: string;
  neo4j: boolean;
  events: number | null;
  incidents: number | null;
}

export interface IncidentSummary {
  incident_id: string;
  start: string;
  end: string;
  event_count: number;
}

export type GraphNodeType = 'event' | 'user' | 'device' | 'ip' | 'process' | 'technique' | 'tactic';

export interface GraphNode {
  id: string;
  type: GraphNodeType;
  label: string;
  // Extra fields based on node type
  timestamp?: string;
  action?: string;
  source?: string;
  internal?: boolean;
  name?: string;
  description?: string;
  tactic?: string;
  [key: string]: any;
}

export type GraphEdgeType = 'PERFORMED' | 'OCCURRED_ON' | 'INVOLVES' | 'EXECUTED' | 'MAPS_TO' | 'BELONGS_TO' | 'NEXT';

export interface GraphEdge {
  source: string;
  target: string;
  type: GraphEdgeType;
  // Extra fields based on edge type
  role?: string;
  confidence?: number;
  delta_seconds?: number;
  [key: string]: any;
}

export interface IncidentGraph {
  incident_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface TechniqueInfo {
  id: string;
  name: string;
  tactic: string;
  description: string;
}

export interface LookedUpTechnique extends TechniqueInfo {
  relation: 'in_trajectory' | 'predicted' | 'not_in_evidence';
}

export interface EventSummary {
  count: number;
  first: string | null;
  last: string | null;
  users: Record<string, number>;
  devices: Record<string, number>;
  actions: Record<string, number>;
}

export interface AgentStep {
  tool: string;
  input: Record<string, any>;
  ok: boolean;
  summary: string;
}

export interface AgentStatus {
  llm: string;
  complete: boolean;
  stop_reason: string;
  tool_calls: number;
  failed_tool_calls: number;
}

export interface EvidenceBundle {
  incident_id: string;
  trajectory: AttackTrajectory | null;
  event_summary: EventSummary | null;
  historical_matches: HistoricalMatch | null;
  prediction: Prediction | null;
  techniques: LookedUpTechnique[];
  steps: AgentStep[];
  agent: AgentStatus;
  agent_notes: string;
}

export interface Report {
  incident_id: string;
  format: 'markdown';
  generated_by: string;
  report: string;
}

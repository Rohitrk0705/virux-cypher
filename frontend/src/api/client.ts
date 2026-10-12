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
import { getApiBaseUrl, isMockEnabled } from '../config/api';
import {
  MOCK_HEALTH,
  MOCK_INCIDENTS,
  MOCK_EVENTS,
  MOCK_TRAJECTORIES,
  MOCK_MATCHES,
  MOCK_PREDICTIONS,
  MOCK_GRAPHS,
  MOCK_TECHNIQUES,
  MOCK_INVESTIGATIONS,
  MOCK_REPORTS,
} from './mockData';

// Simulated delay for realistic mock experience
const mockDelay = (ms = 120) => new Promise((resolve) => setTimeout(resolve, ms));

async function request<T>(path: string, mockFallback: () => T): Promise<T> {
  if (isMockEnabled()) {
    await mockDelay();
    return mockFallback();
  }

  const baseUrl = getApiBaseUrl().replace(/\/+$/, '');
  try {
    const res = await fetch(`${baseUrl}${path}`);
    if (!res.ok) {
      const errBody = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(errBody.detail || `Request failed with status ${res.status}`);
    }
    return (await res.json()) as T;
  } catch (err: any) {
    console.warn(`[Virux API] Live request to ${path} failed:`, err);
    throw err;
  }
}

export const api = {
  async getHealth(): Promise<Health> {
    return request('/health', () => MOCK_HEALTH);
  },

  async getIncidents(): Promise<IncidentSummary[]> {
    return request('/incidents', () => MOCK_INCIDENTS);
  },

  async getEvents(incidentId: string): Promise<NormalizedEvent[]> {
    return request(`/events/${incidentId}`, () => {
      return MOCK_EVENTS[incidentId] || MOCK_EVENTS['INC-03265'] || [];
    });
  },

  async getGraph(incidentId: string): Promise<IncidentGraph> {
    return request(`/graph/${incidentId}`, () => {
      return (
        MOCK_GRAPHS[incidentId] ||
        MOCK_GRAPHS['INC-03265'] || {
          incident_id: incidentId,
          nodes: [],
          edges: [],
        }
      );
    });
  },

  async getTrajectory(incidentId: string): Promise<AttackTrajectory> {
    return request(`/trajectory/${incidentId}`, () => {
      return (
        MOCK_TRAJECTORIES[incidentId] ||
        MOCK_TRAJECTORIES['INC-03265'] || {
          incident_id: incidentId,
          techniques: [],
        }
      );
    });
  },

  async getMatch(incidentId: string): Promise<HistoricalMatch> {
    return request(`/match/${incidentId}`, () => {
      return (
        MOCK_MATCHES[incidentId] ||
        MOCK_MATCHES['INC-03265'] || {
          incident_id: incidentId,
          matches: [],
        }
      );
    });
  },

  async getPredict(incidentId: string): Promise<Prediction> {
    return request(`/predict/${incidentId}`, () => {
      return (
        MOCK_PREDICTIONS[incidentId] ||
        MOCK_PREDICTIONS['INC-03265'] || {
          incident_id: incidentId,
          predictions: [],
          evidence: [],
        }
      );
    });
  },

  async getInvestigate(incidentId: string): Promise<EvidenceBundle> {
    return request(`/investigate/${incidentId}`, () => {
      return MOCK_INVESTIGATIONS[incidentId] || MOCK_INVESTIGATIONS['INC-03265'];
    });
  },

  async getExplain(incidentId: string): Promise<Report> {
    return request(`/explain/${incidentId}`, () => {
      return (
        MOCK_REPORTS[incidentId] ||
        MOCK_REPORTS['INC-03265'] || {
          incident_id: incidentId,
          format: 'markdown',
          generated_by: 'mock',
          report: `# Incident ${incidentId}\nNo report generated yet.`,
        }
      );
    });
  },

  async getTechnique(techniqueId: string): Promise<TechniqueInfo> {
    return request(`/technique/${techniqueId}`, () => {
      return (
        MOCK_TECHNIQUES[techniqueId] || {
          id: techniqueId,
          name: techniqueId,
          tactic: 'Unknown',
          description: 'No detailed description available in local database.',
        }
      );
    });
  },
};

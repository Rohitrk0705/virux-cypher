import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { IncidentSummary, Health } from '../types/contracts';
import { api } from '../api/client';
import { getApiBaseUrl, setApiBaseUrl, isMockEnabled, setMockEnabled } from '../config/api';

interface IncidentContextType {
  incidents: IncidentSummary[];
  activeIncidentId: string;
  setActiveIncidentId: (id: string) => void;
  health: Health | null;
  loading: boolean;
  error: string | null;
  useMock: boolean;
  toggleMock: () => void;
  baseUrl: string;
  updateBaseUrl: (url: string) => void;
  refreshIncidents: () => Promise<void>;
  refreshHealth: () => Promise<void>;
}

const IncidentContext = createContext<IncidentContextType | undefined>(undefined);

export const IncidentProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [activeIncidentId, setActiveIncidentId] = useState<string>('INC-03265');
  const [health, setHealth] = useState<Health | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [useMock, setUseMockState] = useState<boolean>(isMockEnabled());
  const [baseUrl, setBaseUrlState] = useState<string>(getApiBaseUrl());

  const refreshHealth = useCallback(async () => {
    try {
      const h = await api.getHealth();
      setHealth(h);
    } catch (err: any) {
      console.warn('Failed to fetch health:', err);
      setHealth({
        status: 'degraded',
        service: 'virux-cypher',
        neo4j: false,
        events: null,
        incidents: null,
      });
    }
  }, []);

  const refreshIncidents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const list = await api.getIncidents();
      setIncidents(list);
      if (list.length > 0 && !list.find((i) => i.incident_id === activeIncidentId)) {
        setActiveIncidentId(list[0].incident_id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load incidents');
    } finally {
      setLoading(false);
    }
  }, [activeIncidentId]);

  useEffect(() => {
    refreshHealth();
    refreshIncidents();
  }, [refreshHealth, refreshIncidents, useMock]);

  const toggleMock = () => {
    const next = !useMock;
    setMockEnabled(next);
    setUseMockState(next);
  };

  const updateBaseUrl = (url: string) => {
    setApiBaseUrl(url);
    setBaseUrlState(url);
  };

  return (
    <IncidentContext.Provider
      value={{
        incidents,
        activeIncidentId,
        setActiveIncidentId,
        health,
        loading,
        error,
        useMock,
        toggleMock,
        baseUrl,
        updateBaseUrl,
        refreshIncidents,
        refreshHealth,
      }}
    >
      {children}
    </IncidentContext.Provider>
  );
};

export const useIncident = () => {
  const context = useContext(IncidentContext);
  if (!context) {
    throw new Error('useIncident must be used within an IncidentProvider');
  }
  return context;
};

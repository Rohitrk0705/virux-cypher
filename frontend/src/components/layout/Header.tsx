import React, { useState } from 'react';
import { useIncident } from '../../context/IncidentContext';
import { Shield, Database, Server, Settings, RefreshCw, Radio } from 'lucide-react';

export const Header: React.FC = () => {
  const {
    incidents,
    activeIncidentId,
    setActiveIncidentId,
    health,
    useMock,
    toggleMock,
    baseUrl,
    updateBaseUrl,
    refreshIncidents,
    refreshHealth,
  } = useIncident();

  const [showConfig, setShowConfig] = useState(false);
  const [tempUrl, setTempUrl] = useState(baseUrl);
  const [isRefreshing, setIsRefreshing] = useState(false);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    await Promise.all([refreshIncidents(), refreshHealth()]);
    setIsRefreshing(false);
  };

  const handleSaveConfig = () => {
    updateBaseUrl(tempUrl);
    setShowConfig(false);
    handleRefresh();
  };

  return (
    <header
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '12px 24px',
        backgroundColor: 'rgba(10, 14, 23, 0.92)',
        backdropFilter: 'blur(16px)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
        position: 'sticky',
        top: 0,
        zIndex: 50,
      }}
    >
      {/* Brand & Subtitle */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '40px',
            height: '40px',
            borderRadius: '10px',
            background: 'linear-gradient(135deg, rgba(56, 189, 248, 0.2) 0%, rgba(99, 102, 241, 0.2) 100%)',
            border: '1px solid rgba(56, 189, 248, 0.4)',
            boxShadow: '0 0 15px rgba(56, 189, 248, 0.25)',
          }}
        >
          <Shield size={22} color="#38bdf8" />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span style={{ fontSize: '1.15rem', fontWeight: 800, letterSpacing: '0.05em', color: '#f8fafc' }}>
              VIRUX<span style={{ color: '#38bdf8' }}>CYPHER</span>
            </span>
            <span
              className="badge-mono"
              style={{
                background: 'rgba(56, 189, 248, 0.1)',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                color: '#38bdf8',
                fontSize: '0.65rem',
              }}
            >
              SOC v0.1.0
            </span>
          </div>
          <div style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: 500, letterSpacing: '0.02em' }}>
            TEMPORAL CYBER-THREAT KNOWLEDGE GRAPH & TRAJECTORY ENGINE
          </div>
        </div>
      </div>

      {/* Middle: Active Incident Selector */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <span style={{ fontSize: '0.8rem', color: '#94a3b8', fontWeight: 500 }}>Active Incident:</span>
        <select
          value={activeIncidentId}
          onChange={(e) => setActiveIncidentId(e.target.value)}
          style={{
            background: 'var(--bg-secondary)',
            color: '#f8fafc',
            border: '1px solid rgba(56, 189, 248, 0.3)',
            borderRadius: '8px',
            padding: '6px 12px',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.875rem',
            fontWeight: 600,
            cursor: 'pointer',
            outline: 'none',
          }}
        >
          {incidents.map((inc) => (
            <option key={inc.incident_id} value={inc.incident_id}>
              {inc.incident_id} ({inc.event_count} events)
            </option>
          ))}
        </select>

        <button
          onClick={handleRefresh}
          className="btn-secondary"
          style={{ padding: '6px 10px', fontSize: '0.8rem' }}
          title="Refresh incidents and health status"
        >
          <RefreshCw size={13} className={isRefreshing ? 'pulse-dot' : ''} />
        </button>
      </div>

      {/* Right Controls: Health Pill, Mock Switch, Config */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        {/* Health status pill */}
        <div
          className="badge-mono"
          style={{
            background: health?.status === 'ok' ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
            border: `1px solid ${health?.status === 'ok' ? 'rgba(16, 185, 129, 0.4)' : 'rgba(239, 68, 68, 0.4)'}`,
            color: health?.status === 'ok' ? '#34d399' : '#f87171',
            padding: '4px 10px',
            fontSize: '0.75rem',
          }}
          title={
            health
              ? `Neo4j: ${health.neo4j ? 'Connected' : 'Unavailable'} | Events: ${health.events ?? 0} | Incidents: ${health.incidents ?? 0}`
              : 'Checking status...'
          }
        >
          <span
            className="pulse-dot"
            style={{
              backgroundColor: health?.status === 'ok' ? '#10b981' : '#ef4444',
            }}
          />
          <Database size={12} />
          <span>Neo4j: {health?.neo4j ? 'ONLINE' : 'OFFLINE'}</span>
          {health?.events !== null && (
            <span style={{ opacity: 0.75 }}>({health?.events} evts)</span>
          )}
        </div>

        {/* Mock Data / Live Backend Toggle */}
        <div
          onClick={toggleMock}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            background: useMock ? 'rgba(56, 189, 248, 0.12)' : 'rgba(99, 102, 241, 0.15)',
            border: `1px solid ${useMock ? 'rgba(56, 189, 248, 0.4)' : 'rgba(99, 102, 241, 0.5)'}`,
            padding: '5px 12px',
            borderRadius: '20px',
            cursor: 'pointer',
            transition: 'all 0.2s ease',
          }}
          title="Click to toggle between offline mock data and live FastAPI backend"
        >
          <Radio size={13} color={useMock ? '#38bdf8' : '#818cf8'} />
          <span style={{ fontSize: '0.75rem', fontWeight: 600, color: useMock ? '#38bdf8' : '#818cf8' }}>
            {useMock ? 'MOCK DATA (OFFLINE)' : 'LIVE BACKEND'}
          </span>
        </div>

        {/* Settings button */}
        <button
          onClick={() => setShowConfig(!showConfig)}
          className="btn-secondary"
          style={{ padding: '6px 10px' }}
          title="API Configuration"
        >
          <Settings size={14} />
        </button>
      </div>

      {/* Settings Modal */}
      {showConfig && (
        <div
          style={{
            position: 'absolute',
            top: '64px',
            right: '24px',
            width: '360px',
            backgroundColor: '#0f172a',
            border: '1px solid rgba(56, 189, 248, 0.3)',
            borderRadius: '12px',
            padding: '18px',
            boxShadow: '0 10px 30px rgba(0,0,0,0.7)',
            zIndex: 100,
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <h4 style={{ fontSize: '0.9rem', color: '#f8fafc', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Server size={14} color="#38bdf8" /> API Configuration
            </h4>
            <button
              onClick={() => setShowConfig(false)}
              style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer' }}
            >
              ✕
            </button>
          </div>
          <div style={{ marginBottom: '14px' }}>
            <label style={{ display: 'block', fontSize: '0.75rem', color: '#94a3b8', marginBottom: '6px' }}>
              Backend Base URL:
            </label>
            <input
              type="text"
              value={tempUrl}
              onChange={(e) => setTempUrl(e.target.value)}
              placeholder="http://127.0.0.1:8000"
              style={{
                width: '100%',
                background: '#090d16',
                border: '1px solid rgba(255,255,255,0.1)',
                color: '#f8fafc',
                padding: '8px 10px',
                borderRadius: '6px',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.8rem',
                outline: 'none',
              }}
            />
          </div>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '8px' }}>
            <button className="btn-secondary" onClick={() => setShowConfig(false)} style={{ fontSize: '0.75rem' }}>
              Cancel
            </button>
            <button className="btn-primary" onClick={handleSaveConfig} style={{ fontSize: '0.75rem' }}>
              Save & Test
            </button>
          </div>
        </div>
      )}
    </header>
  );
};

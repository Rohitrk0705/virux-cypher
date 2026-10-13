import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useIncident } from '../../context/IncidentContext';
import { Shield, Database, Server, Settings, RefreshCw, Radio, X } from 'lucide-react';

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
        backgroundColor: 'rgba(10, 13, 20, 0.94)',
        backdropFilter: 'blur(20px)',
        WebkitBackdropFilter: 'blur(20px)',
        borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
        position: 'sticky',
        top: 0,
        zIndex: 50,
      }}
    >
      {/* Brand & Subtitle */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            width: '38px',
            height: '38px',
            borderRadius: '10px',
            background: 'linear-gradient(135deg, rgba(255, 138, 61, 0.2) 0%, rgba(234, 88, 12, 0.1) 100%)',
            border: '1px solid rgba(255, 138, 61, 0.45)',
            boxShadow: '0 0 16px rgba(255, 138, 61, 0.2)',
          }}
        >
          <Shield size={20} color="#ff8a3d" />
        </div>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <span
              style={{
                fontSize: '1.15rem',
                fontWeight: 800,
                letterSpacing: '0.04em',
                color: '#f8fafc',
                fontFamily: 'var(--font-heading)',
              }}
            >
              VIRUX<span style={{ color: '#ff8a3d' }}>CYPHER</span>
            </span>
            <span
              className="badge-mono"
              style={{
                background: 'rgba(255, 138, 61, 0.1)',
                border: '1px solid rgba(255, 138, 61, 0.3)',
                color: '#ff8a3d',
                fontSize: '0.65rem',
                fontWeight: 700,
              }}
            >
              SOC v0.1.0
            </span>
          </div>
          <div
            style={{
              fontSize: '0.7rem',
              color: '#64748b',
              fontWeight: 600,
              letterSpacing: '0.04em',
              fontFamily: 'var(--font-mono)',
            }}
          >
            TEMPORAL THREAT KNOWLEDGE GRAPH & TRAJECTORY ENGINE
          </div>
        </div>
      </div>

      {/* Middle: Active Incident Selector */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        <span style={{ fontSize: '0.78rem', color: '#94a3b8', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em' }}>
          Active Threat:
        </span>
        <select
          value={activeIncidentId}
          onChange={(e) => setActiveIncidentId(e.target.value)}
          style={{
            background: 'rgba(15, 20, 32, 0.9)',
            color: '#f8fafc',
            border: '1px solid rgba(255, 138, 61, 0.35)',
            borderRadius: '8px',
            padding: '6px 12px',
            fontFamily: 'var(--font-mono)',
            fontSize: '0.825rem',
            fontWeight: 600,
            cursor: 'pointer',
            outline: 'none',
            boxShadow: '0 0 10px rgba(255, 138, 61, 0.1)',
          }}
        >
          {incidents.map((inc) => (
            <option key={inc.incident_id} value={inc.incident_id} style={{ background: '#0f1420', color: '#f8fafc' }}>
              {inc.incident_id} ({inc.event_count} events)
            </option>
          ))}
        </select>

        <button
          onClick={handleRefresh}
          className="btn-secondary"
          style={{ padding: '7px 10px', fontSize: '0.8rem' }}
          title="Refresh incidents and health status"
        >
          <RefreshCw
            size={13}
            style={{
              animation: isRefreshing ? 'spin 1s linear infinite' : 'none',
              color: isRefreshing ? '#ff8a3d' : '#94a3b8',
            }}
          />
        </button>
      </div>

      {/* Right Controls: Health Pill, Mock Switch, Config */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        {/* Health status pill */}
        <div
          className="badge-mono"
          style={{
            background: health?.status === 'ok' ? 'rgba(16, 185, 129, 0.12)' : 'rgba(255, 77, 77, 0.12)',
            border: `1px solid ${health?.status === 'ok' ? 'rgba(16, 185, 129, 0.4)' : 'rgba(255, 77, 77, 0.45)'}`,
            color: health?.status === 'ok' ? '#34d399' : '#ff6b6b',
            padding: '4px 10px',
            fontSize: '0.72rem',
            fontWeight: 600,
          }}
          title={
            health
              ? `Neo4j: ${health.neo4j ? 'Connected' : 'Unavailable'} | Events: ${health.events ?? 0} | Incidents: ${health.incidents ?? 0}`
              : 'Checking status...'
          }
        >
          <span className={health?.status === 'ok' ? 'pulse-dot-emerald' : 'pulse-dot-red'} style={{ width: '6px', height: '6px' }} />
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
            background: useMock ? 'rgba(255, 138, 61, 0.12)' : 'rgba(16, 185, 129, 0.12)',
            border: `1px solid ${useMock ? 'rgba(255, 138, 61, 0.45)' : 'rgba(16, 185, 129, 0.45)'}`,
            padding: '5px 12px',
            borderRadius: '20px',
            cursor: 'pointer',
            transition: 'all 0.2s cubic-bezier(0.16, 1, 0.3, 1)',
            boxShadow: useMock ? '0 0 12px rgba(255, 138, 61, 0.15)' : '0 0 12px rgba(16, 185, 129, 0.15)',
          }}
          title="Click to toggle between mock sandbox data and live FastAPI backend"
        >
          <Radio size={12} color={useMock ? '#ff8a3d' : '#34d399'} />
          <span
            style={{
              fontSize: '0.72rem',
              fontWeight: 700,
              fontFamily: 'var(--font-mono)',
              letterSpacing: '0.03em',
              color: useMock ? '#ff8a3d' : '#34d399',
            }}
          >
            {useMock ? 'MOCK TELEMETRY' : 'LIVE AGENT API'}
          </span>
        </div>

        {/* Settings button */}
        <button
          onClick={() => setShowConfig(!showConfig)}
          className="btn-secondary"
          style={{ padding: '6px 10px' }}
          title="API Configuration"
        >
          <Settings size={14} color="#94a3b8" />
        </button>
      </div>

      {/* Settings Modal */}
      <AnimatePresence>
        {showConfig && (
          <motion.div
            initial={{ opacity: 0, y: -8, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -8, scale: 0.98 }}
            transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
            className="glass-panel"
            style={{
              position: 'absolute',
              top: '64px',
              right: '24px',
              width: '360px',
              backgroundColor: 'rgba(15, 20, 32, 0.96)',
              border: '1px solid rgba(255, 138, 61, 0.35)',
              padding: '20px',
              boxShadow: '0 16px 45px rgba(0,0,0,0.8), 0 0 25px rgba(255, 138, 61, 0.12)',
              zIndex: 100,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
              <h4 style={{ fontSize: '0.9rem', color: '#f8fafc', fontWeight: 700, display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Server size={14} color="#ff8a3d" /> Endpoint Telemetry Config
              </h4>
              <button
                onClick={() => setShowConfig(false)}
                style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', display: 'flex' }}
              >
                <X size={15} />
              </button>
            </div>
            <div style={{ marginBottom: '16px' }}>
              <label style={{ display: 'block', fontSize: '0.72rem', color: '#94a3b8', fontWeight: 600, marginBottom: '6px' }}>
                BACKEND API URL:
              </label>
              <input
                type="text"
                value={tempUrl}
                onChange={(e) => setTempUrl(e.target.value)}
                placeholder="http://127.0.0.1:8000"
                style={{
                  width: '100%',
                  background: 'rgba(10, 13, 20, 0.85)',
                  border: '1px solid rgba(255,255,255,0.12)',
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
                Save & Connect
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </header>
  );
};

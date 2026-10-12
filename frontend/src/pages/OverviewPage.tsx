import React, { useState } from 'react';
import { useIncident } from '../context/IncidentContext';
import { RiskBadge, calculateIncidentRisk } from '../components/common/RiskBadge';
import { PageTab } from '../components/layout/Sidebar';
import { ShieldAlert, Search, Filter, ArrowRight, Clock, Hash, AlertTriangle, Layers } from 'lucide-react';

interface OverviewPageProps {
  onNavigate: (tab: PageTab, incidentId?: string) => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({ onNavigate }) => {
  const { incidents, activeIncidentId, setActiveIncidentId, health, loading, error } = useIncident();
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL');

  const filteredIncidents = incidents.filter((inc) => {
    const matchesSearch = inc.incident_id.toLowerCase().includes(search.toLowerCase());
    if (!matchesSearch) return false;
    if (riskFilter === 'ALL') return true;
    const { level } = calculateIncidentRisk(inc);
    return level === riskFilter;
  });

  const criticalCount = incidents.filter((i) => calculateIncidentRisk(i).level === 'CRITICAL').length;
  const highCount = incidents.filter((i) => calculateIncidentRisk(i).level === 'HIGH').length;
  const totalEvents = incidents.reduce((acc, curr) => acc + curr.event_count, 0);

  const formatDuration = (start: string, end: string) => {
    const ms = new Date(end).getTime() - new Date(start).getTime();
    const mins = Math.round(ms / 60000);
    if (mins < 60) return `${mins}m`;
    const hours = Math.floor(mins / 60);
    const remMins = mins % 60;
    return `${hours}h ${remMins}m`;
  };

  const handleSelectIncident = (id: string, targetTab: PageTab = 'incident') => {
    setActiveIncidentId(id);
    onNavigate(targetTab, id);
  };

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 style={{ fontSize: '1.6rem', fontWeight: 700, color: '#f8fafc', marginBottom: '6px' }}>
            Threat Incidents Overview
          </h1>
          <p style={{ color: '#94a3b8', fontSize: '0.875rem' }}>
            Inferred security campaigns and attack clusters with dynamic risk scoring and graph telemetry.
          </p>
        </div>
      </div>

      {/* KPI Metric Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
        <div className="glass-panel" style={{ padding: '18px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: '#94a3b8', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>TOTAL INCIDENTS</span>
            <Layers size={18} color="#38bdf8" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
            {incidents.length}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#64748b', marginTop: '4px' }}>
            {health?.incidents ?? incidents.length} in temporal graph
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '18px', borderColor: 'rgba(244, 63, 94, 0.25)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: '#fb7185', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>CRITICAL THREATS</span>
            <ShieldAlert size={18} color="#f43f5e" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#fb7185', fontFamily: 'var(--font-mono)' }}>
            {criticalCount}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#f43f5e', opacity: 0.8, marginTop: '4px' }}>
            Immediate action required
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '18px', borderColor: 'rgba(245, 158, 11, 0.25)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: '#fbbf24', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>HIGH SEVERITY</span>
            <AlertTriangle size={18} color="#f59e0b" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#fbbf24', fontFamily: 'var(--font-mono)' }}>
            {highCount}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#f59e0b', opacity: 0.8, marginTop: '4px' }}>
            Privilege Escalation & Lateral
          </div>
        </div>

        <div className="glass-panel" style={{ padding: '18px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: '#94a3b8', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>CORRELATED EVENTS</span>
            <Hash size={18} color="#10b981" />
          </div>
          <div style={{ fontSize: '1.8rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
            {totalEvents}
          </div>
          <div style={{ fontSize: '0.75rem', color: '#10b981', marginTop: '4px' }}>
            {health?.events ?? 3986} total events in knowledge base
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div
        className="glass-panel"
        style={{
          padding: '12px 18px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '16px',
          flexWrap: 'wrap',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: '240px' }}>
          <Search size={16} color="#64748b" />
          <input
            type="text"
            placeholder="Search incident ID (e.g. INC-03265)..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              background: 'transparent',
              border: 'none',
              outline: 'none',
              color: '#f8fafc',
              fontSize: '0.875rem',
              width: '100%',
              fontFamily: 'var(--font-mono)',
            }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Filter size={15} color="#64748b" />
          <span style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 500 }}>Risk Level:</span>
          {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((lvl) => (
            <button
              key={lvl}
              onClick={() => setRiskFilter(lvl)}
              style={{
                background: riskFilter === lvl ? 'rgba(56, 189, 248, 0.2)' : 'rgba(255, 255, 255, 0.04)',
                border: riskFilter === lvl ? '1px solid rgba(56, 189, 248, 0.5)' : '1px solid rgba(255, 255, 255, 0.08)',
                color: riskFilter === lvl ? '#38bdf8' : '#94a3b8',
                borderRadius: '6px',
                padding: '4px 10px',
                fontSize: '0.75rem',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              {lvl}
            </button>
          ))}
        </div>
      </div>

      {/* Incidents Table */}
      <div className="glass-panel glow-panel" style={{ overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.875rem' }}>
          <thead>
            <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.03)', borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
              <th style={{ padding: '14px 20px', color: '#94a3b8', fontWeight: 600 }}>INCIDENT ID</th>
              <th style={{ padding: '14px 20px', color: '#94a3b8', fontWeight: 600 }}>RISK SCORE</th>
              <th style={{ padding: '14px 20px', color: '#94a3b8', fontWeight: 600 }}>TIMEFRAME (UTC)</th>
              <th style={{ padding: '14px 20px', color: '#94a3b8', fontWeight: 600 }}>DURATION</th>
              <th style={{ padding: '14px 20px', color: '#94a3b8', fontWeight: 600 }}>EVENTS</th>
              <th style={{ padding: '14px 20px', color: '#94a3b8', fontWeight: 600, textAlign: 'right' }}>ACTIONS</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={6} style={{ padding: '36px', textAlign: 'center', color: '#94a3b8' }}>
                  Loading incidents from Virux Cypher engine...
                </td>
              </tr>
            ) : filteredIncidents.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ padding: '36px', textAlign: 'center', color: '#64748b' }}>
                  No incidents found matching criteria.
                </td>
              </tr>
            ) : (
              filteredIncidents.map((inc) => {
                const isActive = inc.incident_id === activeIncidentId;
                return (
                  <tr
                    key={inc.incident_id}
                    style={{
                      borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
                      backgroundColor: isActive ? 'rgba(56, 189, 248, 0.06)' : 'transparent',
                      transition: 'background-color 0.15s ease',
                      cursor: 'pointer',
                    }}
                    onClick={() => handleSelectIncident(inc.incident_id, 'incident')}
                  >
                    <td style={{ padding: '14px 20px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className="mono" style={{ fontWeight: 700, color: '#f8fafc', fontSize: '0.95rem' }}>
                          {inc.incident_id}
                        </span>
                        {isActive && (
                          <span
                            className="badge-mono"
                            style={{
                              background: 'rgba(56, 189, 248, 0.2)',
                              color: '#38bdf8',
                              border: '1px solid rgba(56, 189, 248, 0.4)',
                              fontSize: '0.65rem',
                            }}
                          >
                            ACTIVE
                          </span>
                        )}
                      </div>
                    </td>
                    <td style={{ padding: '14px 20px' }}>
                      <RiskBadge incident={inc} />
                    </td>
                    <td style={{ padding: '14px 20px', color: '#cbd5e1' }}>
                      <div className="mono" style={{ fontSize: '0.78rem' }}>
                        <div>{new Date(inc.start).toLocaleString()}</div>
                        <div style={{ color: '#64748b' }}>→ {new Date(inc.end).toLocaleString()}</div>
                      </div>
                    </td>
                    <td style={{ padding: '14px 20px', color: '#94a3b8' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                        <Clock size={13} color="#64748b" />
                        <span className="mono">{formatDuration(inc.start, inc.end)}</span>
                      </div>
                    </td>
                    <td style={{ padding: '14px 20px' }}>
                      <span className="badge-mono" style={{ background: 'rgba(255,255,255,0.06)', color: '#e2e8f0' }}>
                        {inc.event_count} events
                      </span>
                    </td>
                    <td style={{ padding: '14px 20px', textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: '6px' }}>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleSelectIncident(inc.incident_id, 'graph');
                          }}
                          className="btn-secondary"
                          style={{ padding: '5px 10px', fontSize: '0.75rem' }}
                        >
                          Graph
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleSelectIncident(inc.incident_id, 'prediction');
                          }}
                          className="btn-secondary"
                          style={{ padding: '5px 10px', fontSize: '0.75rem' }}
                        >
                          Predict
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleSelectIncident(inc.incident_id, 'incident');
                          }}
                          className="btn-primary"
                          style={{ padding: '5px 12px', fontSize: '0.75rem' }}
                        >
                          Trajectory <ArrowRight size={12} />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

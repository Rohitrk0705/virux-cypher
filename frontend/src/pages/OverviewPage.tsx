import React, { useState } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { useIncident } from '../context/IncidentContext';
import { RiskBadge, calculateIncidentRisk } from '../components/common/RiskBadge';
import { AnimatedCounter } from '../components/common/AnimatedCounter';
import { PageTab } from '../components/layout/Sidebar';
import { ShieldAlert, Search, Filter, ArrowRight, Clock, Hash, AlertTriangle, Layers } from 'lucide-react';

interface OverviewPageProps {
  onNavigate: (tab: PageTab, incidentId?: string) => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({ onNavigate }) => {
  const { incidents, activeIncidentId, setActiveIncidentId, health, loading } = useIncident();
  const [search, setSearch] = useState('');
  const [riskFilter, setRiskFilter] = useState<'ALL' | 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'>('ALL');
  const prefersReduced = useReducedMotion();

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

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: prefersReduced ? 0 : 0.05,
      },
    },
  };

  const itemVariants = {
    hidden: { opacity: 0, y: prefersReduced ? 0 : 10 },
    visible: {
      opacity: 1,
      y: 0,
      transition: { duration: 0.25, ease: 'easeOut' as const },
    },
  };

  return (
    <div style={{ padding: '26px 32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div>
          <h1 style={{ fontSize: '1.65rem', fontWeight: 800, color: '#f8fafc', marginBottom: '6px' }}>
            Threat Incidents Command Center
          </h1>
          <p style={{ color: '#94a3b8', fontSize: '0.875rem' }}>
            Inferred intrusion campaigns and attack clusters with dynamic risk scoring and graph telemetry.
          </p>
        </div>
      </div>

      {/* KPI Metric Cards */}
      <motion.div
        variants={containerVariants}
        initial="hidden"
        animate="visible"
        style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}
      >
        {/* TOTAL INCIDENTS */}
        <motion.div
          variants={itemVariants}
          className="glass-panel glass-panel-interactive"
          style={{ padding: '20px' }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', color: '#94a3b8', marginBottom: '10px' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, letterSpacing: '0.04em' }}>TOTAL INCIDENTS</span>
            <Layers size={18} color="#94a3b8" />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
            <AnimatedCounter value={incidents.length} />
          </div>
          <div style={{ fontSize: '0.72rem', color: '#64748b', marginTop: '6px', fontFamily: 'var(--font-mono)' }}>
            {health?.incidents ?? incidents.length} in temporal graph
          </div>
        </motion.div>

        {/* CRITICAL THREATS (strictly reserved red) */}
        <motion.div
          variants={itemVariants}
          className="glass-panel glass-panel-interactive glow-panel-critical"
          style={{ padding: '20px' }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', color: '#ff6b6b', marginBottom: '10px' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, letterSpacing: '0.04em', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span className="pulse-dot-red" style={{ width: '6px', height: '6px' }} /> CRITICAL THREATS
            </span>
            <ShieldAlert size={18} color="#ff4d4d" />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: '#ff6b6b', fontFamily: 'var(--font-mono)' }}>
            <AnimatedCounter value={criticalCount} />
          </div>
          <div style={{ fontSize: '0.72rem', color: '#ff6b6b', opacity: 0.85, marginTop: '6px', fontFamily: 'var(--font-mono)' }}>
            Immediate SOC triage required
          </div>
        </motion.div>

        {/* HIGH SEVERITY (amber) */}
        <motion.div
          variants={itemVariants}
          className="glass-panel glass-panel-interactive glow-panel-amber"
          style={{ padding: '20px' }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', color: '#ff9c5a', marginBottom: '10px' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, letterSpacing: '0.04em', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span className="pulse-dot-amber" style={{ width: '6px', height: '6px' }} /> HIGH SEVERITY
            </span>
            <AlertTriangle size={18} color="#ff8a3d" />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: '#ff9c5a', fontFamily: 'var(--font-mono)' }}>
            <AnimatedCounter value={highCount} />
          </div>
          <div style={{ fontSize: '0.72rem', color: '#ff8a3d', opacity: 0.85, marginTop: '6px', fontFamily: 'var(--font-mono)' }}>
            Privilege Escalation & Lateral Movement
          </div>
        </motion.div>

        {/* CORRELATED EVENTS */}
        <motion.div
          variants={itemVariants}
          className="glass-panel glass-panel-interactive"
          style={{ padding: '20px' }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', color: '#94a3b8', marginBottom: '10px' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 700, letterSpacing: '0.04em' }}>CORRELATED EVENTS</span>
            <Hash size={18} color="#10b981" />
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
            <AnimatedCounter value={totalEvents} />
          </div>
          <div style={{ fontSize: '0.72rem', color: '#10b981', marginTop: '6px', fontFamily: 'var(--font-mono)' }}>
            {health?.events ?? 3986} normalized telemetry events
          </div>
        </motion.div>
      </motion.div>

      {/* Filter and Search Bar */}
      <div
        className="glass-panel"
        style={{
          padding: '14px 20px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          gap: '16px',
          flexWrap: 'wrap',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flex: 1, minWidth: '260px' }}>
          <Search size={16} color="#ff8a3d" />
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
              fontSize: '0.85rem',
              width: '100%',
              fontFamily: 'var(--font-mono)',
            }}
          />
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Filter size={14} color="#64748b" />
          <span style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 600 }}>Risk Filter:</span>
          {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((lvl) => (
            <button
              key={lvl}
              onClick={() => setRiskFilter(lvl)}
              style={{
                background:
                  riskFilter === lvl
                    ? lvl === 'CRITICAL'
                      ? 'rgba(255, 77, 77, 0.2)'
                      : 'rgba(255, 138, 61, 0.2)'
                    : 'rgba(255, 255, 255, 0.04)',
                border:
                  riskFilter === lvl
                    ? lvl === 'CRITICAL'
                      ? '1px solid rgba(255, 77, 77, 0.6)'
                      : '1px solid rgba(255, 138, 61, 0.6)'
                    : '1px solid rgba(255, 255, 255, 0.08)',
                color:
                  riskFilter === lvl
                    ? lvl === 'CRITICAL'
                      ? '#ff6b6b'
                      : '#ff8a3d'
                    : '#94a3b8',
                boxShadow:
                  riskFilter === lvl
                    ? lvl === 'CRITICAL'
                      ? '0 0 10px rgba(255, 77, 77, 0.25)'
                      : '0 0 10px rgba(255, 138, 61, 0.2)'
                    : 'none',
                borderRadius: '6px',
                padding: '4px 10px',
                fontSize: '0.72rem',
                fontWeight: 700,
                cursor: 'pointer',
                transition: 'all 0.15s ease',
              }}
            >
              {lvl}
            </button>
          ))}
        </div>
      </div>

      {/* Incidents Table */}
      <div className="glass-panel" style={{ overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.85rem' }}>
          <thead>
            <tr style={{ backgroundColor: 'rgba(255, 255, 255, 0.03)', borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
              <th style={{ padding: '14px 20px', color: '#94a3b8', fontWeight: 700, fontFamily: 'var(--font-heading)' }}>INCIDENT ID</th>
              <th style={{ padding: '14px 20px', color: '#94a3b8', fontWeight: 700, fontFamily: 'var(--font-heading)' }}>RISK SCORE</th>
              <th style={{ padding: '14px 20px', color: '#94a3b8', fontWeight: 700, fontFamily: 'var(--font-heading)' }}>TIMEFRAME (UTC)</th>
              <th style={{ padding: '14px 20px', color: '#94a3b8', fontWeight: 700, fontFamily: 'var(--font-heading)' }}>DURATION</th>
              <th style={{ padding: '14px 20px', color: '#94a3b8', fontWeight: 700, fontFamily: 'var(--font-heading)' }}>EVENTS</th>
              <th style={{ padding: '14px 20px', color: '#94a3b8', fontWeight: 700, fontFamily: 'var(--font-heading)', textAlign: 'right' }}>ACTIONS</th>
            </tr>
          </thead>
          <motion.tbody variants={containerVariants} initial="hidden" animate="visible">
            {loading ? (
              <tr>
                <td colSpan={6} style={{ padding: '40px', textAlign: 'center', color: '#94a3b8' }}>
                  Loading incidents from Virux Cypher engine...
                </td>
              </tr>
            ) : filteredIncidents.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ padding: '40px', textAlign: 'center', color: '#64748b' }}>
                  No incidents found matching criteria.
                </td>
              </tr>
            ) : (
              filteredIncidents.map((inc) => {
                const isActive = inc.incident_id === activeIncidentId;
                return (
                  <motion.tr
                    key={inc.incident_id}
                    variants={itemVariants}
                    style={{
                      borderBottom: '1px solid rgba(255, 255, 255, 0.05)',
                      backgroundColor: isActive ? 'rgba(255, 138, 61, 0.08)' : 'transparent',
                      transition: 'background-color 0.15s ease',
                      cursor: 'pointer',
                    }}
                    onClick={() => handleSelectIncident(inc.incident_id, 'incident')}
                    onMouseEnter={(e) => {
                      if (!isActive) e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.03)';
                    }}
                    onMouseLeave={(e) => {
                      if (!isActive) e.currentTarget.style.backgroundColor = 'transparent';
                    }}
                  >
                    <td style={{ padding: '14px 20px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span className="mono" style={{ fontWeight: 700, color: '#f8fafc', fontSize: '0.925rem' }}>
                          {inc.incident_id}
                        </span>
                        {isActive && (
                          <span
                            className="badge-mono"
                            style={{
                              background: 'rgba(255, 138, 61, 0.2)',
                              color: '#ff8a3d',
                              border: '1px solid rgba(255, 138, 61, 0.5)',
                              fontSize: '0.65rem',
                              fontWeight: 700,
                            }}
                          >
                            ACTIVE
                          </span>
                        )}
                      </div>
                    </td>
                    <td style={{ padding: '14px 20px' }}>
                      <RiskBadge incident={inc} animateScore={true} />
                    </td>
                    <td style={{ padding: '14px 20px', color: '#cbd5e1' }}>
                      <div className="mono" style={{ fontSize: '0.78rem' }}>
                        <div>{new Date(inc.start).toLocaleString()}</div>
                        <div style={{ color: '#64748b' }}>→ {new Date(inc.end).toLocaleString()}</div>
                      </div>
                    </td>
                    <td style={{ padding: '14px 20px', color: '#94a3b8' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
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
                  </motion.tr>
                );
              })
            )}
          </motion.tbody>
        </table>
      </div>
    </div>
  );
};

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence, useReducedMotion } from 'framer-motion';
import { useIncident } from '../context/IncidentContext';
import { api } from '../api/client';
import { AttackTrajectory, NormalizedEvent } from '../types/contracts';
import { TechniqueTag } from '../components/common/TechniqueTag';
import { RiskBadge } from '../components/common/RiskBadge';
import {
  Activity,
  ArrowRight,
  Clock,
  Terminal,
  Search,
  ChevronDown,
  ChevronRight,
  Zap,
} from 'lucide-react';

export const IncidentPage: React.FC = () => {
  const { activeIncidentId, incidents } = useIncident();
  const [trajectory, setTrajectory] = useState<AttackTrajectory | null>(null);
  const [events, setEvents] = useState<NormalizedEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [eventSearch, setEventSearch] = useState('');
  const [selectedAction, setSelectedAction] = useState('ALL');
  const [expandedEventId, setExpandedEventId] = useState<string | null>(null);
  const prefersReduced = useReducedMotion();

  const activeIncident = incidents.find((i) => i.incident_id === activeIncidentId);

  useEffect(() => {
    let isCurrent = true;
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const [trajData, eventsData] = await Promise.all([
          api.getTrajectory(activeIncidentId),
          api.getEvents(activeIncidentId),
        ]);
        if (isCurrent) {
          setTrajectory(trajData);
          setEvents(eventsData);
        }
      } catch (err: any) {
        if (isCurrent) setError(err.message || 'Failed to load incident trajectory and events');
      } finally {
        if (isCurrent) setLoading(false);
      }
    };
    fetchData();
    return () => {
      isCurrent = false;
    };
  }, [activeIncidentId]);

  const uniqueActions = ['ALL', ...Array.from(new Set(events.map((e) => e.action)))];

  const filteredEvents = events.filter((e) => {
    const matchesAction = selectedAction === 'ALL' || e.action === selectedAction;
    const matchesSearch =
      e.event_id.toLowerCase().includes(eventSearch.toLowerCase()) ||
      e.user.toLowerCase().includes(eventSearch.toLowerCase()) ||
      (e.process && e.process.toLowerCase().includes(eventSearch.toLowerCase())) ||
      e.device.toLowerCase().includes(eventSearch.toLowerCase());
    return matchesAction && matchesSearch;
  });

  const timelineContainerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: prefersReduced ? 0 : 0.09,
      },
    },
  };

  const timelineItemVariants = {
    hidden: { opacity: 0, x: prefersReduced ? 0 : -16, scale: prefersReduced ? 1 : 0.95 },
    visible: {
      opacity: 1,
      x: 0,
      scale: 1,
      transition: { duration: 0.3, ease: 'easeOut' as const },
    },
  };

  return (
    <div style={{ padding: '26px 32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Incident Summary Bar */}
      <div
        className="glass-panel"
        style={{
          padding: '20px 24px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '16px',
          borderLeft: '4px solid var(--accent-amber)',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '8px' }}>
            <span style={{ fontSize: '1.45rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
              {activeIncidentId}
            </span>
            {activeIncident && <RiskBadge incident={activeIncident} animateScore={true} />}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', color: '#94a3b8', fontSize: '0.8rem', fontFamily: 'var(--font-mono)' }}>
            <span>
              Time window: <strong style={{ color: '#cbd5e1' }}>{activeIncident?.start ? new Date(activeIncident.start).toUTCString() : '—'}</strong>
            </span>
            <span>•</span>
            <span>
              Total Events: <strong style={{ color: '#ff8a3d' }}>{events.length}</strong>
            </span>
            <span>•</span>
            <span>
              Trajectory Steps: <strong style={{ color: '#ff8a3d' }}>{trajectory?.techniques.length ?? 0}</strong>
            </span>
          </div>
        </div>
      </div>

      {/* Attack Trajectory Timeline */}
      <div className="glass-panel" style={{ padding: '24px', position: 'relative', overflow: 'hidden' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '22px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                background: 'rgba(255, 138, 61, 0.15)',
                border: '1px solid rgba(255, 138, 61, 0.4)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Activity size={18} color="#ff8a3d" />
            </div>
            <div>
              <h2 style={{ fontSize: '1.2rem', fontWeight: 700, color: '#f8fafc' }}>
                Sequential Attack Trajectory
              </h2>
              <p style={{ fontSize: '0.75rem', color: '#64748b' }}>
                Contract 3: Reconstructed MITRE ATT&CK progression chain ordered by causal execution time
              </p>
            </div>
          </div>
          <span
            className="badge-mono"
            style={{
              background: 'rgba(255, 138, 61, 0.12)',
              border: '1px solid rgba(255, 138, 61, 0.35)',
              color: '#ff8a3d',
            }}
          >
            <Zap size={11} /> Causal Flow
          </span>
        </div>

        {loading ? (
          <div style={{ padding: '36px', textAlign: 'center', color: '#94a3b8', fontSize: '0.875rem' }}>
            Reconstructing attack trajectory from temporal knowledge graph...
          </div>
        ) : error ? (
          <div style={{ padding: '20px', color: '#ff6b6b', background: 'rgba(255, 77, 77, 0.1)', borderRadius: '8px', border: '1px solid rgba(255, 77, 77, 0.3)' }}>
            {error}
          </div>
        ) : !trajectory || trajectory.techniques.length === 0 ? (
          <div style={{ padding: '36px', textAlign: 'center', color: '#64748b', fontSize: '0.875rem' }}>
            No mapped ATT&CK techniques in trajectory for this incident.
          </div>
        ) : (
          <div>
            {/* Timeline Horizontal Steps Flow */}
            <motion.div
              variants={timelineContainerVariants}
              initial="hidden"
              animate="visible"
              style={{
                display: 'flex',
                alignItems: 'center',
                overflowX: 'auto',
                padding: '8px 4px 20px',
                gap: '12px',
              }}
            >
              {trajectory.techniques.map((step, idx) => {
                const prevStep = idx > 0 ? trajectory.techniques[idx - 1] : null;
                const deltaSec = prevStep
                  ? Math.round((new Date(step.timestamp).getTime() - new Date(prevStep.timestamp).getTime()) / 1000)
                  : null;

                return (
                  <React.Fragment key={`${step.id}-${idx}`}>
                    <motion.div
                      variants={timelineItemVariants}
                      whileHover={prefersReduced ? {} : { y: -3, transition: { duration: 0.18 } }}
                      className="glass-panel"
                      style={{
                        minWidth: '230px',
                        padding: '18px',
                        display: 'flex',
                        flexDirection: 'column',
                        justifyContent: 'space-between',
                        backgroundColor: 'rgba(16, 21, 34, 0.82)',
                        border: '1px solid rgba(255, 138, 61, 0.3)',
                        borderRadius: '10px',
                        boxShadow: '0 8px 24px rgba(0, 0, 0, 0.4), 0 0 16px rgba(255, 138, 61, 0.08)',
                        position: 'relative',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
                        <span
                          className="badge-mono"
                          style={{
                            background: 'rgba(255, 138, 61, 0.16)',
                            border: '1px solid rgba(255, 138, 61, 0.45)',
                            color: '#ff8a3d',
                            fontSize: '0.68rem',
                            fontWeight: 700,
                          }}
                        >
                          STEP #{idx + 1}
                        </span>
                        {deltaSec !== null && (
                          <span style={{ fontSize: '0.7rem', color: '#ff8a3d', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                            +{deltaSec}s
                          </span>
                        )}
                      </div>

                      <div style={{ marginBottom: '14px' }}>
                        <TechniqueTag techniqueId={step.id} glow={idx === trajectory.techniques.length - 1} />
                      </div>

                      <div style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                        <Clock size={11} style={{ verticalAlign: 'middle', marginRight: '5px', color: '#64748b' }} />
                        {new Date(step.timestamp).toLocaleTimeString()}
                      </div>
                    </motion.div>

                    {idx < trajectory.techniques.length - 1 && (
                      <motion.div
                        variants={timelineItemVariants}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          color: '#ff8a3d',
                          padding: '0 4px',
                          position: 'relative',
                        }}
                      >
                        <ArrowRight size={20} color="#ff8a3d" style={{ filter: 'drop-shadow(0 0 6px rgba(255, 138, 61, 0.5))' }} />
                      </motion.div>
                    )}
                  </React.Fragment>
                );
              })}
            </motion.div>

            {/* Trajectory textual chain */}
            <div
              style={{
                marginTop: '12px',
                padding: '12px 18px',
                background: 'rgba(10, 13, 20, 0.75)',
                borderRadius: '8px',
                border: '1px solid rgba(255, 255, 255, 0.06)',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                flexWrap: 'wrap',
                fontSize: '0.825rem',
              }}
            >
              <span style={{ color: '#94a3b8', fontWeight: 700, fontFamily: 'var(--font-heading)' }}>Progression Vector:</span>
              {trajectory.techniques.map((t, i) => (
                <React.Fragment key={i}>
                  <code style={{ color: '#ff8a3d', fontWeight: 700, background: 'rgba(255, 138, 61, 0.1)', padding: '2px 6px', borderRadius: '4px' }}>
                    {t.id}
                  </code>
                  {i < trajectory.techniques.length - 1 && <span style={{ color: '#64748b' }}>→</span>}
                </React.Fragment>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Normalized Events Table (Contract 1) */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px', flexWrap: 'wrap', gap: '14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '32px',
                height: '32px',
                borderRadius: '8px',
                background: 'rgba(16, 185, 129, 0.15)',
                border: '1px solid rgba(16, 185, 129, 0.4)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              <Terminal size={18} color="#10b981" />
            </div>
            <div>
              <h3 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#f8fafc' }}>
                Correlated Telemetry Events
              </h3>
              <p style={{ fontSize: '0.75rem', color: '#64748b' }}>
                Contract 1: Ingested network, process execution, and auth logs tied to active incident
              </p>
            </div>
            <span className="badge-mono" style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#34d399', border: '1px solid rgba(16, 185, 129, 0.35)' }}>
              {filteredEvents.length} events
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {/* Search */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', background: 'rgba(10, 13, 20, 0.85)', padding: '6px 12px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.1)' }}>
              <Search size={14} color="#ff8a3d" />
              <input
                type="text"
                placeholder="Filter events, users, processes..."
                value={eventSearch}
                onChange={(e) => setEventSearch(e.target.value)}
                style={{ background: 'transparent', border: 'none', color: '#fff', fontSize: '0.78rem', outline: 'none', fontFamily: 'var(--font-mono)' }}
              />
            </div>

            {/* Action filter */}
            <select
              value={selectedAction}
              onChange={(e) => setSelectedAction(e.target.value)}
              style={{
                background: 'rgba(10, 13, 20, 0.85)',
                color: '#cbd5e1',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '6px',
                padding: '6px 10px',
                fontSize: '0.78rem',
                outline: 'none',
                fontFamily: 'var(--font-mono)',
              }}
            >
              {uniqueActions.map((act) => (
                <option key={act} value={act} style={{ background: '#0a0d14' }}>
                  {act}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)', color: '#94a3b8', background: 'rgba(255, 255, 255, 0.02)' }}>
                <th style={{ padding: '12px 14px' }}></th>
                <th style={{ padding: '12px 14px', fontFamily: 'var(--font-heading)', fontWeight: 600 }}>EVENT ID</th>
                <th style={{ padding: '12px 14px', fontFamily: 'var(--font-heading)', fontWeight: 600 }}>TIMESTAMP</th>
                <th style={{ padding: '12px 14px', fontFamily: 'var(--font-heading)', fontWeight: 600 }}>USER</th>
                <th style={{ padding: '12px 14px', fontFamily: 'var(--font-heading)', fontWeight: 600 }}>DEVICE</th>
                <th style={{ padding: '12px 14px', fontFamily: 'var(--font-heading)', fontWeight: 600 }}>ACTION</th>
                <th style={{ padding: '12px 14px', fontFamily: 'var(--font-heading)', fontWeight: 600 }}>PROCESS</th>
                <th style={{ padding: '12px 14px', fontFamily: 'var(--font-heading)', fontWeight: 600 }}>SOURCE → DEST IP</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.map((evt) => {
                const isExpanded = expandedEventId === evt.event_id;
                return (
                  <React.Fragment key={evt.event_id}>
                    <tr
                      style={{
                        borderBottom: '1px solid rgba(255,255,255,0.04)',
                        backgroundColor: isExpanded ? 'rgba(255, 138, 61, 0.08)' : 'transparent',
                        cursor: 'pointer',
                        transition: 'background-color 0.15s ease',
                      }}
                      onClick={() => setExpandedEventId(isExpanded ? null : evt.event_id)}
                      onMouseEnter={(e) => {
                        if (!isExpanded) e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.03)';
                      }}
                      onMouseLeave={(e) => {
                        if (!isExpanded) e.currentTarget.style.backgroundColor = 'transparent';
                      }}
                    >
                      <td style={{ padding: '12px 14px', width: '24px' }}>
                        {isExpanded ? <ChevronDown size={14} color="#ff8a3d" /> : <ChevronRight size={14} color="#64748b" />}
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <span className="mono" style={{ color: '#ff8a3d', fontWeight: 700 }}>{evt.event_id}</span>
                      </td>
                      <td style={{ padding: '12px 14px', color: '#cbd5e1' }} className="mono">
                        {new Date(evt.timestamp).toISOString()}
                      </td>
                      <td style={{ padding: '12px 14px', color: '#f8fafc', fontWeight: 600 }}>
                        {evt.user}
                      </td>
                      <td style={{ padding: '12px 14px', color: '#94a3b8' }} className="mono">
                        {evt.device}
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <span
                          className="badge-mono"
                          style={{
                            background: 'rgba(255,255,255,0.06)',
                            border: '1px solid rgba(255,255,255,0.1)',
                            color: '#e2e8f0',
                            fontSize: '0.7rem',
                          }}
                        >
                          {evt.action}
                        </span>
                      </td>
                      <td style={{ padding: '12px 14px', color: '#facc15' }} className="mono">
                        {evt.process || '—'}
                      </td>
                      <td style={{ padding: '12px 14px', color: '#94a3b8' }} className="mono">
                        {evt.source_ip} {evt.destination_ip ? `→ ${evt.destination_ip}` : ''}
                      </td>
                    </tr>

                    {isExpanded && (
                      <tr style={{ backgroundColor: 'rgba(10, 13, 20, 0.9)' }}>
                        <td colSpan={8} style={{ padding: '18px 24px', borderBottom: '1px solid rgba(255, 138, 61, 0.25)' }}>
                          <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap', fontSize: '0.78rem' }}>
                            <div>
                              <div style={{ color: '#64748b', marginBottom: '4px' }}>Source Service</div>
                              <div style={{ color: '#f8fafc', fontWeight: 600 }}>{evt.source}</div>
                            </div>
                            {evt.destination_port !== undefined && evt.destination_port !== null && (
                              <div>
                                <div style={{ color: '#64748b', marginBottom: '4px' }}>Destination Port</div>
                                <div style={{ color: '#ff8a3d' }} className="mono">{evt.destination_port}</div>
                              </div>
                            )}
                            {evt.byte_count !== undefined && evt.byte_count !== null && (
                              <div>
                                <div style={{ color: '#64748b', marginBottom: '4px' }}>Bytes Transferred</div>
                                <div style={{ color: '#ff6b6b' }} className="mono">
                                  {(evt.byte_count / (1024 * 1024)).toFixed(2)} MB ({evt.byte_count} B)
                                </div>
                              </div>
                            )}
                            <div style={{ width: '100%', marginTop: '8px' }}>
                              <div style={{ color: '#64748b', marginBottom: '6px', fontWeight: 600 }}>RAW TELEMETRY PAYLOAD:</div>
                              <pre
                                style={{
                                  background: 'rgba(5, 7, 12, 0.95)',
                                  padding: '12px',
                                  borderRadius: '6px',
                                  border: '1px solid rgba(255, 255, 255, 0.08)',
                                  color: '#cbd5e1',
                                  fontFamily: 'var(--font-mono)',
                                  fontSize: '0.72rem',
                                  overflowX: 'auto',
                                }}
                              >
                                {JSON.stringify(evt, null, 2)}
                              </pre>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

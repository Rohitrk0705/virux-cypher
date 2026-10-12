import React, { useState, useEffect } from 'react';
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
  Shield,
  Layers,
  Search,
  Filter,
  ChevronDown,
  ChevronRight,
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

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Top Incident Summary Bar */}
      <div
        className="glass-panel"
        style={{
          padding: '20px',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '16px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '6px' }}>
            <span style={{ fontSize: '1.4rem', fontWeight: 800, color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>
              {activeIncidentId}
            </span>
            {activeIncident && <RiskBadge incident={activeIncident} />}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '16px', color: '#94a3b8', fontSize: '0.8rem' }}>
            <span>
              Time window: <strong style={{ color: '#cbd5e1' }}>{activeIncident?.start ? new Date(activeIncident.start).toUTCString() : '—'}</strong>
            </span>
            <span>•</span>
            <span>
              Total Events: <strong style={{ color: '#cbd5e1' }}>{events.length}</strong>
            </span>
            <span>•</span>
            <span>
              Technique Steps: <strong style={{ color: '#cbd5e1' }}>{trajectory?.techniques.length ?? 0}</strong>
            </span>
          </div>
        </div>
      </div>

      {/* Attack Trajectory Timeline */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '20px' }}>
          <Activity size={20} color="#38bdf8" />
          <h2 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#f8fafc' }}>
            Sequential ATT&CK Trajectory (Contract 3)
          </h2>
        </div>

        {loading ? (
          <div style={{ padding: '30px', textAlign: 'center', color: '#94a3b8' }}>
            Reconstructing attack trajectory from knowledge graph...
          </div>
        ) : error ? (
          <div style={{ padding: '20px', color: '#fb7185', background: 'rgba(244,63,94,0.1)', borderRadius: '8px' }}>
            {error}
          </div>
        ) : !trajectory || trajectory.techniques.length === 0 ? (
          <div style={{ padding: '30px', textAlign: 'center', color: '#64748b' }}>
            No mapped ATT&CK techniques in trajectory for this incident.
          </div>
        ) : (
          <div>
            {/* Timeline Horizontal Steps Flow */}
            <div
              style={{
                display: 'flex',
                alignItems: 'stretch',
                overflowX: 'auto',
                paddingBottom: '16px',
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
                    <div
                      className="glass-panel"
                      style={{
                        minWidth: '220px',
                        padding: '16px',
                        display: 'flex',
                        flexDirection: 'column',
                        justifyContent: 'space-between',
                        backgroundColor: 'rgba(20, 28, 45, 0.75)',
                        border: '1px solid rgba(56, 189, 248, 0.25)',
                        borderRadius: '10px',
                        position: 'relative',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
                        <span
                          className="badge-mono"
                          style={{
                            background: 'rgba(56, 189, 248, 0.15)',
                            color: '#38bdf8',
                            fontSize: '0.65rem',
                          }}
                        >
                          STEP #{idx + 1}
                        </span>
                        {deltaSec !== null && (
                          <span style={{ fontSize: '0.7rem', color: '#64748b', fontFamily: 'var(--font-mono)' }}>
                            +{deltaSec}s
                          </span>
                        )}
                      </div>

                      <div style={{ marginBottom: '12px' }}>
                        <TechniqueTag techniqueId={step.id} />
                      </div>

                      <div style={{ fontSize: '0.72rem', color: '#94a3b8', fontFamily: 'var(--font-mono)' }}>
                        <Clock size={11} style={{ verticalAlign: 'middle', marginRight: '4px' }} />
                        {new Date(step.timestamp).toLocaleTimeString()}
                      </div>
                    </div>

                    {idx < trajectory.techniques.length - 1 && (
                      <div style={{ display: 'flex', alignItems: 'center', color: '#38bdf8' }}>
                        <ArrowRight size={18} opacity={0.6} />
                      </div>
                    )}
                  </React.Fragment>
                );
              })}
            </div>

            {/* Trajectory textual chain */}
            <div
              style={{
                marginTop: '16px',
                padding: '12px 16px',
                background: 'rgba(0,0,0,0.3)',
                borderRadius: '8px',
                border: '1px solid rgba(255,255,255,0.05)',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                flexWrap: 'wrap',
                fontSize: '0.85rem',
              }}
            >
              <span style={{ color: '#94a3b8', fontWeight: 600 }}>Trajectory Chain:</span>
              {trajectory.techniques.map((t, i) => (
                <React.Fragment key={i}>
                  <code style={{ color: '#38bdf8', fontWeight: 700 }}>{t.id}</code>
                  {i < trajectory.techniques.length - 1 && <span style={{ color: '#64748b' }}>→</span>}
                </React.Fragment>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Normalized Events Table (Contract 1) */}
      <div className="glass-panel" style={{ padding: '24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <Terminal size={18} color="#10b981" />
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: '#f8fafc' }}>
              Normalized Events (Contract 1)
            </h3>
            <span className="badge-mono" style={{ background: 'rgba(16, 185, 129, 0.15)', color: '#34d399' }}>
              {filteredEvents.length} events
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {/* Search */}
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'rgba(0,0,0,0.3)', padding: '4px 10px', borderRadius: '6px', border: '1px solid rgba(255,255,255,0.08)' }}>
              <Search size={14} color="#64748b" />
              <input
                type="text"
                placeholder="Filter events..."
                value={eventSearch}
                onChange={(e) => setEventSearch(e.target.value)}
                style={{ background: 'transparent', border: 'none', color: '#fff', fontSize: '0.75rem', outline: 'none' }}
              />
            </div>

            {/* Action filter */}
            <select
              value={selectedAction}
              onChange={(e) => setSelectedAction(e.target.value)}
              style={{
                background: 'rgba(0,0,0,0.3)',
                color: '#cbd5e1',
                border: '1px solid rgba(255,255,255,0.08)',
                borderRadius: '6px',
                padding: '4px 8px',
                fontSize: '0.75rem',
                outline: 'none',
              }}
            >
              {uniqueActions.map((act) => (
                <option key={act} value={act}>
                  {act}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.8rem', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255,255,255,0.08)', color: '#94a3b8' }}>
                <th style={{ padding: '10px 12px' }}></th>
                <th style={{ padding: '10px 12px' }}>EVENT ID</th>
                <th style={{ padding: '10px 12px' }}>TIMESTAMP</th>
                <th style={{ padding: '10px 12px' }}>USER</th>
                <th style={{ padding: '10px 12px' }}>DEVICE</th>
                <th style={{ padding: '10px 12px' }}>ACTION</th>
                <th style={{ padding: '10px 12px' }}>PROCESS</th>
                <th style={{ padding: '10px 12px' }}>SOURCE → DEST IP</th>
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
                        backgroundColor: isExpanded ? 'rgba(56, 189, 248, 0.05)' : 'transparent',
                        cursor: 'pointer',
                      }}
                      onClick={() => setExpandedEventId(isExpanded ? null : evt.event_id)}
                    >
                      <td style={{ padding: '10px 12px', width: '24px' }}>
                        {isExpanded ? <ChevronDown size={14} color="#38bdf8" /> : <ChevronRight size={14} color="#64748b" />}
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        <span className="mono" style={{ color: '#38bdf8', fontWeight: 600 }}>{evt.event_id}</span>
                      </td>
                      <td style={{ padding: '10px 12px', color: '#cbd5e1' }} className="mono">
                        {new Date(evt.timestamp).toISOString()}
                      </td>
                      <td style={{ padding: '10px 12px', color: '#f8fafc', fontWeight: 500 }}>
                        {evt.user}
                      </td>
                      <td style={{ padding: '10px 12px', color: '#a855f7' }} className="mono">
                        {evt.device}
                      </td>
                      <td style={{ padding: '10px 12px' }}>
                        <span
                          className="badge-mono"
                          style={{
                            background: 'rgba(255,255,255,0.06)',
                            color: '#e2e8f0',
                            fontSize: '0.7rem',
                          }}
                        >
                          {evt.action}
                        </span>
                      </td>
                      <td style={{ padding: '10px 12px', color: '#fbbf24' }} className="mono">
                        {evt.process || '—'}
                      </td>
                      <td style={{ padding: '10px 12px', color: '#94a3b8' }} className="mono">
                        {evt.source_ip} {evt.destination_ip ? `→ ${evt.destination_ip}` : ''}
                      </td>
                    </tr>

                    {isExpanded && (
                      <tr style={{ backgroundColor: 'rgba(0,0,0,0.3)' }}>
                        <td colSpan={8} style={{ padding: '16px 24px' }}>
                          <div style={{ display: 'flex', gap: '24px', flexWrap: 'wrap', fontSize: '0.78rem' }}>
                            <div>
                              <div style={{ color: '#64748b', marginBottom: '4px' }}>Source Service</div>
                              <div style={{ color: '#f8fafc' }}>{evt.source}</div>
                            </div>
                            {evt.destination_port !== undefined && evt.destination_port !== null && (
                              <div>
                                <div style={{ color: '#64748b', marginBottom: '4px' }}>Destination Port</div>
                                <div style={{ color: '#38bdf8' }} className="mono">{evt.destination_port}</div>
                              </div>
                            )}
                            {evt.byte_count !== undefined && evt.byte_count !== null && (
                              <div>
                                <div style={{ color: '#64748b', marginBottom: '4px' }}>Bytes Transferred</div>
                                <div style={{ color: '#fb7185' }} className="mono">
                                  {(evt.byte_count / (1024 * 1024)).toFixed(2)} MB ({evt.byte_count} B)
                                </div>
                              </div>
                            )}
                            <div style={{ width: '100%', marginTop: '8px' }}>
                              <div style={{ color: '#64748b', marginBottom: '4px' }}>Raw JSON Representation:</div>
                              <pre
                                style={{
                                  background: '#090d16',
                                  padding: '10px',
                                  borderRadius: '6px',
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

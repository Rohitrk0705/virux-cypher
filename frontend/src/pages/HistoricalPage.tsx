import React, { useState, useEffect } from 'react';
import { useIncident } from '../context/IncidentContext';
import { api } from '../api/client';
import { HistoricalMatch } from '../types/contracts';
import { TechniqueTag } from '../components/common/TechniqueTag';
import { History, Shield, CheckCircle2, Percent, Layers, ExternalLink } from 'lucide-react';

export const HistoricalPage: React.FC = () => {
  const { activeIncidentId } = useIncident();
  const [matchData, setMatchData] = useState<HistoricalMatch | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let isCurrent = true;
    const fetchMatches = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await api.getMatch(activeIncidentId);
        if (isCurrent) setMatchData(data);
      } catch (err: any) {
        if (isCurrent) setError(err.message || 'Failed to load historical matches');
      } finally {
        if (isCurrent) setLoading(false);
      }
    };
    fetchMatches();
    return () => {
      isCurrent = false;
    };
  }, [activeIncidentId]);

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Page Title */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
          <History size={22} color="#38bdf8" />
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f8fafc' }}>
            Historical Threat Matching (Contract 4)
          </h1>
        </div>
        <p style={{ color: '#94a3b8', fontSize: '0.875rem' }}>
          Comparing active incident <code style={{ color: '#38bdf8' }}>{activeIncidentId}</code> trajectory against reference campaigns and known adversary group playbooks.
        </p>
      </div>

      {loading ? (
        <div className="glass-panel" style={{ padding: '40px', textAlign: 'center', color: '#94a3b8' }}>
          Calculating trajectory similarity vectors across historical intrusion sets...
        </div>
      ) : error ? (
        <div className="glass-panel" style={{ padding: '20px', color: '#fb7185', background: 'rgba(244,63,94,0.1)' }}>
          {error}
        </div>
      ) : !matchData || matchData.matches.length === 0 ? (
        <div className="glass-panel" style={{ padding: '40px', textAlign: 'center', color: '#64748b' }}>
          No historical campaign matches identified for this trajectory.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {matchData.matches.map((match, idx) => {
            const similarityPercent = Math.round(match.similarity * 100);
            const isTopMatch = idx === 0;

            return (
              <div
                key={match.attack_id}
                className="glass-panel"
                style={{
                  padding: '24px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '16px',
                  borderColor: isTopMatch ? 'rgba(56, 189, 248, 0.4)' : 'rgba(255, 255, 255, 0.07)',
                  backgroundColor: isTopMatch ? 'rgba(15, 23, 42, 0.85)' : 'rgba(15, 20, 34, 0.75)',
                  boxShadow: isTopMatch ? '0 0 25px rgba(56, 189, 248, 0.1)' : 'none',
                }}
              >
                {/* Header row */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <div
                      style={{
                        padding: '6px 12px',
                        borderRadius: '8px',
                        background: 'rgba(56, 189, 248, 0.15)',
                        border: '1px solid rgba(56, 189, 248, 0.3)',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        fontSize: '1rem',
                        color: '#f8fafc',
                      }}
                    >
                      {match.attack_id}
                    </div>

                    {isTopMatch && (
                      <span
                        className="badge-mono"
                        style={{
                          background: 'rgba(16, 185, 129, 0.15)',
                          color: '#34d399',
                          border: '1px solid rgba(16, 185, 129, 0.4)',
                          fontSize: '0.7rem',
                        }}
                      >
                        <CheckCircle2 size={12} /> TOP ALIGNED PATTERN
                      </span>
                    )}
                  </div>

                  {/* Similarity gauge & percentage */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                    <div style={{ textAlign: 'right' }}>
                      <div style={{ fontSize: '0.75rem', color: '#94a3b8' }}>Similarity Match</div>
                      <div
                        style={{
                          fontSize: '1.4rem',
                          fontWeight: 800,
                          fontFamily: 'var(--font-mono)',
                          color: similarityPercent >= 80 ? '#34d399' : similarityPercent >= 50 ? '#fbbf24' : '#94a3b8',
                        }}
                      >
                        {similarityPercent}%
                      </div>
                    </div>

                    <div
                      style={{
                        width: '100px',
                        height: '8px',
                        backgroundColor: 'rgba(255,255,255,0.08)',
                        borderRadius: '4px',
                        overflow: 'hidden',
                      }}
                    >
                      <div
                        style={{
                          width: `${similarityPercent}%`,
                          height: '100%',
                          backgroundColor: similarityPercent >= 80 ? '#10b981' : similarityPercent >= 50 ? '#f59e0b' : '#38bdf8',
                          transition: 'width 0.5s ease-out',
                        }}
                      />
                    </div>
                  </div>
                </div>

                {/* Common techniques */}
                <div>
                  <div style={{ fontSize: '0.8rem', color: '#94a3b8', marginBottom: '8px', fontWeight: 600 }}>
                    COMMON TECHNIQUES ({match.common_techniques.length}):
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                    {match.common_techniques.map((tech) => (
                      <TechniqueTag key={tech} techniqueId={tech} />
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

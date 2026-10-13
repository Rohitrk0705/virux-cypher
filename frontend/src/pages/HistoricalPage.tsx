import React, { useState, useEffect } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { useIncident } from '../context/IncidentContext';
import { api } from '../api/client';
import { HistoricalMatch } from '../types/contracts';
import { TechniqueTag } from '../components/common/TechniqueTag';
import { AnimatedCounter } from '../components/common/AnimatedCounter';
import { History, CheckCircle2, Shield, Layers } from 'lucide-react';

export const HistoricalPage: React.FC = () => {
  const { activeIncidentId } = useIncident();
  const [matchData, setMatchData] = useState<HistoricalMatch | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const prefersReduced = useReducedMotion();

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

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: prefersReduced ? 0 : 0.08,
      },
    },
  };

  const itemVariants = {
    hidden: { opacity: 0, y: prefersReduced ? 0 : 12 },
    visible: {
      opacity: 1,
      y: 0,
      transition: { duration: 0.28, ease: 'easeOut' as const },
    },
  };

  return (
    <div style={{ padding: '26px 32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Page Title */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
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
            <History size={18} color="#ff8a3d" />
          </div>
          <h1 style={{ fontSize: '1.6rem', fontWeight: 800, color: '#f8fafc' }}>
            Historical Threat Attribution (Contract 4)
          </h1>
        </div>
        <p style={{ color: '#94a3b8', fontSize: '0.875rem' }}>
          Comparing active incident <code style={{ color: '#ff8a3d', fontWeight: 700 }}>{activeIncidentId}</code> trajectory against reference intrusion campaigns and threat actor playbooks.
        </p>
      </div>

      {loading ? (
        <div className="glass-panel" style={{ padding: '48px', textAlign: 'center', color: '#94a3b8', fontSize: '0.875rem' }}>
          Calculating cosine trajectory similarity vectors across intrusion sets...
        </div>
      ) : error ? (
        <div className="glass-panel glow-panel-critical" style={{ padding: '20px', color: '#ff6b6b' }}>
          {error}
        </div>
      ) : !matchData || matchData.matches.length === 0 ? (
        <div className="glass-panel" style={{ padding: '48px', textAlign: 'center', color: '#64748b', fontSize: '0.875rem' }}>
          No historical campaign matches identified for this trajectory.
        </div>
      ) : (
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}
        >
          {matchData.matches.map((match, idx) => {
            const similarityPercent = Math.round(match.similarity * 100);
            const isTopMatch = idx === 0;

            return (
              <motion.div
                key={match.attack_id}
                variants={itemVariants}
                whileHover={prefersReduced ? {} : { y: -2, transition: { duration: 0.18 } }}
                className={`glass-panel ${isTopMatch ? 'glow-panel-amber' : ''}`}
                style={{
                  padding: '24px 28px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '18px',
                  borderColor: isTopMatch ? 'rgba(255, 138, 61, 0.45)' : 'rgba(255, 255, 255, 0.08)',
                  backgroundColor: isTopMatch ? 'rgba(18, 24, 38, 0.88)' : 'rgba(14, 18, 28, 0.72)',
                  borderRadius: '12px',
                }}
              >
                {/* Header row */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '14px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                    <div
                      style={{
                        padding: '6px 14px',
                        borderRadius: '8px',
                        background: isTopMatch ? 'rgba(255, 138, 61, 0.2)' : 'rgba(255, 255, 255, 0.05)',
                        border: isTopMatch ? '1px solid rgba(255, 138, 61, 0.5)' : '1px solid rgba(255, 255, 255, 0.1)',
                        fontFamily: 'var(--font-mono)',
                        fontWeight: 700,
                        fontSize: '1.05rem',
                        color: isTopMatch ? '#ff8a3d' : '#f8fafc',
                        letterSpacing: '0.04em',
                      }}
                    >
                      {match.attack_id}
                    </div>

                    {isTopMatch && (
                      <span
                        className="badge-mono"
                        style={{
                          background: 'rgba(255, 138, 61, 0.18)',
                          color: '#ff8a3d',
                          border: '1px solid rgba(255, 138, 61, 0.45)',
                          fontSize: '0.72rem',
                          fontWeight: 700,
                          boxShadow: '0 0 12px rgba(255, 138, 61, 0.25)',
                        }}
                      >
                        <CheckCircle2 size={13} /> HIGHEST CONVERGENCE MATCH
                      </span>
                    )}
                  </div>

                  {/* Similarity gauge & percentage */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                    <div style={{ textAlign: 'right' }}>
                      <div style={{ fontSize: '0.72rem', color: '#94a3b8', fontWeight: 600, letterSpacing: '0.03em' }}>
                        ALIGNMENT SCORE
                      </div>
                      <div
                        style={{
                          fontSize: '1.5rem',
                          fontWeight: 800,
                          fontFamily: 'var(--font-mono)',
                          color: similarityPercent >= 80 ? '#ff8a3d' : similarityPercent >= 50 ? '#facc15' : '#94a3b8',
                        }}
                      >
                        <AnimatedCounter value={similarityPercent} suffix="%" />
                      </div>
                    </div>

                    <div
                      style={{
                        width: '120px',
                        height: '8px',
                        backgroundColor: 'rgba(255, 255, 255, 0.08)',
                        borderRadius: '4px',
                        overflow: 'hidden',
                      }}
                    >
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${similarityPercent}%` }}
                        transition={{ duration: prefersReduced ? 0 : 0.8, ease: [0.16, 1, 0.3, 1] }}
                        style={{
                          height: '100%',
                          backgroundColor: similarityPercent >= 80 ? '#ff8a3d' : similarityPercent >= 50 ? '#facc15' : '#94a3b8',
                          boxShadow: similarityPercent >= 80 ? '0 0 10px rgba(255, 138, 61, 0.6)' : 'none',
                        }}
                      />
                    </div>
                  </div>
                </div>

                {/* Common techniques */}
                <div style={{ borderTop: '1px solid rgba(255, 255, 255, 0.06)', paddingTop: '14px' }}>
                  <div style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: '10px', fontWeight: 700, letterSpacing: '0.04em' }}>
                    OVERLAPPING TECHNIQUES ({match.common_techniques.length}):
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
                    {match.common_techniques.map((tech) => (
                      <TechniqueTag key={tech} techniqueId={tech} glow={isTopMatch} />
                    ))}
                  </div>
                </div>
              </motion.div>
            );
          })}
        </motion.div>
      )}
    </div>
  );
};

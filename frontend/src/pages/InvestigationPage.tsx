import React, { useState, useEffect } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { useIncident } from '../context/IncidentContext';
import { api } from '../api/client';
import { EvidenceBundle } from '../types/contracts';
import { Terminal, CheckCircle2, Bot, Cpu } from 'lucide-react';

export const InvestigationPage: React.FC = () => {
  const { activeIncidentId } = useIncident();
  const [bundle, setBundle] = useState<EvidenceBundle | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const prefersReduced = useReducedMotion();

  useEffect(() => {
    let isCurrent = true;
    const fetchInvestigation = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await api.getInvestigate(activeIncidentId);
        if (isCurrent) setBundle(data);
      } catch (err: any) {
        if (isCurrent) setError(err.message || 'Failed to load investigation bundle');
      } finally {
        if (isCurrent) setLoading(false);
      }
    };
    fetchInvestigation();
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
    hidden: { opacity: 0, y: prefersReduced ? 0 : 10 },
    visible: {
      opacity: 1,
      y: 0,
      transition: { duration: 0.25, ease: 'easeOut' as const },
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
            <Terminal size={18} color="#ff8a3d" />
          </div>
          <h1 style={{ fontSize: '1.6rem', fontWeight: 800, color: '#f8fafc' }}>
            Multi-Agent Investigation Trace (Agent 2)
          </h1>
        </div>
        <p style={{ color: '#94a3b8', fontSize: '0.875rem' }}>
          Autonomous evidence gathering audit trail and tool invocation sequence for incident <code style={{ color: '#ff8a3d', fontWeight: 700 }}>{activeIncidentId}</code>.
        </p>
      </div>

      {loading ? (
        <div className="glass-panel" style={{ padding: '48px', textAlign: 'center', color: '#94a3b8', fontSize: '0.875rem' }}>
          Retrieving agent evidence bundle and execution trace...
        </div>
      ) : error ? (
        <div className="glass-panel glow-panel-critical" style={{ padding: '20px', color: '#ff6b6b' }}>
          {error}
        </div>
      ) : !bundle ? null : (
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}
        >
          {/* Agent Status KPI Banner */}
          <motion.div
            variants={itemVariants}
            className="glass-panel"
            style={{
              padding: '22px 28px',
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
              gap: '16px',
            }}
          >
            <div>
              <div style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: 700, letterSpacing: '0.04em' }}>AGENT MODEL</div>
              <div style={{ fontSize: '1.05rem', color: '#ff8a3d', fontWeight: 700, marginTop: '6px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Bot size={17} /> {bundle.agent.llm}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: 700, letterSpacing: '0.04em' }}>EXECUTION STATUS</div>
              <div style={{ fontSize: '1.05rem', color: '#34d399', fontWeight: 700, marginTop: '6px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                <CheckCircle2 size={17} /> {bundle.agent.complete ? 'COMPLETE' : 'RUNNING'}
              </div>
            </div>
            <div>
              <div style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: 700, letterSpacing: '0.04em' }}>TOOL INVOCATIONS</div>
              <div style={{ fontSize: '1.3rem', color: '#f8fafc', fontWeight: 800, fontFamily: 'var(--font-mono)', marginTop: '4px' }}>
                {bundle.agent.tool_calls} <span style={{ fontSize: '0.75rem', color: '#64748b', fontWeight: 500 }}>(0 errors)</span>
              </div>
            </div>
            <div>
              <div style={{ fontSize: '0.72rem', color: '#64748b', fontWeight: 700, letterSpacing: '0.04em' }}>STOP REASON</div>
              <div style={{ fontSize: '0.9rem', color: '#cbd5e1', fontFamily: 'var(--font-mono)', marginTop: '6px' }}>
                {bundle.agent.stop_reason}
              </div>
            </div>
          </motion.div>

          {/* Agent Notes */}
          {bundle.agent_notes && (
            <motion.div
              variants={itemVariants}
              className="glass-panel"
              style={{
                padding: '18px 24px',
                borderLeft: '4px solid #ff8a3d',
                background: 'rgba(255, 138, 61, 0.06)',
              }}
            >
              <div style={{ fontSize: '0.75rem', color: '#ff8a3d', fontWeight: 700, marginBottom: '6px', letterSpacing: '0.04em' }}>
                INVESTIGATION SYNTHESIS LOG
              </div>
              <div style={{ color: '#e2e8f0', fontSize: '0.875rem', fontStyle: 'italic', lineHeight: '1.6' }}>
                "{bundle.agent_notes}"
              </div>
            </motion.div>
          )}

          {/* Tool Execution Steps Timeline */}
          <motion.div variants={itemVariants} className="glass-panel" style={{ padding: '24px 28px' }}>
            <h2 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#f8fafc', marginBottom: '20px', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Cpu size={18} color="#ff8a3d" /> Tool Execution Trace
            </h2>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {bundle.steps.map((step, idx) => (
                <div
                  key={idx}
                  style={{
                    padding: '14px 18px',
                    borderRadius: '8px',
                    background: 'rgba(255, 255, 255, 0.02)',
                    border: '1px solid rgba(255, 255, 255, 0.06)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '12px',
                    transition: 'all 0.15s ease',
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.borderColor = 'rgba(255, 138, 61, 0.35)';
                    e.currentTarget.style.backgroundColor = 'rgba(255, 138, 61, 0.04)';
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.06)';
                    e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.02)';
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                    <span
                      className="badge-mono"
                      style={{
                        background: 'rgba(255, 138, 61, 0.15)',
                        border: '1px solid rgba(255, 138, 61, 0.35)',
                        color: '#ff8a3d',
                        fontSize: '0.68rem',
                        fontWeight: 700,
                      }}
                    >
                      STEP {idx + 1}
                    </span>
                    <span className="mono" style={{ color: '#f8fafc', fontWeight: 700, fontSize: '0.85rem' }}>
                      {step.tool}
                    </span>
                    <span style={{ color: '#94a3b8', fontSize: '0.825rem' }}>
                      {step.summary}
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span
                      className="badge-mono"
                      style={{
                        background: step.ok ? 'rgba(16, 185, 129, 0.15)' : 'rgba(255, 77, 77, 0.15)',
                        border: step.ok ? '1px solid rgba(16, 185, 129, 0.4)' : '1px solid rgba(255, 77, 77, 0.4)',
                        color: step.ok ? '#34d399' : '#ff6b6b',
                        fontSize: '0.65rem',
                        fontWeight: 700,
                      }}
                    >
                      {step.ok ? 'SUCCESS' : 'FAILED'}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        </motion.div>
      )}
    </div>
  );
};

import React, { useState, useEffect } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { useIncident } from '../context/IncidentContext';
import { api } from '../api/client';
import { Prediction } from '../types/contracts';
import { TechniqueTag } from '../components/common/TechniqueTag';
import { AnimatedCounter } from '../components/common/AnimatedCounter';
import { TrendingUp, AlertCircle, ShieldAlert, Lightbulb, Zap, Shield } from 'lucide-react';

export const PredictionPage: React.FC = () => {
  const { activeIncidentId } = useIncident();
  const [predictionData, setPredictionData] = useState<Prediction | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const prefersReduced = useReducedMotion();

  useEffect(() => {
    let isCurrent = true;
    const fetchPrediction = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await api.getPredict(activeIncidentId);
        if (isCurrent) setPredictionData(data);
      } catch (err: any) {
        if (isCurrent) setError(err.message || 'Failed to load next-step prediction');
      } finally {
        if (isCurrent) setLoading(false);
      }
    };
    fetchPrediction();
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
            <TrendingUp size={18} color="#ff8a3d" />
          </div>
          <h1 style={{ fontSize: '1.6rem', fontWeight: 800, color: '#f8fafc' }}>
            Next-Step Predictive Analytics (Contract 5)
          </h1>
        </div>
        <p style={{ color: '#94a3b8', fontSize: '0.875rem' }}>
          Probabilistic trajectory forecasting based on temporal Markov order and historical intrusion patterns for <code style={{ color: '#ff8a3d', fontWeight: 700 }}>{activeIncidentId}</code>.
        </p>
      </div>

      {loading ? (
        <div className="glass-panel" style={{ padding: '48px', textAlign: 'center', color: '#94a3b8', fontSize: '0.875rem' }}>
          Simulating forward attack trajectories from knowledge graph history...
        </div>
      ) : error ? (
        <div className="glass-panel glow-panel-critical" style={{ padding: '20px', color: '#ff6b6b' }}>
          {error}
        </div>
      ) : !predictionData ? null : (
        <motion.div
          variants={containerVariants}
          initial="hidden"
          animate="visible"
          style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '24px' }}
        >
          {/* Left: Next Techniques Forecast */}
          <motion.div
            variants={itemVariants}
            className="glass-panel"
            style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: '20px' }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <h2 style={{ fontSize: '1.2rem', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '10px' }}>
                <ShieldAlert size={20} color="#ff8a3d" />
                Predicted Next Technique(s)
              </h2>
              <span className="badge-mono" style={{ background: 'rgba(255, 138, 61, 0.12)', color: '#ff8a3d', border: '1px solid rgba(255, 138, 61, 0.35)' }}>
                <Zap size={11} /> Markov Order 1
              </span>
            </div>

            {predictionData.predictions.length === 0 ? (
              <div
                style={{
                  padding: '28px',
                  backgroundColor: 'rgba(10, 13, 20, 0.7)',
                  borderRadius: '10px',
                  border: '1px solid rgba(255, 255, 255, 0.08)',
                  textAlign: 'center',
                }}
              >
                <AlertCircle size={32} color="#ff8a3d" style={{ margin: '0 auto 12px' }} />
                <div style={{ color: '#f8fafc', fontWeight: 700, fontSize: '1rem', marginBottom: '8px' }}>
                  Terminal Trajectory Detected
                </div>
                <p style={{ color: '#94a3b8', fontSize: '0.825rem', lineHeight: '1.6' }}>
                  No continuation has been observed past the latest step in historical datasets. This typically signifies the final exfiltration or cleanup phase.
                </p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                {predictionData.predictions.map((pred, idx) => {
                  const probPercent = Math.round(pred.probability * 100);
                  const isTopPredicted = idx === 0;
                  const isHighRisk = probPercent >= 75;

                  return (
                    <motion.div
                      key={pred.technique_id}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.1 }}
                      whileHover={prefersReduced ? {} : { y: -2, transition: { duration: 0.15 } }}
                      style={{
                        padding: '20px',
                        borderRadius: '10px',
                        background: isTopPredicted
                          ? isHighRisk
                            ? 'rgba(255, 77, 77, 0.1)'
                            : 'rgba(255, 138, 61, 0.1)'
                          : 'rgba(255, 255, 255, 0.02)',
                        border: isTopPredicted
                          ? isHighRisk
                            ? '1px solid rgba(255, 77, 77, 0.5)'
                            : '1px solid rgba(255, 138, 61, 0.5)'
                          : '1px solid rgba(255, 255, 255, 0.08)',
                        boxShadow: isTopPredicted
                          ? isHighRisk
                            ? '0 0 25px -4px rgba(255, 77, 77, 0.25)'
                            : '0 0 25px -4px rgba(255, 138, 61, 0.2)'
                          : 'none',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '14px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <TechniqueTag techniqueId={pred.technique_id} glow={isTopPredicted} />
                          {isTopPredicted && (
                            <span
                              className="badge-mono"
                              style={{
                                background: isHighRisk ? 'rgba(255, 77, 77, 0.18)' : 'rgba(255, 138, 61, 0.18)',
                                border: isHighRisk ? '1px solid rgba(255, 77, 77, 0.45)' : '1px solid rgba(255, 138, 61, 0.45)',
                                color: isHighRisk ? '#ff6b6b' : '#ff8a3d',
                                fontSize: '0.65rem',
                                fontWeight: 700,
                              }}
                            >
                              MOST LIKELY NEXT
                            </span>
                          )}
                        </div>

                        <div style={{ textAlign: 'right' }}>
                          <span style={{ fontSize: '0.7rem', color: '#94a3b8', display: 'block', fontWeight: 600 }}>LIKELIHOOD</span>
                          <span
                            style={{
                              fontSize: '1.4rem',
                              fontWeight: 800,
                              fontFamily: 'var(--font-mono)',
                              color: isHighRisk ? '#ff4d4d' : '#ff8a3d',
                            }}
                          >
                            <AnimatedCounter value={probPercent} suffix="%" />
                          </span>
                        </div>
                      </div>

                      {/* Animated Progress bar */}
                      <div
                        style={{
                          height: '8px',
                          background: 'rgba(255, 255, 255, 0.08)',
                          borderRadius: '4px',
                          overflow: 'hidden',
                        }}
                      >
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${probPercent}%` }}
                          transition={{ duration: prefersReduced ? 0 : 0.85, ease: [0.16, 1, 0.3, 1] }}
                          style={{
                            height: '100%',
                            background: isHighRisk
                              ? 'linear-gradient(90deg, #ea580c 0%, #ff4d4d 100%)'
                              : 'linear-gradient(90deg, #d97706 0%, #ff8a3d 100%)',
                            boxShadow: isTopPredicted
                              ? isHighRisk
                                ? '0 0 12px rgba(255, 77, 77, 0.8)'
                                : '0 0 12px rgba(255, 138, 61, 0.8)'
                              : 'none',
                          }}
                        />
                      </div>
                    </motion.div>
                  );
                })}
              </div>
            )}
          </motion.div>

          {/* Right: Evidence & Model Rationale */}
          <motion.div
            variants={itemVariants}
            className="glass-panel"
            style={{ padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: '20px' }}
          >
            <h2 style={{ fontSize: '1.2rem', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Lightbulb size={20} color="#ff8a3d" />
              Evidence & Probabilistic Basis
            </h2>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {predictionData.evidence.map((item, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '12px',
                    padding: '14px 16px',
                    borderRadius: '8px',
                    background: 'rgba(255, 255, 255, 0.02)',
                    border: '1px solid rgba(255, 255, 255, 0.06)',
                  }}
                >
                  <span
                    className="badge-mono"
                    style={{
                      background: 'rgba(255, 138, 61, 0.15)',
                      border: '1px solid rgba(255, 138, 61, 0.35)',
                      color: '#ff8a3d',
                      fontSize: '0.68rem',
                      fontWeight: 700,
                      marginTop: '2px',
                    }}
                  >
                    #{idx + 1}
                  </span>
                  <span style={{ color: '#cbd5e1', fontSize: '0.85rem', lineHeight: '1.6' }}>
                    {item}
                  </span>
                </div>
              ))}
            </div>

            <div
              style={{
                marginTop: 'auto',
                padding: '14px 18px',
                borderRadius: '8px',
                background: 'rgba(255, 138, 61, 0.05)',
                border: '1px solid rgba(255, 138, 61, 0.2)',
                fontSize: '0.78rem',
                color: '#94a3b8',
                lineHeight: '1.6',
              }}
            >
              <strong style={{ color: '#ff8a3d' }}>SOC Defensive Recommendation:</strong> Trajectory forecast probabilities evaluate transition frequency ratios across validated intrusion sequences. Preemptively deploy EDR isolation rules for the predicted technique vector.
            </div>
          </motion.div>
        </motion.div>
      )}
    </div>
  );
};

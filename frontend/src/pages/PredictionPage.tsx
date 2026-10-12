import React, { useState, useEffect } from 'react';
import { useIncident } from '../context/IncidentContext';
import { api } from '../api/client';
import { Prediction } from '../types/contracts';
import { TechniqueTag } from '../components/common/TechniqueTag';
import { TrendingUp, AlertCircle, CheckCircle2, ShieldAlert, FileText, ArrowRight, Lightbulb } from 'lucide-react';

export const PredictionPage: React.FC = () => {
  const { activeIncidentId } = useIncident();
  const [predictionData, setPredictionData] = useState<Prediction | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

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

  return (
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Page Title */}
      <div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
          <TrendingUp size={22} color="#38bdf8" />
          <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f8fafc' }}>
            Next-Step Predictive Analytics (Contract 5)
          </h1>
        </div>
        <p style={{ color: '#94a3b8', fontSize: '0.875rem' }}>
          Probabilistic trajectory forecasting based on temporal Markov order and historical intrusion patterns for <code style={{ color: '#38bdf8' }}>{activeIncidentId}</code>.
        </p>
      </div>

      {loading ? (
        <div className="glass-panel" style={{ padding: '40px', textAlign: 'center', color: '#94a3b8' }}>
          Simulating forward attack trajectories from knowledge graph history...
        </div>
      ) : error ? (
        <div className="glass-panel" style={{ padding: '20px', color: '#fb7185', background: 'rgba(244,63,94,0.1)' }}>
          {error}
        </div>
      ) : !predictionData ? null : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '24px' }}>
          {/* Left: Next Techniques Forecast */}
          <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '18px' }}>
            <h2 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldAlert size={18} color="#f59e0b" />
              Predicted Next Technique(s)
            </h2>

            {predictionData.predictions.length === 0 ? (
              <div
                style={{
                  padding: '24px',
                  backgroundColor: 'rgba(15, 23, 42, 0.6)',
                  borderRadius: '10px',
                  border: '1px solid rgba(255, 255, 255, 0.06)',
                  textAlign: 'center',
                }}
              >
                <AlertCircle size={28} color="#38bdf8" style={{ margin: '0 auto 10px' }} />
                <div style={{ color: '#f8fafc', fontWeight: 600, fontSize: '0.95rem', marginBottom: '6px' }}>
                  Terminal Trajectory Detected
                </div>
                <p style={{ color: '#94a3b8', fontSize: '0.8rem', lineHeight: '1.6' }}>
                  No continuation has been observed past the latest step in historical datasets. This typically signifies the final exfiltration or cleanup phase.
                </p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                {predictionData.predictions.map((pred) => {
                  const probPercent = Math.round(pred.probability * 100);
                  return (
                    <div
                      key={pred.technique_id}
                      style={{
                        padding: '18px',
                        borderRadius: '10px',
                        background: 'rgba(239, 68, 68, 0.08)',
                        border: '1px solid rgba(239, 68, 68, 0.3)',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: '12px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <TechniqueTag techniqueId={pred.technique_id} />
                        <div style={{ textAlign: 'right' }}>
                          <span style={{ fontSize: '0.75rem', color: '#94a3b8', display: 'block' }}>Likelihood</span>
                          <span
                            style={{
                              fontSize: '1.3rem',
                              fontWeight: 800,
                              fontFamily: 'var(--font-mono)',
                              color: probPercent >= 75 ? '#f43f5e' : '#f59e0b',
                            }}
                          >
                            {probPercent}%
                          </span>
                        </div>
                      </div>

                      {/* Progress bar */}
                      <div
                        style={{
                          height: '6px',
                          background: 'rgba(255,255,255,0.08)',
                          borderRadius: '3px',
                          overflow: 'hidden',
                        }}
                      >
                        <div
                          style={{
                            height: '100%',
                            width: `${probPercent}%`,
                            background: probPercent >= 75 ? '#f43f5e' : '#f59e0b',
                          }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Right: Evidence & Model Rationale */}
          <div className="glass-panel" style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            <h2 style={{ fontSize: '1.15rem', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Lightbulb size={18} color="#38bdf8" />
              Evidence & Probabilistic Basis
            </h2>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {predictionData.evidence.map((item, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '12px',
                    padding: '12px 14px',
                    borderRadius: '8px',
                    background: 'rgba(255, 255, 255, 0.02)',
                    border: '1px solid rgba(255, 255, 255, 0.05)',
                  }}
                >
                  <span
                    className="badge-mono"
                    style={{
                      background: 'rgba(56, 189, 248, 0.15)',
                      color: '#38bdf8',
                      fontSize: '0.65rem',
                      marginTop: '2px',
                    }}
                  >
                    #{idx + 1}
                  </span>
                  <span style={{ color: '#cbd5e1', fontSize: '0.85rem', lineHeight: '1.5' }}>
                    {item}
                  </span>
                </div>
              ))}
            </div>

            <div
              style={{
                marginTop: 'auto',
                padding: '12px 16px',
                borderRadius: '8px',
                background: 'rgba(56, 189, 248, 0.04)',
                border: '1px solid rgba(56, 189, 248, 0.15)',
                fontSize: '0.75rem',
                color: '#94a3b8',
                lineHeight: '1.5',
              }}
            >
              <strong>Note:</strong> Probabilities reflect ratio counts over known historical sequences with minimum support thresholds. They serve as actionable early-warning alerts for defensive hardening.
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

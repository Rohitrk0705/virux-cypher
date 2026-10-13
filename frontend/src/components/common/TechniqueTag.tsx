import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { api } from '../../api/client';
import { TechniqueInfo } from '../../types/contracts';
import { Info, ExternalLink, ShieldAlert, X } from 'lucide-react';

interface TechniqueTagProps {
  techniqueId: string;
  name?: string;
  clickable?: boolean;
  glow?: boolean;
}

export const TechniqueTag: React.FC<TechniqueTagProps> = ({ techniqueId, name: propName, clickable = true, glow = false }) => {
  const [modalOpen, setModalOpen] = useState(false);
  const [techInfo, setTechInfo] = useState<TechniqueInfo | null>(null);
  const [loading, setLoading] = useState(false);

  const handleClick = async (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!clickable) return;
    setModalOpen(true);
    if (!techInfo) {
      setLoading(true);
      try {
        const info = await api.getTechnique(techniqueId);
        setTechInfo(info);
      } catch (err) {
        console.error('Failed to lookup technique:', err);
      } finally {
        setLoading(false);
      }
    }
  };

  return (
    <>
      <span
        onClick={handleClick}
        className="badge-mono"
        style={{
          cursor: clickable ? 'pointer' : 'default',
          backgroundColor: glow ? 'rgba(255, 138, 61, 0.16)' : 'rgba(255, 255, 255, 0.05)',
          border: glow ? '1px solid rgba(255, 138, 61, 0.5)' : '1px solid rgba(255, 255, 255, 0.12)',
          color: glow ? '#ff8a3d' : '#f1f5f9',
          boxShadow: glow ? '0 0 16px rgba(255, 138, 61, 0.28)' : 'none',
          transition: 'all 0.18s cubic-bezier(0.16, 1, 0.3, 1)',
        }}
        onMouseEnter={(e) => {
          if (clickable) {
            e.currentTarget.style.borderColor = 'rgba(255, 138, 61, 0.6)';
            e.currentTarget.style.color = '#ff8a3d';
            e.currentTarget.style.backgroundColor = 'rgba(255, 138, 61, 0.12)';
          }
        }}
        onMouseLeave={(e) => {
          if (clickable && !glow) {
            e.currentTarget.style.borderColor = 'rgba(255, 255, 255, 0.12)';
            e.currentTarget.style.color = '#f1f5f9';
            e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.05)';
          }
        }}
        title="Click to inspect MITRE ATT&CK technique details"
      >
        <span style={{ fontWeight: 700, letterSpacing: '0.04em' }}>{techniqueId}</span>
        {propName && <span style={{ opacity: 0.8, fontWeight: 400 }}>· {propName}</span>}
        {clickable && <Info size={11} style={{ opacity: 0.6 }} />}
      </span>

      <AnimatePresence>
        {modalOpen && (
          <div
            style={{
              position: 'fixed',
              inset: 0,
              backgroundColor: 'rgba(0, 0, 0, 0.78)',
              backdropFilter: 'blur(8px)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              zIndex: 1000,
            }}
            onClick={() => setModalOpen(false)}
          >
            <motion.div
              initial={{ opacity: 0, scale: 0.95, y: 10 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.95, y: 10 }}
              transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
              className="glass-panel"
              style={{
                width: '90%',
                maxWidth: '540px',
                padding: '26px',
                backgroundColor: 'rgba(15, 20, 32, 0.95)',
                border: '1px solid rgba(255, 138, 61, 0.35)',
                boxShadow: '0 25px 60px rgba(0, 0, 0, 0.8), 0 0 30px rgba(255, 138, 61, 0.12)',
              }}
              onClick={(e) => e.stopPropagation()}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '18px' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                    <span
                      className="badge-mono"
                      style={{
                        background: 'rgba(255, 138, 61, 0.18)',
                        border: '1px solid rgba(255, 138, 61, 0.5)',
                        color: '#ff8a3d',
                        fontSize: '0.85rem',
                        fontWeight: 700,
                      }}
                    >
                      <ShieldAlert size={13} /> {techniqueId}
                    </span>
                    <span
                      className="badge-mono"
                      style={{
                        background: 'rgba(255, 255, 255, 0.05)',
                        border: '1px solid rgba(255, 255, 255, 0.1)',
                        color: '#94a3b8',
                      }}
                    >
                      {techInfo?.tactic || 'ATT&CK TACTIC'}
                    </span>
                  </div>
                  <h3 style={{ fontSize: '1.25rem', color: '#f8fafc', fontWeight: 700, fontFamily: 'var(--font-heading)' }}>
                    {techInfo?.name || propName || techniqueId}
                  </h3>
                </div>
                <button
                  onClick={() => setModalOpen(false)}
                  style={{
                    background: 'rgba(255, 255, 255, 0.05)',
                    border: '1px solid rgba(255, 255, 255, 0.1)',
                    borderRadius: '6px',
                    color: '#94a3b8',
                    padding: '4px',
                    cursor: 'pointer',
                    display: 'flex',
                  }}
                >
                  <X size={16} />
                </button>
              </div>

              {loading ? (
                <div style={{ padding: '28px', textAlign: 'center', color: '#94a3b8', fontSize: '0.875rem' }}>
                  Querying MITRE ATT&CK knowledge base...
                </div>
              ) : (
                <div>
                  <p style={{ color: '#cbd5e1', fontSize: '0.9rem', lineHeight: '1.65', marginBottom: '22px' }}>
                    {techInfo?.description || 'No description found for this technique identifier.'}
                  </p>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid var(--border-subtle)', paddingTop: '16px' }}>
                    <a
                      href={`https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{
                        color: '#ff8a3d',
                        fontSize: '0.825rem',
                        fontWeight: 500,
                        textDecoration: 'none',
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '5px',
                      }}
                    >
                      Official MITRE ATT&CK Documentation <ExternalLink size={12} />
                    </a>
                    <button className="btn-secondary" onClick={() => setModalOpen(false)}>
                      Dismiss
                    </button>
                  </div>
                </div>
              )}
            </motion.div>
          </div>
        )}
      </AnimatePresence>
    </>
  );
};

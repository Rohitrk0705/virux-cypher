import React, { useState } from 'react';
import { api } from '../../api/client';
import { TechniqueInfo } from '../../types/contracts';
import { Info, ExternalLink } from 'lucide-react';

interface TechniqueTagProps {
  techniqueId: string;
  name?: string;
  clickable?: boolean;
}

export const TechniqueTag: React.FC<TechniqueTagProps> = ({ techniqueId, name: propName, clickable = true }) => {
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
          backgroundColor: 'rgba(239, 68, 68, 0.12)',
          border: '1px solid rgba(239, 68, 68, 0.35)',
          color: '#f87171',
          transition: 'all 0.15s ease',
        }}
        title="Click to view MITRE ATT&CK technique details"
      >
        <span style={{ fontWeight: 700 }}>{techniqueId}</span>
        {propName && <span style={{ opacity: 0.85, fontWeight: 400 }}>· {propName}</span>}
        {clickable && <Info size={11} style={{ opacity: 0.6 }} />}
      </span>

      {modalOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            backgroundColor: 'rgba(0, 0, 0, 0.7)',
            backdropFilter: 'blur(4px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
          }}
          onClick={() => setModalOpen(false)}
        >
          <div
            className="glass-panel"
            style={{
              width: '90%',
              maxWidth: '520px',
              padding: '24px',
              backgroundColor: '#0f172a',
              border: '1px solid rgba(56, 189, 248, 0.3)',
              boxShadow: '0 20px 40px rgba(0,0,0,0.6)',
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                  <span
                    className="badge-mono"
                    style={{
                      background: 'rgba(239, 68, 68, 0.2)',
                      border: '1px solid rgba(239, 68, 68, 0.5)',
                      color: '#f87171',
                      fontSize: '0.85rem',
                      fontWeight: 700,
                    }}
                  >
                    {techniqueId}
                  </span>
                  <span
                    className="badge-mono"
                    style={{
                      background: 'rgba(56, 189, 248, 0.15)',
                      border: '1px solid rgba(56, 189, 248, 0.3)',
                      color: '#38bdf8',
                    }}
                  >
                    {techInfo?.tactic || 'ATT&CK Tactic'}
                  </span>
                </div>
                <h3 style={{ fontSize: '1.2rem', color: '#f8fafc', fontWeight: 600 }}>
                  {techInfo?.name || propName || techniqueId}
                </h3>
              </div>
              <button
                onClick={() => setModalOpen(false)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#94a3b8',
                  fontSize: '1.25rem',
                  cursor: 'pointer',
                }}
              >
                ✕
              </button>
            </div>

            {loading ? (
              <div style={{ padding: '24px', textAlign: 'center', color: '#94a3b8' }}>
                Fetching MITRE ATT&CK definition...
              </div>
            ) : (
              <div>
                <p style={{ color: '#cbd5e1', fontSize: '0.9rem', lineHeight: '1.6', marginBottom: '20px' }}>
                  {techInfo?.description || 'No description found.'}
                </p>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '16px' }}>
                  <a
                    href={`https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      color: '#38bdf8',
                      fontSize: '0.825rem',
                      textDecoration: 'none',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: '4px',
                    }}
                  >
                    View on MITRE ATT&CK <ExternalLink size={12} />
                  </a>
                  <button className="btn-secondary" onClick={() => setModalOpen(false)}>
                    Close
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
};

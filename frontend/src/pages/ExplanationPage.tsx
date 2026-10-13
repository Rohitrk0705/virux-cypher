import React, { useState, useEffect } from 'react';
import { motion, useReducedMotion } from 'framer-motion';
import { useIncident } from '../context/IncidentContext';
import { api } from '../api/client';
import { Report } from '../types/contracts';
import { marked } from 'marked';
import { FileText, Copy, Check, Download, Code2, Eye, ShieldCheck } from 'lucide-react';

export const ExplanationPage: React.FC = () => {
  const { activeIncidentId } = useIncident();
  const [reportData, setReportData] = useState<Report | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [viewMode, setViewMode] = useState<'rendered' | 'raw'>('rendered');
  const prefersReduced = useReducedMotion();

  useEffect(() => {
    let isCurrent = true;
    const fetchReport = async () => {
      setLoading(true);
      setError(null);
      try {
        const data = await api.getExplain(activeIncidentId);
        if (isCurrent) setReportData(data);
      } catch (err: any) {
        if (isCurrent) setError(err.message || 'Failed to load analyst report');
      } finally {
        if (isCurrent) setLoading(false);
      }
    };
    fetchReport();
    return () => {
      isCurrent = false;
    };
  }, [activeIncidentId]);

  const handleCopy = () => {
    if (!reportData) return;
    navigator.clipboard.writeText(reportData.report);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    if (!reportData) return;
    const blob = new Blob([reportData.report], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${activeIncidentId}-analyst-report.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const renderedHtml = reportData ? marked.parse(reportData.report) : '';

  return (
    <div style={{ padding: '26px 32px', display: 'flex', flexDirection: 'column', gap: '24px' }}>
      {/* Page Header & Actions */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
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
              <FileText size={18} color="#ff8a3d" />
            </div>
            <h1 style={{ fontSize: '1.6rem', fontWeight: 800, color: '#f8fafc' }}>
              Analyst Executive Brief (Contract 6)
            </h1>
          </div>
          <p style={{ color: '#94a3b8', fontSize: '0.875rem' }}>
            Multi-agent incident synthesis and recommended containment posture for <code style={{ color: '#ff8a3d', fontWeight: 700 }}>{activeIncidentId}</code>.
          </p>
        </div>

        {reportData && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {/* View Mode Switcher */}
            <div style={{ display: 'flex', background: 'rgba(10, 13, 20, 0.8)', borderRadius: '8px', padding: '3px', border: '1px solid rgba(255,255,255,0.08)' }}>
              <button
                onClick={() => setViewMode('rendered')}
                style={{
                  background: viewMode === 'rendered' ? 'rgba(255, 138, 61, 0.2)' : 'transparent',
                  color: viewMode === 'rendered' ? '#ff8a3d' : '#94a3b8',
                  border: 'none',
                  padding: '6px 14px',
                  borderRadius: '6px',
                  fontSize: '0.78rem',
                  fontWeight: 700,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                <Eye size={13} /> Rendered
              </button>
              <button
                onClick={() => setViewMode('raw')}
                style={{
                  background: viewMode === 'raw' ? 'rgba(255, 138, 61, 0.2)' : 'transparent',
                  color: viewMode === 'raw' ? '#ff8a3d' : '#94a3b8',
                  border: 'none',
                  padding: '6px 14px',
                  borderRadius: '6px',
                  fontSize: '0.78rem',
                  fontWeight: 700,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  cursor: 'pointer',
                  transition: 'all 0.15s ease',
                }}
              >
                <Code2 size={13} /> Markdown Source
              </button>
            </div>

            <button className="btn-secondary" onClick={handleCopy} style={{ fontSize: '0.8rem' }}>
              {copied ? <Check size={14} color="#10b981" /> : <Copy size={14} />}
              {copied ? 'Copied' : 'Copy'}
            </button>

            <button className="btn-primary" onClick={handleDownload} style={{ fontSize: '0.8rem' }}>
              <Download size={14} /> Export MD
            </button>
          </div>
        )}
      </div>

      {loading ? (
        <div className="glass-panel" style={{ padding: '48px', textAlign: 'center', color: '#94a3b8', fontSize: '0.875rem' }}>
          Synthesizing multi-agent analyst report from causal evidence...
        </div>
      ) : error ? (
        <div className="glass-panel glow-panel-critical" style={{ padding: '20px', color: '#ff6b6b' }}>
          {error}
        </div>
      ) : !reportData ? null : (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: prefersReduced ? 0 : 0.3 }}
          className="glass-panel"
          style={{ padding: '32px 36px', backgroundColor: 'rgba(14, 18, 28, 0.85)' }}
        >
          {/* Metadata banner */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              paddingBottom: '18px',
              marginBottom: '26px',
              borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
              fontSize: '0.8rem',
              color: '#94a3b8',
              flexWrap: 'wrap',
              gap: '12px',
            }}
          >
            <div style={{ display: 'flex', gap: '18px', flexWrap: 'wrap' }}>
              <span>
                Incident ID: <strong style={{ color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>{reportData.incident_id}</strong>
              </span>
              <span>
                Generator: <strong style={{ color: '#ff8a3d' }}>{reportData.generated_by}</strong>
              </span>
              <span>
                Format: <strong style={{ color: '#cbd5e1' }}>{reportData.format}</strong>
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#34d399', fontWeight: 600 }}>
              <ShieldCheck size={15} /> Verified SOC Artifact
            </div>
          </div>

          {/* Report Body */}
          {viewMode === 'rendered' ? (
            <div
              className="markdown-body"
              dangerouslySetInnerHTML={{ __html: renderedHtml as string }}
            />
          ) : (
            <pre
              style={{
                background: 'rgba(5, 7, 12, 0.95)',
                padding: '24px',
                borderRadius: '8px',
                border: '1px solid rgba(255, 255, 255, 0.08)',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.85rem',
                color: '#cbd5e1',
                lineHeight: '1.65',
                overflowX: 'auto',
                whiteSpace: 'pre-wrap',
              }}
            >
              {reportData.report}
            </pre>
          )}
        </motion.div>
      )}
    </div>
  );
};

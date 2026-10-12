import React, { useState, useEffect } from 'react';
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
    <div style={{ padding: '24px', display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Page Header & Actions */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '16px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '6px' }}>
            <FileText size={22} color="#38bdf8" />
            <h1 style={{ fontSize: '1.5rem', fontWeight: 700, color: '#f8fafc' }}>
              Analyst Investigation Report (Contract 6)
            </h1>
          </div>
          <p style={{ color: '#94a3b8', fontSize: '0.875rem' }}>
            Executive briefing and technical synthesis generated for <code style={{ color: '#38bdf8' }}>{activeIncidentId}</code>.
          </p>
        </div>

        {reportData && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {/* View Mode Switcher */}
            <div style={{ display: 'flex', background: 'rgba(255,255,255,0.05)', borderRadius: '8px', padding: '2px', border: '1px solid rgba(255,255,255,0.08)' }}>
              <button
                onClick={() => setViewMode('rendered')}
                style={{
                  background: viewMode === 'rendered' ? 'rgba(56, 189, 248, 0.2)' : 'transparent',
                  color: viewMode === 'rendered' ? '#38bdf8' : '#94a3b8',
                  border: 'none',
                  padding: '6px 12px',
                  borderRadius: '6px',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <Eye size={13} /> Rendered
              </button>
              <button
                onClick={() => setViewMode('raw')}
                style={{
                  background: viewMode === 'raw' ? 'rgba(56, 189, 248, 0.2)' : 'transparent',
                  color: viewMode === 'raw' ? '#38bdf8' : '#94a3b8',
                  border: 'none',
                  padding: '6px 12px',
                  borderRadius: '6px',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                }}
              >
                <Code2 size={13} /> Raw MD
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
        <div className="glass-panel" style={{ padding: '40px', textAlign: 'center', color: '#94a3b8' }}>
          Synthesizing multi-agent analyst report...
        </div>
      ) : error ? (
        <div className="glass-panel" style={{ padding: '20px', color: '#fb7185', background: 'rgba(244,63,94,0.1)' }}>
          {error}
        </div>
      ) : !reportData ? null : (
        <div className="glass-panel glow-panel" style={{ padding: '32px' }}>
          {/* Metadata banner */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              paddingBottom: '16px',
              marginBottom: '24px',
              borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
              fontSize: '0.8rem',
              color: '#94a3b8',
              flexWrap: 'wrap',
              gap: '12px',
            }}
          >
            <div style={{ display: 'flex', gap: '16px' }}>
              <span>
                Incident ID: <strong style={{ color: '#f8fafc', fontFamily: 'var(--font-mono)' }}>{reportData.incident_id}</strong>
              </span>
              <span>
                Generator: <strong style={{ color: '#38bdf8' }}>{reportData.generated_by}</strong>
              </span>
              <span>
                Format: <strong style={{ color: '#cbd5e1' }}>{reportData.format}</strong>
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: '#10b981' }}>
              <ShieldCheck size={14} /> Verified SOC Artifact
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
                background: '#090d16',
                padding: '20px',
                borderRadius: '8px',
                fontFamily: 'var(--font-mono)',
                fontSize: '0.85rem',
                color: '#cbd5e1',
                lineHeight: '1.6',
                overflowX: 'auto',
                whiteSpace: 'pre-wrap',
              }}
            >
              {reportData.report}
            </pre>
          )}
        </div>
      )}
    </div>
  );
};

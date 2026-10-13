import React from 'react';
import {
  LayoutDashboard,
  Activity,
  Share2,
  History,
  TrendingUp,
  FileText,
  Terminal,
} from 'lucide-react';

export type PageTab = 'overview' | 'incident' | 'graph' | 'historical' | 'prediction' | 'explanation' | 'investigation';

interface SidebarProps {
  currentTab: PageTab;
  onSelectTab: (tab: PageTab) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab }) => {
  const navItems: { id: PageTab; label: string; icon: React.FC<{ size?: number; color?: string }>; badge?: string }[] = [
    { id: 'overview', label: 'Threat Overview', icon: LayoutDashboard },
    { id: 'incident', label: 'Attack Trajectory', icon: Activity },
    { id: 'graph', label: 'Knowledge Graph', icon: Share2 },
    { id: 'historical', label: 'Campaign Matches', icon: History },
    { id: 'prediction', label: 'Predictive Threat', icon: TrendingUp },
    { id: 'explanation', label: 'Analyst Brief', icon: FileText },
    { id: 'investigation', label: 'Agent Audit Trace', icon: Terminal, badge: 'Agent' },
  ];

  return (
    <aside
      style={{
        width: '230px',
        backgroundColor: 'rgba(10, 13, 20, 0.95)',
        borderRight: '1px solid rgba(255, 255, 255, 0.08)',
        display: 'flex',
        flexDirection: 'column',
        padding: '16px 10px',
        gap: '4px',
        flexShrink: 0,
        zIndex: 20,
      }}
    >
      <div
        style={{
          padding: '6px 12px 12px',
          fontSize: '0.68rem',
          fontWeight: 700,
          color: '#64748b',
          letterSpacing: '0.08em',
          textTransform: 'uppercase',
          fontFamily: 'var(--font-heading)',
        }}
      >
        SOC Workspaces
      </div>

      {navItems.map((item) => {
        const Icon = item.icon;
        const isActive = currentTab === item.id;
        return (
          <button
            key={item.id}
            onClick={() => onSelectTab(item.id)}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              padding: '9px 12px',
              borderRadius: '8px',
              border: isActive ? '1px solid rgba(255, 138, 61, 0.4)' : '1px solid transparent',
              backgroundColor: isActive ? 'rgba(255, 138, 61, 0.12)' : 'transparent',
              color: isActive ? '#ff8a3d' : '#94a3b8',
              boxShadow: isActive ? '0 0 14px rgba(255, 138, 61, 0.12)' : 'none',
              textAlign: 'left',
              transition: 'all 0.18s cubic-bezier(0.16, 1, 0.3, 1)',
              outline: 'none',
              cursor: 'pointer',
              fontWeight: isActive ? 600 : 500,
              fontSize: '0.825rem',
              position: 'relative',
            }}
            onMouseEnter={(e) => {
              if (!isActive) {
                e.currentTarget.style.backgroundColor = 'rgba(255, 255, 255, 0.04)';
                e.currentTarget.style.color = '#f1f5f9';
              }
            }}
            onMouseLeave={(e) => {
              if (!isActive) {
                e.currentTarget.style.backgroundColor = 'transparent';
                e.currentTarget.style.color = '#94a3b8';
              }
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <Icon size={16} color={isActive ? '#ff8a3d' : '#64748b'} />
              <span>{item.label}</span>
            </div>
            {item.badge && (
              <span
                className="badge-mono"
                style={{
                  fontSize: '0.625rem',
                  padding: '1px 6px',
                  background: 'rgba(255, 138, 61, 0.15)',
                  border: '1px solid rgba(255, 138, 61, 0.4)',
                  color: '#ff8a3d',
                }}
              >
                {item.badge}
              </span>
            )}
          </button>
        );
      })}

      <div style={{ marginTop: 'auto', padding: '16px 6px 4px' }}>
        <div
          className="glass-panel"
          style={{
            padding: '12px 14px',
            backgroundColor: 'rgba(15, 20, 32, 0.7)',
            border: '1px solid rgba(255, 255, 255, 0.06)',
            fontSize: '0.75rem',
          }}
        >
          <div style={{ color: '#94a3b8', marginBottom: '4px', fontWeight: 600, fontSize: '0.7rem' }}>
            GRAPH TELEMETRY
          </div>
          <div style={{ color: '#f1f5f9', display: 'flex', alignItems: 'center', gap: '6px', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
            <span className="pulse-dot-emerald" style={{ width: '6px', height: '6px' }} />
            Neo4j Bolt: 7687
          </div>
          <div style={{ color: '#64748b', fontSize: '0.68rem', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
            Temporal Cypher v19.2
          </div>
        </div>
      </div>
    </aside>
  );
};

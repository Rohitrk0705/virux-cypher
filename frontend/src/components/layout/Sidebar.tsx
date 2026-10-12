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
    { id: 'overview', label: 'Incidents Overview', icon: LayoutDashboard },
    { id: 'incident', label: 'Attack Trajectory', icon: Activity },
    { id: 'graph', label: 'Knowledge Graph', icon: Share2 },
    { id: 'historical', label: 'Historical Matches', icon: History },
    { id: 'prediction', label: 'Predictive Threat', icon: TrendingUp },
    { id: 'explanation', label: 'Analyst Report', icon: FileText },
    { id: 'investigation', label: 'Agent Investigation', icon: Terminal, badge: 'Agent' },
  ];

  return (
    <aside
      style={{
        width: '240px',
        backgroundColor: 'rgba(11, 15, 25, 0.95)',
        borderRight: '1px solid rgba(255, 255, 255, 0.07)',
        display: 'flex',
        flexDirection: 'column',
        padding: '16px 12px',
        gap: '4px',
        flexShrink: 0,
      }}
    >
      <div style={{ padding: '4px 12px 12px', fontSize: '0.7rem', fontWeight: 600, color: '#64748b', letterSpacing: '0.05em' }}>
        ANALYST WORKSPACES
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
              padding: '10px 14px',
              borderRadius: '8px',
              border: isActive ? '1px solid rgba(56, 189, 248, 0.35)' : '1px solid transparent',
              backgroundColor: isActive ? 'rgba(56, 189, 248, 0.12)' : 'transparent',
              color: isActive ? '#38bdf8' : '#94a3b8',
              textAlign: 'left',
              transition: 'all 0.15s ease',
              outline: 'none',
              cursor: 'pointer',
              fontWeight: isActive ? 600 : 500,
              fontSize: '0.85rem',
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
              <Icon size={16} color={isActive ? '#38bdf8' : '#64748b'} />
              <span>{item.label}</span>
            </div>
            {item.badge && (
              <span
                className="badge-mono"
                style={{
                  fontSize: '0.625rem',
                  padding: '1px 6px',
                  background: 'rgba(168, 85, 247, 0.15)',
                  border: '1px solid rgba(168, 85, 247, 0.4)',
                  color: '#c084fc',
                }}
              >
                {item.badge}
              </span>
            )}
          </button>
        );
      })}

      <div style={{ marginTop: 'auto', padding: '16px 12px 4px' }}>
        <div
          className="glass-panel"
          style={{
            padding: '12px',
            backgroundColor: 'rgba(15, 23, 42, 0.6)',
            border: '1px solid rgba(255, 255, 255, 0.05)',
            fontSize: '0.75rem',
          }}
        >
          <div style={{ color: '#94a3b8', marginBottom: '4px', fontWeight: 600 }}>Active Graph DB</div>
          <div style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#10b981' }} />
            Neo4j Bolt :7687
          </div>
          <div style={{ color: '#64748b', fontSize: '0.7rem', marginTop: '4px' }}>
            Cypher Schema v19.2
          </div>
        </div>
      </div>
    </aside>
  );
};

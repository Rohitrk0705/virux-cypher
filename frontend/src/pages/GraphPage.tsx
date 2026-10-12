import React, { useEffect, useRef, useState } from 'react';
import cytoscape, { Core, EventObject } from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { useIncident } from '../context/IncidentContext';
import { api } from '../api/client';
import { IncidentGraph, GraphNode, GraphEdge, GraphNodeType } from '../types/contracts';
import {
  Share2,
  ZoomIn,
  ZoomOut,
  Maximize2,
  RefreshCw,
  Sliders,
  Info,
  CheckSquare,
  Square,
  Search,
} from 'lucide-react';

cytoscape.use(dagre);

const NODE_COLORS: Record<GraphNodeType, string> = {
  user: '#3b82f6',
  device: '#a855f7',
  ip: '#06b6d4',
  process: '#f59e0b',
  technique: '#ef4444',
  tactic: '#ec4899',
  event: '#64748b',
};

export const GraphPage: React.FC = () => {
  const { activeIncidentId } = useIncident();
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<Core | null>(null);

  const [graphData, setGraphData] = useState<IncidentGraph | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedElement, setSelectedElement] = useState<any | null>(null);
  const [layoutName, setLayoutName] = useState<'cose' | 'dagre' | 'concentric' | 'breadthfirst'>('cose');
  const [searchQuery, setSearchQuery] = useState('');

  // Node type visibility filters
  const [visibleTypes, setVisibleTypes] = useState<Record<GraphNodeType, boolean>>({
    user: true,
    device: true,
    ip: true,
    process: true,
    technique: true,
    tactic: true,
    event: true,
  });

  // Fetch graph data
  useEffect(() => {
    let isCurrent = true;
    const fetchGraph = async () => {
      setLoading(true);
      setError(null);
      setSelectedElement(null);
      try {
        const data = await api.getGraph(activeIncidentId);
        if (isCurrent) setGraphData(data);
      } catch (err: any) {
        if (isCurrent) setError(err.message || 'Failed to load graph data');
      } finally {
        if (isCurrent) setLoading(false);
      }
    };
    fetchGraph();
    return () => {
      isCurrent = false;
    };
  }, [activeIncidentId]);

  // Initialize & update Cytoscape
  useEffect(() => {
    if (!containerRef.current || !graphData) return;

    // Filter nodes by visible types
    const filteredNodes = graphData.nodes.filter((n) => visibleTypes[n.type]);
    const validNodeIds = new Set(filteredNodes.map((n) => n.id));
    const filteredEdges = graphData.edges.filter(
      (e) => validNodeIds.has(e.source) && validNodeIds.has(e.target)
    );

    const elements = [
      ...filteredNodes.map((node) => ({
        data: {
          id: node.id,
          label: node.label,
          type: node.type,
          nodeColor: NODE_COLORS[node.type] || '#94a3b8',
          raw: node,
        },
      })),
      ...filteredEdges.map((edge, idx) => ({
        data: {
          id: `edge-${idx}`,
          source: edge.source,
          target: edge.target,
          label: edge.type,
          type: edge.type,
          raw: edge,
        },
      })),
    ];

    if (cyRef.current) {
      cyRef.current.destroy();
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(nodeColor)',
            label: 'data(label)',
            color: '#f8fafc',
            'font-family': 'Inter, sans-serif',
            'font-size': '11px',
            'font-weight': 600,
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'text-background-color': 'rgba(11, 15, 25, 0.85)',
            'text-background-opacity': 0.85,
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            width: 32,
            height: 32,
            'border-width': 2,
            'border-color': 'rgba(255, 255, 255, 0.25)',
          },
        },
        {
          selector: 'node[type = "technique"]',
          style: {
            shape: 'diamond',
            width: 38,
            height: 38,
            'border-width': 2.5,
            'border-color': '#f87171',
          },
        },
        {
          selector: 'node[type = "event"]',
          style: {
            width: 22,
            height: 22,
            'font-size': '9px',
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': 4,
            'border-color': '#38bdf8',
            'background-blacken': 0.1,
          },
        },
        {
          selector: 'edge',
          style: {
            width: 1.8,
            'line-color': 'rgba(148, 163, 184, 0.35)',
            'target-arrow-color': 'rgba(148, 163, 184, 0.6)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.8,
            label: 'data(label)',
            'font-size': '8px',
            'font-family': 'JetBrains Mono, monospace',
            color: '#94a3b8',
            'text-rotation': 'autorotate',
            'text-background-color': 'rgba(11, 15, 25, 0.9)',
            'text-background-opacity': 0.9,
            'text-background-padding': '2px',
          },
        },
        {
          selector: 'edge[type = "NEXT"]',
          style: {
            width: 2.5,
            'line-color': '#38bdf8',
            'target-arrow-color': '#38bdf8',
            'line-style': 'dashed',
          },
        },
        {
          selector: 'edge[type = "MAPS_TO"]',
          style: {
            width: 2,
            'line-color': '#f43f5e',
            'target-arrow-color': '#f43f5e',
          },
        },
        {
          selector: 'edge:selected',
          style: {
            width: 3,
            'line-color': '#38bdf8',
            'target-arrow-color': '#38bdf8',
          },
        },
      ],
      layout: {
        name: layoutName,
        padding: 40,
        animate: false,
        ...(layoutName === 'dagre' ? { rankDir: 'LR', nodeSep: 50, rankSep: 70 } : {}),
      },
    });

    cy.on('tap', 'node, edge', (evt: EventObject) => {
      const target = evt.target;
      setSelectedElement({
        isNode: target.isNode(),
        data: target.data(),
        raw: target.data('raw'),
      });
    });

    cy.on('tap', (evt: EventObject) => {
      if (evt.target === cy) {
        setSelectedElement(null);
      }
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graphData, visibleTypes, layoutName]);

  // Handle Search highlight
  useEffect(() => {
    if (!cyRef.current || !searchQuery.trim()) {
      cyRef.current?.nodes().removeClass('highlighted');
      return;
    }
    const query = searchQuery.toLowerCase();
    const cy = cyRef.current;
    cy.nodes().forEach((n) => {
      const label = n.data('label')?.toLowerCase() || '';
      const id = n.data('id')?.toLowerCase() || '';
      if (label.includes(query) || id.includes(query)) {
        n.select();
      } else {
        n.unselect();
      }
    });
  }, [searchQuery]);

  const toggleType = (t: GraphNodeType) => {
    setVisibleTypes((prev) => ({ ...prev, [t]: !prev[t] }));
  };

  const resetView = () => {
    cyRef.current?.fit(undefined, 40);
  };

  const zoomIn = () => {
    if (cyRef.current) cyRef.current.zoom(cyRef.current.zoom() * 1.25);
  };

  const zoomOut = () => {
    if (cyRef.current) cyRef.current.zoom(cyRef.current.zoom() * 0.8);
  };

  return (
    <div style={{ height: 'calc(100vh - 65px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Subheader Toolbar */}
      <div
        style={{
          padding: '12px 24px',
          background: 'rgba(13, 18, 29, 0.9)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.07)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px',
          zIndex: 10,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <Share2 size={18} color="#38bdf8" />
          <h2 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc' }}>
            Threat Knowledge Graph — {activeIncidentId}
          </h2>
          {graphData && (
            <span className="badge-mono" style={{ background: 'rgba(56, 189, 248, 0.12)', color: '#38bdf8' }}>
              {graphData.nodes.length} nodes · {graphData.edges.length} edges
            </span>
          )}
        </div>

        {/* Controls: Layout switcher, Search, Zoom */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          {/* Node Search */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              background: 'rgba(0,0,0,0.4)',
              border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: '6px',
              padding: '4px 8px',
            }}
          >
            <Search size={13} color="#64748b" />
            <input
              type="text"
              placeholder="Search graph node..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#f8fafc',
                fontSize: '0.75rem',
                outline: 'none',
                width: '130px',
              }}
            />
          </div>

          {/* Layout Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Sliders size={14} color="#94a3b8" />
            <select
              value={layoutName}
              onChange={(e) => setLayoutName(e.target.value as any)}
              style={{
                background: 'var(--bg-secondary)',
                color: '#cbd5e1',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '6px',
                padding: '4px 8px',
                fontSize: '0.75rem',
                outline: 'none',
              }}
            >
              <option value="cose">Force-Directed (CoSE)</option>
              <option value="dagre">Hierarchical DAG (Dagre)</option>
              <option value="concentric">Concentric Circles</option>
              <option value="breadthfirst">Breadth-First Tree</option>
            </select>
          </div>

          {/* Zoom Buttons */}
          <div style={{ display: 'flex', gap: '4px' }}>
            <button className="btn-secondary" onClick={zoomIn} style={{ padding: '5px 8px' }} title="Zoom In">
              <ZoomIn size={14} />
            </button>
            <button className="btn-secondary" onClick={zoomOut} style={{ padding: '5px 8px' }} title="Zoom Out">
              <ZoomOut size={14} />
            </button>
            <button className="btn-secondary" onClick={resetView} style={{ padding: '5px 8px' }} title="Fit View">
              <Maximize2 size={14} />
            </button>
          </div>
        </div>
      </div>

      {/* Main Canvas Area + Side Inspector */}
      <div style={{ flex: 1, display: 'flex', position: 'relative', overflow: 'hidden' }}>
        {/* Cytoscape Canvas */}
        <div
          ref={containerRef}
          style={{
            flex: 1,
            width: '100%',
            height: '100%',
            backgroundColor: '#07090e',
            backgroundImage:
              'radial-gradient(circle at center, rgba(56, 189, 248, 0.04) 0%, transparent 70%), linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px)',
            backgroundSize: '100% 100%, 30px 30px, 30px 30px',
          }}
        />

        {/* Floating Legend / Filter Overlay */}
        <div
          className="glass-panel"
          style={{
            position: 'absolute',
            bottom: '20px',
            left: '20px',
            padding: '12px 16px',
            zIndex: 10,
            maxWidth: '320px',
            boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
          }}
        >
          <div style={{ fontSize: '0.72rem', color: '#94a3b8', fontWeight: 700, marginBottom: '8px', letterSpacing: '0.05em' }}>
            NODE TYPE FILTERS
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: '6px' }}>
            {(Object.keys(NODE_COLORS) as GraphNodeType[]).map((type) => {
              const isVis = visibleTypes[type];
              return (
                <div
                  key={type}
                  onClick={() => toggleType(type)}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    cursor: 'pointer',
                    fontSize: '0.72rem',
                    color: isVis ? '#f1f5f9' : '#64748b',
                    padding: '3px 6px',
                    borderRadius: '4px',
                    background: isVis ? 'rgba(255, 255, 255, 0.04)' : 'transparent',
                  }}
                >
                  <span
                    style={{
                      width: '10px',
                      height: '10px',
                      borderRadius: type === 'technique' ? '2px' : '50%',
                      transform: type === 'technique' ? 'rotate(45deg)' : 'none',
                      backgroundColor: isVis ? NODE_COLORS[type] : '#475569',
                      display: 'inline-block',
                      flexShrink: 0,
                    }}
                  />
                  <span style={{ textTransform: 'capitalize', fontWeight: 500 }}>{type}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Node & Edge Inspector Side Drawer */}
        {selectedElement && (
          <div
            className="glass-panel"
            style={{
              width: '340px',
              position: 'absolute',
              top: '20px',
              right: '20px',
              bottom: '20px',
              padding: '20px',
              zIndex: 20,
              display: 'flex',
              flexDirection: 'column',
              boxShadow: '0 12px 40px rgba(0,0,0,0.7)',
              backgroundColor: 'rgba(15, 23, 42, 0.95)',
              overflowY: 'auto',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <Info size={16} color="#38bdf8" />
                <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: '#f8fafc' }}>
                  {selectedElement.isNode ? 'Node Details' : 'Edge Relationship'}
                </h3>
              </div>
              <button
                onClick={() => setSelectedElement(null)}
                style={{ background: 'none', border: 'none', color: '#94a3b8', fontSize: '1rem', cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>

            {selectedElement.isNode ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div>
                  <span
                    className="badge-mono"
                    style={{
                      background: `${NODE_COLORS[selectedElement.data.type as GraphNodeType] || '#38bdf8'}22`,
                      color: NODE_COLORS[selectedElement.data.type as GraphNodeType] || '#38bdf8',
                      border: `1px solid ${NODE_COLORS[selectedElement.data.type as GraphNodeType] || '#38bdf8'}66`,
                      textTransform: 'uppercase',
                      fontWeight: 700,
                    }}
                  >
                    {selectedElement.data.type}
                  </span>
                  <div
                    style={{
                      fontSize: '1.2rem',
                      fontWeight: 700,
                      color: '#f8fafc',
                      marginTop: '8px',
                      fontFamily: 'var(--font-mono)',
                    }}
                  >
                    {selectedElement.data.label}
                  </div>
                </div>

                <div style={{ borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '12px' }}>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '8px', fontWeight: 600 }}>
                    RAW ATTRIBUTES
                  </div>
                  <pre
                    style={{
                      background: '#090d16',
                      padding: '12px',
                      borderRadius: '8px',
                      fontSize: '0.72rem',
                      fontFamily: 'var(--font-mono)',
                      color: '#cbd5e1',
                      overflowX: 'auto',
                    }}
                  >
                    {JSON.stringify(selectedElement.raw, null, 2)}
                  </pre>
                </div>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                <div>
                  <span
                    className="badge-mono"
                    style={{
                      background: 'rgba(56, 189, 248, 0.15)',
                      color: '#38bdf8',
                      border: '1px solid rgba(56, 189, 248, 0.4)',
                      fontWeight: 700,
                    }}
                  >
                    {selectedElement.data.type}
                  </span>
                  <div style={{ marginTop: '12px', fontSize: '0.85rem', color: '#cbd5e1' }}>
                    <div style={{ marginBottom: '6px' }}>
                      <span style={{ color: '#64748b' }}>From:</span>{' '}
                      <code style={{ color: '#f8fafc' }}>{selectedElement.data.source}</code>
                    </div>
                    <div>
                      <span style={{ color: '#64748b' }}>To:</span>{' '}
                      <code style={{ color: '#f8fafc' }}>{selectedElement.data.target}</code>
                    </div>
                  </div>
                </div>

                <div style={{ borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '12px' }}>
                  <div style={{ fontSize: '0.75rem', color: '#94a3b8', marginBottom: '8px', fontWeight: 600 }}>
                    EDGE METADATA
                  </div>
                  <pre
                    style={{
                      background: '#090d16',
                      padding: '12px',
                      borderRadius: '8px',
                      fontSize: '0.72rem',
                      fontFamily: 'var(--font-mono)',
                      color: '#cbd5e1',
                      overflowX: 'auto',
                    }}
                  >
                    {JSON.stringify(selectedElement.raw, null, 2)}
                  </pre>
                </div>
              </div>
            )}
          </div>
        )}

        {loading && (
          <div
            style={{
              position: 'absolute',
              inset: 0,
              background: 'rgba(7, 9, 14, 0.75)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#38bdf8',
              fontSize: '0.9rem',
              fontWeight: 600,
              zIndex: 30,
            }}
          >
            Building interactive knowledge graph...
          </div>
        )}
      </div>
    </div>
  );
};

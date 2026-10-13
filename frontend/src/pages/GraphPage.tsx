import React, { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import cytoscape, { Core, EventObject } from 'cytoscape';
import dagre from 'cytoscape-dagre';
import { useIncident } from '../context/IncidentContext';
import { api } from '../api/client';
import { IncidentGraph, GraphNodeType } from '../types/contracts';
import {
  Share2,
  ZoomIn,
  ZoomOut,
  Maximize2,
  Sliders,
  Info,
  Search,
  X,
  Compass,
} from 'lucide-react';

cytoscape.use(dagre);

const NODE_COLORS: Record<GraphNodeType, string> = {
  technique: '#ff4d4d', // Reserved Red for high threat MITRE techniques
  tactic: '#ff8a3d',    // Amber for ATT&CK Tactics
  process: '#facc15',   // Amber-Gold for Process execution
  user: '#38bdf8',      // Slate-Cyan for Identity
  device: '#94a3b8',    // Cool Slate for Host Device
  ip: '#06b6d4',        // Cyan for Network IPs
  event: '#64748b',     // Dark Slate for Normalized Log Events
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
            'font-family': 'Space Grotesk, sans-serif',
            'font-size': '11px',
            'font-weight': 600,
            'text-valign': 'bottom',
            'text-margin-y': 7,
            'text-background-color': 'rgba(10, 13, 20, 0.9)',
            'text-background-opacity': 0.9,
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            width: 32,
            height: 32,
            'border-width': 2,
            'border-color': 'rgba(255, 255, 255, 0.2)',
            'transition-property': 'opacity, border-color, border-width, width, height',
            'transition-duration': 200,
          },
        },
        {
          selector: 'node[type = "technique"]',
          style: {
            shape: 'diamond',
            width: 40,
            height: 40,
            'border-width': 3,
            'border-color': '#ff4d4d',
            'text-background-color': 'rgba(255, 77, 77, 0.15)',
            'text-background-opacity': 1,
            color: '#ff6b6b',
            'font-weight': 700,
          },
        },
        {
          selector: 'node[type = "tactic"]',
          style: {
            shape: 'hexagon',
            width: 36,
            height: 36,
            'border-width': 2.5,
            'border-color': '#ff8a3d',
            color: '#ff9c5a',
          },
        },
        {
          selector: 'node[type = "event"]',
          style: {
            width: 22,
            height: 22,
            'font-size': '9px',
            'border-width': 1.5,
          },
        },
        {
          selector: 'node:selected',
          style: {
            'border-width': 4,
            'border-color': '#ff8a3d',
            'background-blacken': 0.1,
          },
        },
        {
          selector: 'edge',
          style: {
            width: 1.8,
            'line-color': 'rgba(148, 163, 184, 0.35)',
            'target-arrow-color': 'rgba(148, 163, 184, 0.65)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            'arrow-scale': 0.8,
            label: 'data(label)',
            'font-size': '8px',
            'font-family': 'JetBrains Mono, monospace',
            color: '#94a3b8',
            'text-rotation': 'autorotate',
            'text-background-color': 'rgba(10, 13, 20, 0.9)',
            'text-background-opacity': 0.9,
            'text-background-padding': '2px',
            'transition-property': 'opacity, line-color, width',
            'transition-duration': 200,
          },
        },
        {
          selector: 'edge[type = "NEXT"]',
          style: {
            width: 2.5,
            'line-color': '#ff8a3d',
            'target-arrow-color': '#ff8a3d',
            'line-style': 'dashed',
          },
        },
        {
          selector: 'edge[type = "MAPS_TO"]',
          style: {
            width: 2.2,
            'line-color': '#ff4d4d',
            'target-arrow-color': '#ff4d4d',
          },
        },
        {
          selector: 'edge:selected',
          style: {
            width: 3.5,
            'line-color': '#ff8a3d',
            'target-arrow-color': '#ff8a3d',
          },
        },
        /* Dimming & Highlighting on hover */
        {
          selector: '.dimmed',
          style: {
            opacity: 0.12,
          },
        },
        {
          selector: '.highlighted',
          style: {
            opacity: 1,
            'border-width': 3.5,
            'border-color': '#ff8a3d',
            'z-index': 999,
          },
        },
        {
          selector: 'edge.highlighted',
          style: {
            opacity: 1,
            width: 2.8,
            'line-color': '#ff8a3d',
            'target-arrow-color': '#ff8a3d',
            'z-index': 998,
          },
        },
      ],
      layout: {
        name: layoutName,
        padding: 50,
        animate: true,
        animationDuration: 650,
        animationEasing: 'ease-out-cubic',
        ...(layoutName === 'dagre' ? { rankDir: 'LR', nodeSep: 55, rankSep: 75 } : {}),
      },
    });

    // Hover interactions: highlight connected neighborhood and dim others
    cy.on('mouseover', 'node', (evt: EventObject) => {
      const node = evt.target;
      const neighborhood = node.closedNeighborhood();
      cy.elements().difference(neighborhood).addClass('dimmed');
      neighborhood.addClass('highlighted');
    });

    cy.on('mouseout', 'node', () => {
      cy.elements().removeClass('dimmed').removeClass('highlighted');
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
    cyRef.current?.animate({
      fit: { eles: cyRef.current.elements(), padding: 50 },
      duration: 500,
      easing: 'ease-out-cubic',
    });
  };

  const zoomIn = () => {
    if (!cyRef.current) return;
    const cy = cyRef.current;
    cy.animate({
      zoom: cy.zoom() * 1.3,
      duration: 250,
      easing: 'ease-out-cubic',
    });
  };

  const zoomOut = () => {
    if (!cyRef.current) return;
    const cy = cyRef.current;
    cy.animate({
      zoom: cy.zoom() * 0.77,
      duration: 250,
      easing: 'ease-out-cubic',
    });
  };

  return (
    <div style={{ height: 'calc(100vh - 65px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Subheader Toolbar */}
      <div
        style={{
          padding: '12px 24px',
          background: 'rgba(10, 13, 20, 0.94)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '12px',
          zIndex: 10,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div
            style={{
              width: '28px',
              height: '28px',
              borderRadius: '6px',
              background: 'rgba(255, 138, 61, 0.15)',
              border: '1px solid rgba(255, 138, 61, 0.4)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Share2 size={16} color="#ff8a3d" />
          </div>
          <div>
            <h2 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', fontFamily: 'var(--font-heading)' }}>
              Temporal Knowledge Graph — {activeIncidentId}
            </h2>
          </div>
          {graphData && (
            <span className="badge-mono" style={{ background: 'rgba(255, 138, 61, 0.12)', color: '#ff8a3d', border: '1px solid rgba(255, 138, 61, 0.3)' }}>
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
              background: 'rgba(15, 20, 32, 0.85)',
              border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: '6px',
              padding: '5px 10px',
            }}
          >
            <Search size={13} color="#ff8a3d" />
            <input
              type="text"
              placeholder="Search node..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              style={{
                background: 'transparent',
                border: 'none',
                color: '#f8fafc',
                fontSize: '0.78rem',
                outline: 'none',
                width: '130px',
                fontFamily: 'var(--font-mono)',
              }}
            />
          </div>

          {/* Layout Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Sliders size={13} color="#94a3b8" />
            <select
              value={layoutName}
              onChange={(e) => setLayoutName(e.target.value as any)}
              style={{
                background: 'rgba(15, 20, 32, 0.85)',
                color: '#cbd5e1',
                border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: '6px',
                padding: '5px 10px',
                fontSize: '0.78rem',
                outline: 'none',
                fontFamily: 'var(--font-heading)',
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
            <button className="btn-secondary" onClick={zoomIn} style={{ padding: '6px 8px' }} title="Zoom In">
              <ZoomIn size={14} />
            </button>
            <button className="btn-secondary" onClick={zoomOut} style={{ padding: '6px 8px' }} title="Zoom Out">
              <ZoomOut size={14} />
            </button>
            <button className="btn-secondary" onClick={resetView} style={{ padding: '6px 8px' }} title="Fit View">
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
              'radial-gradient(circle at center, rgba(255, 138, 61, 0.03) 0%, transparent 70%), linear-gradient(rgba(255, 255, 255, 0.015) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.015) 1px, transparent 1px)',
            backgroundSize: '100% 100%, 36px 36px, 36px 36px',
          }}
        />

        {/* Floating Legend / Filter Overlay */}
        <div
          className="glass-panel"
          style={{
            position: 'absolute',
            bottom: '24px',
            left: '24px',
            padding: '14px 18px',
            zIndex: 10,
            maxWidth: '340px',
            boxShadow: '0 12px 35px rgba(0,0,0,0.7)',
          }}
        >
          <div style={{ fontSize: '0.72rem', color: '#ff8a3d', fontWeight: 700, marginBottom: '8px', letterSpacing: '0.05em', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Compass size={12} /> ENTITY FILTERS & LEGEND
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
                    gap: '8px',
                    cursor: 'pointer',
                    fontSize: '0.74rem',
                    color: isVis ? '#f1f5f9' : '#64748b',
                    padding: '4px 8px',
                    borderRadius: '6px',
                    background: isVis ? 'rgba(255, 255, 255, 0.04)' : 'transparent',
                    border: isVis ? '1px solid rgba(255, 255, 255, 0.06)' : '1px solid transparent',
                    transition: 'all 0.15s ease',
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
                      boxShadow: isVis && type === 'technique' ? '0 0 8px #ff4d4d' : 'none',
                    }}
                  />
                  <span style={{ textTransform: 'capitalize', fontWeight: 600 }}>{type}</span>
                </div>
              );
            })}
          </div>
        </div>

        {/* Node & Edge Inspector Side Drawer */}
        <AnimatePresence>
          {selectedElement && (
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: 20 }}
              transition={{ duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
              className="glass-panel"
              style={{
                width: '360px',
                position: 'absolute',
                top: '20px',
                right: '24px',
                bottom: '24px',
                padding: '22px',
                zIndex: 20,
                display: 'flex',
                flexDirection: 'column',
                boxShadow: '0 16px 50px rgba(0,0,0,0.8), 0 0 25px rgba(255, 138, 61, 0.1)',
                backgroundColor: 'rgba(12, 16, 26, 0.96)',
                border: '1px solid rgba(255, 138, 61, 0.3)',
                overflowY: 'auto',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <Info size={16} color="#ff8a3d" />
                  <h3 style={{ fontSize: '1rem', fontWeight: 700, color: '#f8fafc', fontFamily: 'var(--font-heading)' }}>
                    {selectedElement.isNode ? 'Entity Telemetry' : 'Edge Link Relation'}
                  </h3>
                </div>
                <button
                  onClick={() => setSelectedElement(null)}
                  style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', display: 'flex' }}
                >
                  <X size={16} />
                </button>
              </div>

              {selectedElement.isNode ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
                  <div>
                    <span
                      className="badge-mono"
                      style={{
                        background: `${NODE_COLORS[selectedElement.data.type as GraphNodeType] || '#ff8a3d'}22`,
                        color: NODE_COLORS[selectedElement.data.type as GraphNodeType] || '#ff8a3d',
                        border: `1px solid ${NODE_COLORS[selectedElement.data.type as GraphNodeType] || '#ff8a3d'}66`,
                        textTransform: 'uppercase',
                        fontWeight: 700,
                      }}
                    >
                      {selectedElement.data.type}
                    </span>
                    <div
                      style={{
                        fontSize: '1.25rem',
                        fontWeight: 700,
                        color: '#f8fafc',
                        marginTop: '10px',
                        fontFamily: 'var(--font-mono)',
                      }}
                    >
                      {selectedElement.data.label}
                    </div>
                  </div>

                  <div style={{ borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '14px' }}>
                    <div style={{ fontSize: '0.72rem', color: '#64748b', marginBottom: '8px', fontWeight: 700, letterSpacing: '0.04em' }}>
                      RAW GRAPH ENTITY METADATA
                    </div>
                    <pre
                      style={{
                        background: 'rgba(5, 7, 12, 0.95)',
                        padding: '12px',
                        borderRadius: '8px',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
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
                        background: 'rgba(255, 138, 61, 0.18)',
                        color: '#ff8a3d',
                        border: '1px solid rgba(255, 138, 61, 0.45)',
                        fontWeight: 700,
                      }}
                    >
                      RELATION: {selectedElement.data.type}
                    </span>
                    <div style={{ marginTop: '14px', fontSize: '0.85rem', color: '#cbd5e1' }}>
                      <div style={{ marginBottom: '8px' }}>
                        <span style={{ color: '#64748b', fontWeight: 600 }}>Source:</span>{' '}
                        <code style={{ color: '#ff8a3d' }}>{selectedElement.data.source}</code>
                      </div>
                      <div>
                        <span style={{ color: '#64748b', fontWeight: 600 }}>Target:</span>{' '}
                        <code style={{ color: '#ff8a3d' }}>{selectedElement.data.target}</code>
                      </div>
                    </div>
                  </div>

                  <div style={{ borderTop: '1px solid rgba(255,255,255,0.08)', paddingTop: '14px' }}>
                    <div style={{ fontSize: '0.72rem', color: '#64748b', marginBottom: '8px', fontWeight: 700, letterSpacing: '0.04em' }}>
                      RAW EDGE RELATION
                    </div>
                    <pre
                      style={{
                        background: 'rgba(5, 7, 12, 0.95)',
                        padding: '12px',
                        borderRadius: '8px',
                        border: '1px solid rgba(255, 255, 255, 0.08)',
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
            </motion.div>
          )}
        </AnimatePresence>

        {loading && (
          <div
            style={{
              position: 'absolute',
              inset: 0,
              background: 'rgba(7, 9, 14, 0.8)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#ff8a3d',
              fontSize: '0.9rem',
              fontWeight: 600,
              zIndex: 30,
            }}
          >
            Constructing interactive knowledge graph...
          </div>
        )}
      </div>
    </div>
  );
};

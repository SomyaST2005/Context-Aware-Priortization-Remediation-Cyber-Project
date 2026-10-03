import { useEffect, useRef, useState } from 'react';
import cytoscape from 'cytoscape';
import type { ElementDefinition } from 'cytoscape';
import dagre from 'cytoscape-dagre';
import type { GraphResponse } from '../../types/api';
import { inferNodeKind, nodeLabel, edgeKind } from './graphModel';

cytoscape.use(dagre);

export interface Highlight {
  /** Node ids to emphasize (path / blast / chokepoint selection). */
  nodes: Set<string>;
  /** Edge ids (backend edge_id) to emphasize. */
  edges: Set<string>;
}

export const EMPTY_HIGHLIGHT: Highlight = { nodes: new Set(), edges: new Set() };

interface CytoscapeCanvasProps {
  graph: GraphResponse;
  highlight?: Highlight;
  selectedNodeId?: string | null;
  selectedEdgeId?: string | null;
  onNodeSelect?: (nodeId: string | null) => void;
  onEdgeSelect?: (edgeId: string | null) => void;
  /** Initial state of the CVE toggle. When hidden, the CVE id and severity stay visible on each finding. */
  hideVulnerabilities?: boolean;
  height?: number;
}

const EDGE_COLORS: Record<string, string> = {
  EXPLOITS: '#f87171',
  CAN_REACH: '#64748b',
  LATERAL_MOVEMENT: '#fb923c',
  PRIVILEGE_ESCALATION: '#c084fc',
  CREDENTIAL_ACCESS: '#fbbf24',
  TRUSTED_ACCESS: '#60a5fa',
  UNKNOWN: '#475569',
};

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: '#ef4444',
  HIGH: '#fb923c',
  MEDIUM: '#fbbf24',
  LOW: '#60a5fa',
  NONE: '#94a3b8',
};

function toElements(graph: GraphResponse, hideVulns: boolean): ElementDefinition[] {
  const rawNodes = graph.elements.nodes;

  // vulnerability_id -> { cve, severity } so findings can show their CVE.
  const vulnInfo = new Map<string, { cve: string; severity: string }>();
  rawNodes.forEach((n) => {
    if (inferNodeKind(n.data) === 'vulnerability') {
      vulnInfo.set(String(n.data.id), {
        cve: typeof n.data.cve_id === 'string' ? n.data.cve_id : String(n.data.id),
        severity: typeof n.data.severity === 'string' ? n.data.severity.toUpperCase() : 'NONE',
      });
    }
  });

  const keptIds = new Set<string>();
  const nodes: ElementDefinition[] = [];
  rawNodes.forEach((n) => {
    const kind = inferNodeKind(n.data);
    if (hideVulns && kind === 'vulnerability') return;
    keptIds.add(String(n.data.id));

    let label = nodeLabel(n.data);
    let severityColor = '';
    if (kind === 'finding') {
      const v = vulnInfo.get(String(n.data.vulnerability_id ?? ''));
      if (v) {
        label = `${n.data.id}\n${v.cve}`;
        severityColor = SEVERITY_COLORS[v.severity] ?? SEVERITY_COLORS.NONE;
      }
    }
    if (kind === 'asset') {
      if (n.data.is_entry_point === true) label = `${label}\nENTRY`;
      if (n.data.is_crown_jewel === true) label = `${label}\nCROWN JEWEL`;
    }

    nodes.push({
      data: {
        ...n.data,
        label,
        kind,
        severityColor,
        isEntry: n.data.is_entry_point === true,
        isCrown: n.data.is_crown_jewel === true,
      },
    });
  });

  const edges: ElementDefinition[] = graph.elements.edges
    .filter((e) => keptIds.has(String(e.data.source)) && keptIds.has(String(e.data.target)))
    .map((e) => ({
      data: {
        ...e.data,
        kind: edgeKind(e.data),
        label: typeof e.data.edge_type === 'string' ? e.data.edge_type.replace(/_/g, ' ') : '',
      },
    }));

  // View-only links so CVE nodes attach to the finding that references them.
  const links: ElementDefinition[] = [];
  if (!hideVulns) {
    rawNodes.forEach((n) => {
      if (inferNodeKind(n.data) !== 'finding') return;
      const vid = String(n.data.vulnerability_id ?? '');
      if (vid && keptIds.has(vid)) {
        links.push({
          data: { id: `link:${n.data.id}:${vid}`, source: String(n.data.id), target: vid, kind: 'LINK', synthetic: true, label: 'has CVE' },
          selectable: false,
        });
      }
    });
  }

  return [...nodes, ...edges, ...links];
}

/**
 * Shared Cytoscape canvas. Left-to-right layered (dagre) layout so attacks flow
 * from entry points to crown jewels. Edge labels show on hover / selection.
 */
export function CytoscapeCanvas({
  graph,
  highlight = EMPTY_HIGHLIGHT,
  selectedNodeId = null,
  selectedEdgeId = null,
  onNodeSelect,
  onEdgeSelect,
  hideVulnerabilities = true,
  height = 520,
}: CytoscapeCanvasProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const callbacksRef = useRef({ onNodeSelect, onEdgeSelect });
  const [showVulns, setShowVulns] = useState(!hideVulnerabilities);
  const [cyVersion, setCyVersion] = useState(0);

  useEffect(() => {
    callbacksRef.current = { onNodeSelect, onEdgeSelect };
  }, [onNodeSelect, onEdgeSelect]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const cy = cytoscape({
      container,
      elements: toElements(graph, !showVulns),
      minZoom: 0.3,
      maxZoom: 2.5,
      wheelSensitivity: 0.25,
      layout: {
        name: 'dagre',
        rankDir: 'LR',
        nodeSep: 70,
        rankSep: 150,
        edgeSep: 30,
        animate: false,
        fit: true,
        padding: 48,
      } as cytoscape.LayoutOptions,
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            shape: 'round-rectangle',
            width: 'label',
            height: 'label',
            padding: '14px',
            'text-wrap': 'wrap',
            'text-max-width': '150px',
            'text-valign': 'center',
            'text-halign': 'center',
            'font-family': 'Inter, system-ui, sans-serif',
            'font-size': 12,
            'font-weight': 600,
            'line-height': 1.35,
            color: '#e2e8f0',
            'background-color': '#16233a',
            'border-width': 2,
            'border-color': '#3b82f6',
            'min-zoomed-font-size': 6,
            'transition-property': 'opacity, border-color, background-color',
            'transition-duration': 150,
          },
        },
        {
          selector: 'node[kind = "finding"]',
          style: {
            shape: 'round-tag',
            'font-size': 11,
            'font-weight': 500,
            'background-color': '#2a1f10',
            'border-color': '#f59e0b',
            color: '#fde68a',
          },
        },
        {
          selector: 'node[kind = "finding"][severityColor != ""]',
          style: { 'border-color': 'data(severityColor)' },
        },
        {
          selector: 'node[kind = "vulnerability"]',
          style: {
            shape: 'round-triangle',
            'background-color': '#241a3d',
            'border-color': '#8b5cf6',
            color: '#ddd6fe',
          },
        },
        {
          selector: 'node[isEntry = true]',
          style: { 'border-color': '#4ade80', 'background-color': '#10281d', color: '#bbf7d0' },
        },
        {
          selector: 'node[isCrown = true]',
          style: { 'border-color': '#fbbf24', 'background-color': '#33270c', color: '#fef3c7', 'border-width': 3 },
        },
        {
          selector: 'edge',
          style: {
            width: 2,
            'line-color': '#475569',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 1.1,
            'curve-style': 'bezier',
            'control-point-step-size': 50,
            label: '',
            'font-size': 10,
            'font-weight': 500,
            color: '#cbd5e1',
            'text-background-color': '#0b1220',
            'text-background-opacity': 0.9,
            'text-background-padding': '3px',
            'text-background-shape': 'roundrectangle',
            'text-rotation': 'autorotate',
            'transition-property': 'opacity, line-color, width',
            'transition-duration': 150,
          },
        },
        ...Object.entries(EDGE_COLORS).map(([kind, color]) => ({
          selector: `edge[kind = "${kind}"]`,
          style: { 'line-color': color, 'target-arrow-color': color },
        })),
        {
          selector: 'edge[kind = "LINK"]',
          style: {
            width: 1.5,
            'line-style': 'dashed',
            'line-color': '#6d5bd0',
            'target-arrow-color': '#6d5bd0',
            'target-arrow-shape': 'none',
            opacity: 0.8,
          },
        },
        {
          selector: 'edge.hover, edge.selected, edge.highlighted',
          style: { label: 'data(label)' },
        },
        {
          selector: 'edge.hover',
          style: { width: 3.5 },
        },
        {
          selector: 'node.hover',
          style: { 'border-width': 4 },
        },
        {
          selector: '.highlighted',
          style: {
            'line-color': '#22d3ee',
            'target-arrow-color': '#22d3ee',
            'border-color': '#22d3ee',
            'background-color': '#0c2f3a',
            color: '#cffafe',
            width: 4,
            'z-index': 10,
          },
        },
        {
          selector: 'node.highlighted',
          style: { width: 'label', 'border-width': 4 },
        },
        {
          selector: '.dimmed',
          style: { opacity: 0.18 },
        },
        {
          selector: 'node.selected',
          style: { 'border-color': '#ffffff', 'border-width': 4 },
        },
        {
          selector: 'edge.selected',
          style: { 'line-color': '#ffffff', 'target-arrow-color': '#ffffff', width: 4 },
        },
      ],
    });

    cy.on('tap', 'node', (evt) => {
      callbacksRef.current.onNodeSelect?.(evt.target.id());
    });
    cy.on('tap', 'edge', (evt) => {
      if (evt.target.data('synthetic')) return;
      callbacksRef.current.onEdgeSelect?.(evt.target.id());
    });
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        callbacksRef.current.onNodeSelect?.(null);
        callbacksRef.current.onEdgeSelect?.(null);
      }
    });
    cy.on('mouseover', 'node, edge', (evt) => {
      evt.target.addClass('hover');
      container.style.cursor = 'pointer';
    });
    cy.on('mouseout', 'node, edge', (evt) => {
      evt.target.removeClass('hover');
      container.style.cursor = 'default';
    });

    cyRef.current = cy;
    setCyVersion((v) => v + 1);
    return () => {
      cyRef.current = null;
      cy.destroy();
    };
  }, [graph, showVulns]);

  // Keep the graph fitted when the container is resized.
  useEffect(() => {
    const container = containerRef.current;
    if (!container || typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver(() => {
      const cy = cyRef.current;
      if (cy) {
        cy.resize();
        cy.fit(undefined, 48);
      }
    });
    ro.observe(container);
    return () => ro.disconnect();
  }, []);

  // Apply highlight / selection classes without recreating the instance.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    const hasHighlight = highlight.nodes.size > 0 || highlight.edges.size > 0;
    cy.batch(() => {
      cy.elements().removeClass('highlighted dimmed selected');
      if (hasHighlight) {
        cy.elements().addClass('dimmed');
        highlight.nodes.forEach((id) => {
          const el = cy.getElementById(id);
          if (el.nonempty()) el.removeClass('dimmed').addClass('highlighted');
        });
        highlight.edges.forEach((id) => {
          const el = cy.getElementById(id);
          if (el.nonempty()) el.removeClass('dimmed').addClass('highlighted');
        });
      }
      if (selectedNodeId) {
        const el = cy.getElementById(selectedNodeId);
        if (el.nonempty() && el.isNode()) {
          el.removeClass('dimmed').addClass('selected');
        }
      }
      if (selectedEdgeId) {
        const el = cy.getElementById(selectedEdgeId);
        if (el.nonempty() && el.isEdge()) {
          el.removeClass('dimmed').addClass('selected');
        }
      }
    });
  }, [graph, cyVersion, highlight, selectedNodeId, selectedEdgeId]);

  const zoom = (factor: number) => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom({ level: cy.zoom() * factor, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  };

  const toolBtn =
    'w-8 h-8 flex items-center justify-center rounded-md text-sm font-medium text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)] hover:bg-[var(--color-bg-tertiary)] transition-colors';

  return (
    <div className="relative overflow-hidden rounded-xl border border-[var(--color-border-primary)] bg-[var(--color-bg-primary)]">
      <div
        ref={containerRef}
        style={{
          height,
          backgroundImage: 'radial-gradient(circle, rgba(148,163,184,0.14) 1px, transparent 1px)',
          backgroundSize: '22px 22px',
        }}
        className="w-full"
        role="img"
        aria-label="Security graph visualization"
      />

      {/* Zoom toolbar */}
      <div className="absolute top-3 right-3 flex items-center gap-0.5 p-1 rounded-lg bg-[var(--color-bg-secondary)]/90 backdrop-blur border border-[var(--color-border-primary)] shadow-lg">
        <button type="button" className={toolBtn} onClick={() => zoom(1.25)} aria-label="Zoom in">+</button>
        <button type="button" className={toolBtn} onClick={() => zoom(0.8)} aria-label="Zoom out">−</button>
        <span className="w-px h-5 bg-[var(--color-border-primary)] mx-1" aria-hidden="true" />
        <button
          type="button"
          className={`${toolBtn} w-auto px-2.5 text-xs ${showVulns ? 'text-[var(--color-accent)]' : ''}`}
          onClick={() => setShowVulns((v) => !v)}
          aria-pressed={showVulns}
          title="Show vulnerability (CVE) nodes as separate nodes"
        >
          CVEs
        </button>
        <button type="button" className={`${toolBtn} w-auto px-2.5 text-xs`} onClick={() => cyRef.current?.fit(undefined, 48)} aria-label="Fit graph to view">Fit</button>
        <button type="button" className={`${toolBtn} w-auto px-2.5 text-xs`} onClick={() => { cyRef.current?.reset(); cyRef.current?.fit(undefined, 48); }} aria-label="Reset view">Reset</button>
      </div>

      {/* Legend */}
      <div
        className="absolute bottom-3 left-3 flex flex-wrap items-center gap-x-4 gap-y-1 px-3 py-2 rounded-lg bg-[var(--color-bg-secondary)]/90 backdrop-blur border border-[var(--color-border-primary)] text-xs text-[var(--color-text-secondary)]"
        aria-hidden="true"
      >
        <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-[4px] border-2 border-[#3b82f6]" />Asset</span>
        <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-[4px] border-2 border-[#4ade80] bg-[#10281d]" />Entry point</span>
        <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-[4px] border-2 border-[#fbbf24] bg-[#33270c]" />Crown jewel</span>
        <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-[4px] border-2 border-[#f59e0b]" />Finding</span>
        {showVulns && (
          <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-[4px] border-2 border-[#8b5cf6] bg-[#241a3d]" />Vulnerability</span>
        )}
        <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-[4px] border-2 border-[#22d3ee] bg-[#0c2f3a]" />Highlighted</span>
      </div>
    </div>
  );
}

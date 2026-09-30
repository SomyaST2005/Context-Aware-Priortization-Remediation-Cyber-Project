import { useEffect, useRef } from 'react';
import cytoscape from 'cytoscape';
import type { ElementDefinition } from 'cytoscape';
import type { GraphResponse } from '../../types/api';
import { inferNodeKind, nodeLabel, edgeKind } from './graphModel';

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

function toElements(graph: GraphResponse): ElementDefinition[] {
  const nodes: ElementDefinition[] = graph.elements.nodes.map((n) => {
    const kind = inferNodeKind(n.data);
    return {
      data: {
        ...n.data,
        label: nodeLabel(n.data),
        kind,
        isEntry: n.data.is_entry_point === true,
        isCrown: n.data.is_crown_jewel === true,
      },
    };
  });
  const edges: ElementDefinition[] = graph.elements.edges.map((e) => ({
    data: {
      ...e.data,
      kind: edgeKind(e.data),
      label: typeof e.data.edge_type === 'string' ? e.data.edge_type : '',
    },
  }));
  return [...nodes, ...edges];
}

/**
 * Shared Cytoscape canvas. Creates the instance once per graph payload,
 * applies highlight classes imperatively (no re-creation on selection).
 */
export function CytoscapeCanvas({
  graph,
  highlight = EMPTY_HIGHLIGHT,
  selectedNodeId = null,
  selectedEdgeId = null,
  onNodeSelect,
  onEdgeSelect,
}: CytoscapeCanvasProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<cytoscape.Core | null>(null);
  const callbacksRef = useRef({ onNodeSelect, onEdgeSelect });

  // Keep callbacks fresh without reading refs during render.
  useEffect(() => {
    callbacksRef.current = { onNodeSelect, onEdgeSelect };
  }, [onNodeSelect, onEdgeSelect]);

  // (Re)create instance when the graph payload identity changes.
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const cy = cytoscape({
      container,
      elements: toElements(graph),
      layout: { name: 'cose', animate: false, padding: 30 },
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            'font-size': 9,
            color: '#e2e8f0',
            'text-valign': 'bottom',
            'text-halign': 'center',
            'text-margin-y': 4,
            'background-color': '#3b82f6',
            'border-width': 2,
            'border-color': '#1e293b',
            width: 28,
            height: 28,
          },
        },
        {
          selector: 'node[kind = "finding"]',
          style: { 'background-color': '#f59e0b', shape: 'diamond', width: 24, height: 24 },
        },
        {
          selector: 'node[kind = "vulnerability"]',
          style: { 'background-color': '#8b5cf6', shape: 'triangle', width: 22, height: 22 },
        },
        {
          selector: 'node[isEntry = true]',
          style: { 'border-color': '#4ade80', 'border-width': 4 },
        },
        {
          selector: 'node[isCrown = true]',
          style: {
            'background-color': '#fbbf24',
            'border-color': '#f59e0b',
            'border-width': 4,
            width: 34,
            height: 34,
          },
        },
        {
          selector: 'edge',
          style: {
            width: 2,
            'line-color': '#475569',
            'target-arrow-color': '#475569',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            label: 'data(label)',
            'font-size': 7,
            color: '#94a3b8',
          },
        },
        ...Object.entries(EDGE_COLORS).map(([kind, color]) => ({
          selector: `edge[kind = "${kind}"]`,
          style: { 'line-color': color, 'target-arrow-color': color },
        })),
        {
          selector: '.highlighted',
          style: {
            'background-color': '#22d3ee',
            'line-color': '#22d3ee',
            'target-arrow-color': '#22d3ee',
            'border-color': '#22d3ee',
            width: 4,
          },
        },
        {
          selector: '.dimmed',
          style: { opacity: 0.22 },
        },
        {
          selector: '.selected',
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
      callbacksRef.current.onEdgeSelect?.(evt.target.id());
    });
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        callbacksRef.current.onNodeSelect?.(null);
        callbacksRef.current.onEdgeSelect?.(null);
      }
    });

    cyRef.current = cy;
    return () => {
      cyRef.current = null;
      cy.destroy();
    };
  }, [graph]);

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
  }, [graph, highlight, selectedNodeId, selectedEdgeId]);

  const zoom = (factor: number) => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.zoom({ level: cy.zoom() * factor, renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 } });
  };

  return (
    <div className="relative">
      <div ref={containerRef} className="h-[480px] w-full rounded-md bg-[var(--color-bg-primary)]" role="img" aria-label="Security graph visualization" />
      <div className="absolute top-2 right-2 flex gap-1.5">
        <button type="button" className="btn-ghost px-2.5 py-1.5 text-xs" onClick={() => zoom(1.25)} aria-label="Zoom in">+</button>
        <button type="button" className="btn-ghost px-2.5 py-1.5 text-xs" onClick={() => zoom(0.8)} aria-label="Zoom out">−</button>
        <button type="button" className="btn-ghost px-2.5 py-1.5 text-xs" onClick={() => cyRef.current?.fit(undefined, 30)} aria-label="Fit graph to view">Fit</button>
        <button type="button" className="btn-ghost px-2.5 py-1.5 text-xs" onClick={() => cyRef.current?.reset()} aria-label="Reset view">Reset</button>
      </div>
      <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[var(--color-text-muted)]" aria-hidden="true">
        <span><span className="inline-block w-2.5 h-2.5 rounded-full bg-[#3b82f6] mr-1" />Asset</span>
        <span><span className="inline-block w-2.5 h-2.5 rotate-45 bg-[#f59e0b] mr-1" />Finding</span>
        <span><span className="inline-block w-2.5 h-2.5 rounded-full bg-[#8b5cf6] mr-1" />Vuln</span>
        <span><span className="inline-block w-2.5 h-2.5 rounded-full border-2 border-[#4ade80] mr-1" />Entry</span>
        <span><span className="inline-block w-2.5 h-2.5 rounded-full bg-[#fbbf24] mr-1" />Crown jewel</span>
        <span><span className="inline-block w-2.5 h-2.5 rounded-full bg-[#22d3ee] mr-1" />Highlighted</span>
      </div>
    </div>
  );
}

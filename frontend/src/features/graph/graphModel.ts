import type { GraphNodeData, GraphEdgeData } from '../../types/api';

export type NodeKind = 'asset' | 'finding' | 'vulnerability' | 'unknown';

/**
 * The backend graph endpoint excludes the internal node `type` field, so the
 * frontend infers the kind from attribute presence (attribute names come
 * straight from backend/app/graph/builder.py).
 */
export function inferNodeKind(data: GraphNodeData): NodeKind {
  if (data.finding_id !== undefined && data.finding_id !== null) return 'finding';
  if (data.cve_id !== undefined || data.title !== undefined) return 'vulnerability';
  if (data.asset_id !== undefined || data.name !== undefined) return 'asset';
  const id = String(data.id ?? '');
  if (id.startsWith('finding-')) return 'finding';
  if (id.startsWith('asset-')) return 'asset';
  if (id.startsWith('vuln-')) return 'vulnerability';
  return 'unknown';
}

export function nodeLabel(data: GraphNodeData): string {
  const kind = inferNodeKind(data);
  if (kind === 'asset') return String(data.name ?? data.id);
  if (kind === 'finding') return String(data.id);
  if (kind === 'vulnerability') {
    const cve = data.cve_id;
    if (typeof cve === 'string' && cve) return cve;
    return String(data.id);
  }
  return String(data.id);
}

export function isEntryPoint(data: GraphNodeData): boolean {
  return data.is_entry_point === true;
}

export function isCrownJewel(data: GraphNodeData): boolean {
  return data.is_crown_jewel === true;
}

export type EdgeKind =
  | 'EXPLOITS'
  | 'CAN_REACH'
  | 'LATERAL_MOVEMENT'
  | 'PRIVILEGE_ESCALATION'
  | 'CREDENTIAL_ACCESS'
  | 'TRUSTED_ACCESS'
  | 'UNKNOWN';

export function edgeKind(data: GraphEdgeData): EdgeKind {
  const t = data.edge_type;
  switch (t) {
    case 'EXPLOITS':
    case 'CAN_REACH':
    case 'LATERAL_MOVEMENT':
    case 'PRIVILEGE_ESCALATION':
    case 'CREDENTIAL_ACCESS':
    case 'TRUSTED_ACCESS':
      return t;
    default:
      return 'UNKNOWN';
  }
}

import { Card, CardHeader, CardBody, Badge } from '../../components/ui';
import type { GraphResponse } from '../../types/api';
import { inferNodeKind } from './graphModel';

interface NodeDetailsProps {
  graph: GraphResponse;
  nodeId: string | null;
  edgeId: string | null;
  onClose: () => void;
}

function Row({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3 text-sm">
      <dt className="text-[var(--color-text-secondary)] capitalize">{label}</dt>
      <dd className={mono ? 'font-mono text-[var(--color-text-primary)] break-all text-right' : 'text-[var(--color-text-primary)] text-right'}>
        {value}
      </dd>
    </div>
  );
}

function humanize(key: string): string {
  return key.replace(/_/g, ' ');
}

function str(v: unknown): string {
  if (v === null || v === undefined) return '—';
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  if (typeof v === 'number') return Number.isInteger(v) ? String(v) : v.toFixed(3);
  return String(v);
}

export function SelectionDetails({ graph, nodeId, edgeId, onClose }: NodeDetailsProps) {
  if (!nodeId && !edgeId) return null;

  const node = nodeId
    ? graph.elements.nodes.find((n) => String(n.data.id) === nodeId)
    : undefined;
  const edge = edgeId
    ? graph.elements.edges.find((e) => String(e.data.id) === edgeId)
    : undefined;

  if (!node && !edge) return null;

  const linkedVuln =
    node && inferNodeKind(node.data) === 'finding'
      ? graph.elements.nodes.find((n) => String(n.data.id) === String(node.data.vulnerability_id))
      : undefined;

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <h3 className="section-title">Selection details</h3>
          <button type="button" className="btn-ghost px-2 py-1 text-xs" onClick={onClose}>
            Clear
          </button>
        </div>
      </CardHeader>
      <CardBody>
        {node && (
          <div className="space-y-1.5">
            <div className="mb-2">
              <Badge variant="default">{inferNodeKind(node.data)}</Badge>{' '}
              <span className="font-mono text-sm">{String(node.data.id)}</span>
            </div>
            <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-1.5">
              {Object.entries(node.data)
                .filter(([k]) => !['id', 'label', 'kind', 'isEntry', 'isCrown', 'severityColor', 'owner', 'ip_address'].includes(k))
                .map(([k, v]) => (
                  <Row key={k} label={humanize(k)} value={str(v)} mono />
                ))}
            </dl>
            {linkedVuln && (
              <div className="mt-4 pt-3 border-t border-[var(--color-border-primary)]">
                <p className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-muted)] mb-2">
                  Linked vulnerability
                </p>
                <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-1.5">
                  {['cve_id', 'title', 'severity', 'cvss_score', 'epss_score', 'known_exploited', 'attack_vector']
                    .filter((k) => linkedVuln.data[k] !== undefined)
                    .map((k) => (
                      <Row key={k} label={humanize(k)} value={str(linkedVuln.data[k])} mono />
                    ))}
                </dl>
              </div>
            )}
          </div>
        )}
        {edge && (
          <div className="space-y-1.5">
            <div className="mb-2">
              <Badge variant="default">edge</Badge>{' '}
              <span className="font-mono text-sm">
                {String(edge.data.source)} → {String(edge.data.target)}
              </span>
            </div>
            <dl className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-1.5">
              {Object.entries(edge.data)
                .filter(([k]) => k !== 'label' && k !== 'kind')
                .map(([k, v]) => (
                  <Row key={k} label={humanize(k)} value={str(v)} mono />
                ))}
            </dl>
          </div>
        )}
      </CardBody>
    </Card>
  );
}

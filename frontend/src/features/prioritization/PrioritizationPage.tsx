import { useEffect, useState } from 'react';
import { useScenario } from '../../context/ScenarioContext';
import { api } from '../../services/api';
import type {
  PrioritizationResponse,
  PrioritizationResultResponse,
  VulnerabilitySeverity,
} from '../../types/api';
import { Card, CardHeader, CardBody, Badge, Button } from '../../components/ui';
import { EmptyState, ErrorState, PageLoading } from '../../components/ui';

type Severity = VulnerabilitySeverity;

function severityBadge(severity: Severity) {
  const map: Record<Severity, 'critical' | 'high' | 'medium' | 'low' | 'none'> = {
    CRITICAL: 'critical',
    HIGH: 'high',
    MEDIUM: 'medium',
    LOW: 'low',
    NONE: 'none',
  };
  return <Badge variant={map[severity]}>{severity}</Badge>;
}

function fmt(value: number | null | undefined, digits = 3): string {
  if (value === null || value === undefined || Number.isNaN(value)) return '—';
  return Number(value).toFixed(digits);
}

export function PrioritizationPage() {
  const { selectedScenario } = useScenario();
  const [data, setData] = useState<PrioritizationResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [retryKey, setRetryKey] = useState(0);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const scenarioId = selectedScenario?.id;

  useEffect(() => {
    if (!scenarioId) {
      setData(null);
      setIsLoading(false);
      return;
    }
    let cancelled = false;
    const load = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await api.prioritization.get(scenarioId);
        if (!cancelled) setData(result);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load prioritization');
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [scenarioId, retryKey]);

  const toggle = (findingId: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(findingId)) next.delete(findingId);
      else next.add(findingId);
      return next;
    });
  };

  if (!selectedScenario) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="page-title">Prioritization</h1>
        </div>
        <Card>
          <CardBody>
            <EmptyState
              title="No Scenario Selected"
              description="Select a scenario from the header to view contextual prioritization."
            />
          </CardBody>
        </Card>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="page-title">Prioritization</h1>
        </div>
        <PageLoading message="Computing contextual prioritization..." />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="page-title">Prioritization</h1>
        </div>
        <Card>
          <CardBody>
            <ErrorState
              title="Failed to Load Prioritization"
              description={error || 'Unknown error occurred'}
              action={
                <Button variant="primary" onClick={() => setRetryKey((k) => k + 1)}>
                  Retry
                </Button>
              }
            />
          </CardBody>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="page-title">Prioritization</h1>
          <p className="text-muted text-sm mt-1">
            {data.returned_findings} of {data.total_findings} findings in {selectedScenario.name} —
            backend operational ordering (rank preserved)
          </p>
        </div>
        <Button variant="secondary" size="sm" onClick={() => setRetryKey((k) => k + 1)}>
          Re-run
        </Button>
      </div>

      {/* Ordering policy (backend-provided) */}
      <Card>
        <CardHeader>
          <h2 className="section-title">Ordering Policy (backend)</h2>
        </CardHeader>
        <CardBody>
          <p className="text-sm text-[var(--color-text-secondary)] mb-4">
            Operational ordering comes from this configured backend policy — it is not a
            universal risk score.
          </p>
          <div className="flex flex-wrap gap-2 mb-4">
            <Badge variant={data.policy.crown_jewel_first ? 'success' : 'none'}>
              Crown-jewel-first: {data.policy.crown_jewel_first ? 'on' : 'off'}
            </Badge>
            <Badge variant={data.policy.entry_point_first ? 'success' : 'none'}>
              Entry-point-first: {data.policy.entry_point_first ? 'on' : 'off'}
            </Badge>
            <Badge variant={data.policy.kev_tier ? 'warning' : 'none'}>
              KEV tier: {data.policy.kev_tier ? 'on' : 'off'}
            </Badge>
            <Badge variant="default">Tiebreaker: {data.policy.tiebreaker}</Badge>
          </div>
          <dl className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 text-sm">
            <div>
              <dt className="text-muted text-xs">Chokepoint w.</dt>
              <dd className="font-mono">{fmt(data.policy.chokepoint_weight, 2)}</dd>
            </div>
            <div>
              <dt className="text-muted text-xs">Feasibility w.</dt>
              <dd className="font-mono">{fmt(data.policy.feasibility_weight, 2)}</dd>
            </div>
            <div>
              <dt className="text-muted text-xs">CVSS w.</dt>
              <dd className="font-mono">{fmt(data.policy.cvss_weight, 2)}</dd>
            </div>
            <div>
              <dt className="text-muted text-xs">EPSS w.</dt>
              <dd className="font-mono">{fmt(data.policy.epss_weight, 2)}</dd>
            </div>
            <div>
              <dt className="text-muted text-xs">Asset criticality w.</dt>
              <dd className="font-mono">{fmt(data.policy.asset_criticality_weight, 2)}</dd>
            </div>
          </dl>
        </CardBody>
      </Card>

      {data.items.length === 0 ? (
        <Card>
          <CardBody>
            <EmptyState
              title="No Prioritized Findings"
              description="The backend returned no findings for this scenario (no active findings in the current view)."
            />
          </CardBody>
        </Card>
      ) : (
        <Card>
          <CardBody className="p-0">
            <div className="table-container">
              <table className="table">
                <thead>
                  <tr>
                    <th>Rank</th>
                    <th>Finding</th>
                    <th>Asset</th>
                    <th>Severity</th>
                    <th>KEV</th>
                    <th>CVSS (norm)</th>
                    <th>EPSS</th>
                    <th>Paths</th>
                    <th>Crown jewel</th>
                    <th>Chokepoint</th>
                    <th>Op. score</th>
                    <th>Evidence</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((item) => (
                    <PrioritizationRow
                      key={item.profile.finding_id}
                      item={item}
                      isExpanded={expanded.has(item.profile.finding_id)}
                      onToggle={() => toggle(item.profile.finding_id)}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          </CardBody>
        </Card>
      )}
    </div>
  );
}

function PrioritizationRow({
  item,
  isExpanded,
  onToggle,
}: {
  item: PrioritizationResultResponse;
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const p = item.profile;
  const colSpan = 12;
  return (
    <>
      <tr>
        <td className="font-mono font-semibold">#{item.operational_rank}</td>
        <td className="font-mono text-sm">{p.finding_id}</td>
        <td className="font-mono text-sm">{p.asset_id}</td>
        <td>{severityBadge(p.severity_category)}</td>
        <td>
          {p.known_exploited ? (
            <Badge variant="warning">KEV</Badge>
          ) : (
            <Badge variant="none">—</Badge>
          )}
        </td>
        <td className="font-mono">{fmt(p.cvss_normalized)}</td>
        <td className="font-mono">{p.epss_available ? fmt(p.epss_score) : 'n/a'}</td>
        <td className="font-mono">{p.path_participation_count}</td>
        <td>
          {p.crown_jewel_reachable ? (
            <Badge variant="critical">Reachable</Badge>
          ) : (
            <Badge variant="none">No</Badge>
          )}
        </td>
        <td className="font-mono">{fmt(p.finding_chokepoint_score)}</td>
        <td className="font-mono">{fmt(item.operational_score)}</td>
        <td>
          <Button variant="ghost" size="sm" onClick={onToggle} aria-expanded={isExpanded}>
            {isExpanded ? 'Hide' : 'Why here?'}
          </Button>
        </td>
      </tr>
      {isExpanded && (
        <tr>
          <td colSpan={colSpan} className="!whitespace-normal">
            <EvidenceDetail item={item} />
          </td>
        </tr>
      )}
    </>
  );
}

function EvidenceDetail({ item }: { item: PrioritizationResultResponse }) {
  const { profile: p, evidence: e, ordering_keys: keys } = item;
  return (
    <div className="py-2 space-y-4">
      <p className="text-xs text-[var(--color-text-muted)]">
        Backend evidence for <span className="font-mono">{p.finding_id}</span> — descriptive
        values only. Ordering: tiers [{keys.tiers.join(', ')}], composite{' '}
        {fmt(keys.composite_score)}, tiebreaker <span className="font-mono">{keys.tiebreaker}</span>.
      </p>
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
        <EvidenceGroup title="Vulnerability">
          <EvidenceRow label="Severity" value={e.vulnerability_intrinsic.severity_category} />
          <EvidenceRow label="CVSS normalized" value={fmt(e.vulnerability_intrinsic.cvss_normalized)} mono />
          <EvidenceRow
            label="EPSS"
            value={p.epss_available ? fmt(e.vulnerability_intrinsic.epss_score) : 'unavailable'}
            mono
          />
          <EvidenceRow label="Known exploited (KEV)" value={e.vulnerability_intrinsic.known_exploited ? 'Yes' : 'No'} />
        </EvidenceGroup>
        <EvidenceGroup title="Attack-path context">
          <EvidenceRow label="Path participation" value={String(e.attack_path_context.path_count)} mono />
          <EvidenceRow label="Max feasibility" value={fmt(e.attack_path_context.max_feasibility)} mono />
          <EvidenceRow label="Avg feasibility" value={fmt(e.attack_path_context.avg_feasibility)} mono />
          <EvidenceRow
            label="Crown jewel reachable"
            value={e.attack_path_context.crown_jewel_reachable ? 'Yes' : 'No'}
          />
          <EvidenceRow
            label="Entry points / Crown jewels"
            value={`${e.attack_path_context.unique_entry_points} / ${e.attack_path_context.unique_crown_jewels}`}
            mono
          />
          <EvidenceRow
            label="Depth (min–max)"
            value={`${e.attack_path_context.min_depth}–${e.attack_path_context.max_depth}`}
            mono
          />
        </EvidenceGroup>
        <EvidenceGroup title="Environmental">
          <EvidenceRow label="Asset criticality (norm)" value={fmt(e.environmental.asset_criticality_normalized)} mono />
          <EvidenceRow label="Entry point asset" value={e.environmental.is_entry_point ? 'Yes' : 'No'} />
          <EvidenceRow label="Crown jewel asset" value={e.environmental.is_crown_jewel ? 'Yes' : 'No'} />
          <EvidenceRow label="Blast-radius assets" value={String(e.environmental.blast_radius_assets)} mono />
          <EvidenceRow
            label="Blast crown jewels"
            value={String(e.environmental.blast_radius_crown_jewels)}
            mono
          />
          <EvidenceRow label="Blast max depth" value={String(e.environmental.blast_radius_max_depth)} mono />
        </EvidenceGroup>
        <EvidenceGroup title="Chokepoint">
          <EvidenceRow label="Finding score" value={fmt(e.chokepoint.finding_chokepoint_score)} mono />
          <EvidenceRow
            label="Finding path criticality"
            value={fmt(e.chokepoint.finding_path_feasibility_criticality)}
            mono
          />
          <EvidenceRow label="Finding path count" value={String(e.chokepoint.finding_path_count)} mono />
          <EvidenceRow label="Asset score" value={fmt(e.chokepoint.asset_chokepoint_score)} mono />
          <EvidenceRow label="Asset path count" value={String(e.chokepoint.asset_path_count)} mono />
        </EvidenceGroup>
        <EvidenceGroup title="Remediation context">
          <EvidenceRow label="Est. cost" value={fmt(e.remediation_context.remediation_cost, 2)} mono />
          <EvidenceRow
            label="Complexity"
            value={e.remediation_context.implementation_complexity ?? '—'}
          />
          <EvidenceRow
            label="Downtime required"
            value={e.remediation_context.downtime_required ? 'Yes' : 'No'}
          />
          <EvidenceRow label="Action type" value={e.remediation_context.action_type ?? '—'} mono />
        </EvidenceGroup>
      </div>
    </div>
  );
}

function EvidenceGroup({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-[var(--color-border-primary)] bg-[var(--color-bg-secondary)] p-3">
      <h4 className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-muted)] mb-2">
        {title}
      </h4>
      <dl className="space-y-1.5">{children}</dl>
    </div>
  );
}

function EvidenceRow({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between gap-3 text-sm">
      <dt className="text-[var(--color-text-secondary)]">{label}</dt>
      <dd className={mono ? 'font-mono text-[var(--color-text-primary)]' : 'text-[var(--color-text-primary)]'}>
        {value}
      </dd>
    </div>
  );
}

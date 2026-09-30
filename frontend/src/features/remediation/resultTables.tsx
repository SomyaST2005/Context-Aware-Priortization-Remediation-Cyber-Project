import type {
  FindingRankComparisonResponse,
  MetricDeltaResponse,
} from '../../types/api';
import { Badge } from '../../components/ui';

/** Render a backend number, preserving null as "n/a" (never 0). */
export function num(value: number | null | undefined, digits = 2): string {
  if (value === null || value === undefined || Number.isNaN(value)) return 'n/a';
  return Number(value).toFixed(digits);
}

const METRIC_LABELS: Record<string, string> = {
  total_attack_paths: 'Attack paths',
  crown_jewel_path_count: 'Crown-jewel paths',
  distinct_crown_jewels: 'Distinct crown jewels',
  sum_path_feasibility: 'Sum path feasibility',
  max_path_feasibility: 'Max path feasibility',
  min_path_depth: 'Min path depth',
  max_path_depth: 'Max path depth',
  blast_affected_assets: 'Blast affected assets',
  blast_crown_jewels: 'Blast crown jewels',
  blast_max_depth: 'Blast max depth',
  chokepoint_count: 'Chokepoints',
  max_chokepoint_score: 'Max chokepoint score',
  sum_chokepoint_criticality: 'Sum chokepoint criticality',
  prioritization_count: 'Prioritized findings',
  max_operational_score: 'Max operational score',
};

export function metricLabel(name: string): string {
  return METRIC_LABELS[name] ?? name;
}

function deltaTone(delta: MetricDeltaResponse): 'success' | 'critical' | 'none' {
  if (delta.absolute_delta === null || delta.absolute_delta === undefined) return 'none';
  if (delta.absolute_delta < 0) return 'success';
  if (delta.absolute_delta > 0) return 'critical';
  return 'none';
}

/** Before/after metric deltas straight from the backend response. */
export function DeltaTable({ deltas }: { deltas: MetricDeltaResponse[] }) {
  if (deltas.length === 0) {
    return <p className="p-4 text-sm text-[var(--color-text-muted)]">No metric deltas returned.</p>;
  }
  return (
    <div className="table-container max-h-[380px] overflow-y-auto">
      <table className="table">
        <thead>
          <tr>
            <th>Metric</th>
            <th>Before</th>
            <th>After</th>
            <th>Δ abs</th>
            <th>Δ %</th>
          </tr>
        </thead>
        <tbody>
          {deltas.map((d) => (
            <tr key={d.metric_name}>
              <td>{metricLabel(d.metric_name)}</td>
              <td className="font-mono">{num(d.before)}</td>
              <td className="font-mono">{num(d.after)}</td>
              <td>
                <Badge variant={deltaTone(d)}>
                  {d.absolute_delta === null || d.absolute_delta === undefined ? 'n/a' : num(d.absolute_delta)}
                </Badge>
              </td>
              <td className="font-mono">
                {d.percent_change === null || d.percent_change === undefined ? 'n/a' : `${num(d.percent_change)}%`}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** Rank comparison straight from the backend: REMEDIATED vs surviving findings. */
export function RankTable({ rows }: { rows: FindingRankComparisonResponse[] }) {
  if (rows.length === 0) {
    return <p className="p-4 text-sm text-[var(--color-text-muted)]">No rank comparisons returned.</p>;
  }
  return (
    <div className="table-container max-h-[380px] overflow-y-auto">
      <table className="table">
        <thead>
          <tr>
            <th>Finding</th>
            <th>Status</th>
            <th>Base rank</th>
            <th>New rank</th>
            <th>Δ rank</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.finding_id}>
              <td className="font-mono text-xs">{r.finding_id}</td>
              <td>
                {r.status === 'REMEDIATED' ? (
                  <Badge variant="success">REMEDIATED</Badge>
                ) : (
                  <Badge variant="default">ACTIVE</Badge>
                )}
              </td>
              <td className="font-mono">{r.baseline_rank ?? 'n/a'}</td>
              <td className="font-mono">{r.simulated_rank ?? 'n/a'}</td>
              <td className="font-mono">{r.rank_delta ?? 'n/a'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

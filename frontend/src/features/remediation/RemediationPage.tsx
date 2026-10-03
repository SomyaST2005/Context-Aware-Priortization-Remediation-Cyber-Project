import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useScenario } from '../../context/ScenarioContext';
import { api } from '../../services/api';
import type {
  RemediationActionResponse,
  SimulationResponse,
} from '../../types/api';
import { DEFERRED_ACTION_TYPES, MVP_ACTION_TYPES } from '../../types/api';
import { Card, CardHeader, CardBody, Badge, Button, Input, PageHeader, Toolbar } from '../../components/ui';
import { EmptyState, ErrorState, PageLoading } from '../../components/ui';
import { useScenarioGraph } from '../graph/useScenarioGraph';
import { CytoscapeCanvas, EMPTY_HIGHLIGHT, type Highlight } from '../graph/CytoscapeCanvas';
import { DeltaTable, RankTable, num } from './resultTables';

function targetLabel(a: RemediationActionResponse): string {
  if (a.target_finding_id) return `finding ${a.target_finding_id}`;
  if (a.target_asset_id) return `asset ${a.target_asset_id}`;
  if (a.target_edge_id) return `edge ${a.target_edge_id}`;
  return 'no target';
}

function isSupported(a: RemediationActionResponse): boolean {
  return (MVP_ACTION_TYPES as string[]).includes(a.action_type);
}

export function RemediationPage() {
  const navigate = useNavigate();
  const { selectedScenario } = useScenario();
  const scenarioId = selectedScenario?.id;
  const { data: graph } = useScenarioGraph(scenarioId);

  const [actions, setActions] = useState<RemediationActionResponse[]>([]);
  const [isLoadingActions, setIsLoadingActions] = useState(true);
  const [actionsError, setActionsError] = useState<string | null>(null);
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [maxDepth, setMaxDepth] = useState(10);
  const [maxPaths, setMaxPaths] = useState(100);
  const [result, setResult] = useState<SimulationResponse | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);

  // Clear stale state when scenario changes.
  useEffect(() => {
    setActions([]);
    setSelectedIds([]);
    setResult(null);
    setRunError(null);
    setActionsError(null);
    if (!scenarioId) {
      setIsLoadingActions(false);
      return;
    }
    let cancelled = false;
    const load = async () => {
      setIsLoadingActions(true);
      try {
        const list = await api.remediationActions.list(scenarioId);
        if (!cancelled) setActions(list);
      } catch (err) {
        if (!cancelled) setActionsError(err instanceof Error ? err.message : 'Failed to load remediation actions');
      } finally {
        if (!cancelled) setIsLoadingActions(false);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [scenarioId]);

  const toggle = (id: string) => {
    setSelectedIds((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));
  };

  const run = async () => {
    if (!scenarioId || selectedIds.length === 0) return;
    setIsRunning(true);
    setRunError(null);
    try {
      const r = await api.simulation.run(scenarioId, {
        remediation_action_ids: selectedIds,
        max_depth: maxDepth,
        max_paths: maxPaths,
      });
      setResult(r);
    } catch (err) {
      setRunError(err instanceof Error ? err.message : 'Simulation failed');
      setResult(null);
    } finally {
      setIsRunning(false);
    }
  };

  if (!selectedScenario) {
    return (
      <div className="space-y-6">
        <PageHeader title="Remediation Simulation" />
        <Card><CardBody><EmptyState title="No Scenario Selected" description="Select a scenario from the header to simulate remediations." /></CardBody></Card>
      </div>
    );
  }

  const highlight: Highlight = result
    ? { nodes: new Set(result.remediated_findings), edges: new Set() }
    : EMPTY_HIGHLIGHT;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Remediation Simulation"
        description={`What changes if these fixes are applied? Runs on an immutable copy of the baseline in ${selectedScenario.name} — the backend computes every number.`}
      />

      <Toolbar>
        <Input label="Max depth" type="number" min={0} value={maxDepth} onChange={(e) => setMaxDepth(Math.max(0, Number(e.target.value)))} className="w-28" />
        <Input label="Max paths" type="number" min={1} value={maxPaths} onChange={(e) => setMaxPaths(Math.max(1, Number(e.target.value)))} className="w-28" />
        <Button variant="primary" onClick={run} loading={isRunning} disabled={selectedIds.length === 0}>
          Simulate ({selectedIds.length})
        </Button>
        <Button
          variant="secondary"
          disabled={selectedIds.length === 0}
          onClick={() => navigate(`/explanation?type=simulation&actions=${selectedIds.map(encodeURIComponent).join(',')}`)}
        >
          Explain
        </Button>
      </Toolbar>

      {isLoadingActions ? (
        <PageLoading message="Loading remediation actions..." />
      ) : actionsError ? (
        <Card><CardBody><ErrorState title="Failed to Load Actions" description={actionsError} /></CardBody></Card>
      ) : actions.length === 0 ? (
        <Card><CardBody><EmptyState title="No Remediation Actions" description="This scenario has no remediation actions defined, so there is nothing to simulate." /></CardBody></Card>
      ) : (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <h2 className="section-title">Available Actions ({actions.length})</h2>
              {selectedIds.length > 0 && (
                <Button variant="ghost" size="sm" onClick={() => setSelectedIds([])}>Clear selection</Button>
              )}
            </div>
          </CardHeader>
          <CardBody className="p-0">
            <div className="table-container max-h-[420px] overflow-y-auto">
              <table className="table">
                <thead>
                  <tr>
                    <th><span className="sr-only">Select</span></th>
                    <th>Action</th>
                    <th>Type</th>
                    <th>Target</th>
                    <th>Cost</th>
                    <th>Complexity</th>
                    <th>Downtime</th>
                    <th>Support</th>
                  </tr>
                </thead>
                <tbody>
                  {actions.map((a) => {
                    const checked = selectedIds.includes(a.id);
                    const supported = isSupported(a);
                    return (
                      <tr key={a.id} className={checked ? 'row-selected' : undefined}>
                        <td>
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={() => toggle(a.id)}
                            aria-label={`Select action ${a.id}`}
                            className="h-4 w-4 accent-cyan-400"
                          />
                        </td>
                        <td>
                          <p className="font-medium">{a.title}</p>
                          <p className="font-mono text-xs text-[var(--color-text-muted)]">{a.id}</p>
                        </td>
                        <td><Badge variant="default">{a.action_type}</Badge></td>
                        <td className="font-mono text-xs">{targetLabel(a)}</td>
                        <td className="font-mono">{num(a.estimated_cost)}</td>
                        <td><Badge variant="default">{a.implementation_complexity}</Badge></td>
                        <td>{a.downtime_required ? <Badge variant="warning">Yes</Badge> : <Badge variant="none">No</Badge>}</td>
                        <td>
                          {supported ? (
                            <Badge variant="success">Supported</Badge>
                          ) : (
                            <Badge
                              variant="critical"
                              title={(DEFERRED_ACTION_TYPES as string[]).includes(a.action_type) ? 'Deferred by backend — simulation will reject it' : 'Unknown action type'}
                            >
                              Deferred
                            </Badge>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardBody>
        </Card>
      )}

      {runError && (
        <Card><CardBody><ErrorState title="Simulation Failed" description={runError} action={<Button variant="primary" size="sm" onClick={run}>Retry</Button>} /></CardBody></Card>
      )}

      {result && (
        <div className="space-y-6">
          <div className="flex flex-wrap items-center gap-2 text-sm text-[var(--color-text-secondary)]">
            <Badge variant="default">Baseline</Badge>
            <span aria-hidden="true">→</span>
            <Badge variant="info">{result.steps.length} action{result.steps.length === 1 ? '' : 's'} applied</Badge>
            <span aria-hidden="true">→</span>
            <Badge variant="success">Simulated state</Badge>
            <span className="ml-2 font-mono text-xs text-[var(--color-text-muted)] break-all">
              {result.steps.map((st) => st.action.action_id).join(', ')}
            </span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <DeltaStat label="Attack paths" before={result.baseline.total_attack_paths} after={result.final.total_attack_paths} />
            <DeltaStat label="Crown-jewel paths" before={result.baseline.crown_jewel_path_count} after={result.final.crown_jewel_path_count} />
            <DeltaStat label="Blast affected assets" before={result.baseline.blast_affected_assets} after={result.final.blast_affected_assets} />
            <DeltaStat label="Prioritized findings" before={result.baseline.prioritization_count} after={result.final.prioritization_count} />
          </div>

          <Card>
            <CardHeader><h2 className="section-title">Remediated Findings ({result.remediated_findings.length})</h2></CardHeader>
            <CardBody>
              {result.remediated_findings.length === 0 ? (
                <p className="text-sm text-[var(--color-text-muted)]">No findings fully remediated (e.g. asset isolation leaves hosted findings in place).</p>
              ) : (
                <div className="flex flex-wrap gap-1.5">
                  {result.remediated_findings.map((id) => (
                    <Badge key={id} variant="success">{id}</Badge>
                  ))}
                </div>
              )}
              {graph && result.remediated_findings.length > 0 && (
                <div className="mt-4">
                  <p className="text-xs text-[var(--color-text-muted)] mb-2">Remediated finding nodes highlighted on the baseline graph:</p>
                  <CytoscapeCanvas graph={graph} highlight={highlight} />
                </div>
              )}
            </CardBody>
          </Card>

          <Card>
            <CardHeader><h2 className="section-title">Overall Metric Deltas</h2></CardHeader>
            <CardBody className="p-0"><DeltaTable deltas={result.overall_deltas} /></CardBody>
          </Card>

          {result.steps.map((step, i) => (
            <Card key={step.action.action_id}>
              <CardHeader>
                <h2 className="section-title">
                  Step {i + 1}: {step.action.action_id}
                  <span className="ml-2 font-mono text-xs text-[var(--color-text-muted)]">
                    {step.action.action_type} → {step.action.target_type} {step.action.target_id}
                  </span>
                </h2>
              </CardHeader>
              <CardBody className="p-0"><DeltaTable deltas={step.incremental_deltas} /></CardBody>
            </Card>
          ))}

          <Card>
            <CardHeader><h2 className="section-title">Finding Rank Comparison</h2></CardHeader>
            <CardBody className="p-0"><RankTable rows={result.overall_rank_comparison} /></CardBody>
          </Card>
        </div>
      )}
    </div>
  );
}

function DeltaStat({ label, before, after }: { label: string; before: number; after: number }) {
  const improved = after < before;
  const worsened = after > before;
  return (
    <div className="card p-4">
      <p className="text-xs font-medium uppercase tracking-wider text-[var(--color-text-muted)]">{label}</p>
      <p className="mt-2 flex items-baseline gap-2 font-mono tabular-nums">
        <span className="text-lg text-[var(--color-text-muted)]">{before}</span>
        <span className="text-[var(--color-text-muted)]" aria-hidden="true">→</span>
        <span
          className={`text-2xl font-semibold ${
            improved ? 'text-[var(--color-success)]' : worsened ? 'text-[var(--color-danger)]' : 'text-[var(--color-text-primary)]'
          }`}
        >
          {after}
        </span>
      </p>
      <p className="mt-1 text-xs text-[var(--color-text-secondary)]">
        {improved ? 'Reduced' : worsened ? 'Increased' : 'No change'} (baseline → simulated)
      </p>
    </div>
  );
}

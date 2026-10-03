import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useScenario } from '../../context/ScenarioContext';
import { api } from '../../services/api';
import type {
  OptimizationResponse,
  RemediationActionResponse,
} from '../../types/api';
import { MAX_CANDIDATE_ACTIONS } from '../../types/api';
import { Card, CardHeader, CardBody, Badge, Button, Input, PageHeader, Toolbar, StatCard } from '../../components/ui';
import { EmptyState, ErrorState, PageLoading } from '../../components/ui';
import { useScenarioGraph } from '../graph/useScenarioGraph';
import { CytoscapeCanvas, type Highlight } from '../graph/CytoscapeCanvas';
import { DeltaTable, RankTable, num } from '../remediation/resultTables';

const REASON_LABELS: Record<string, string> = {
  optimal_selection: 'Optimal selection found by exact enumeration.',
  zero_path_baseline: 'No attack paths in the baseline — nothing to improve.',
  all_infeasible: 'Every candidate subset failed validation.',
  all_exceed_budget: 'Every candidate subset exceeds the budget.',
  no_positive_improvement: 'No subset improves on the baseline.',
};

export function OptimizationPage() {
  const navigate = useNavigate();
  const { selectedScenario } = useScenario();
  const scenarioId = selectedScenario?.id;
  const { data: graph } = useScenarioGraph(scenarioId);

  const [actions, setActions] = useState<RemediationActionResponse[]>([]);
  const [isLoadingActions, setIsLoadingActions] = useState(true);
  const [actionsError, setActionsError] = useState<string | null>(null);
  const [candidateIds, setCandidateIds] = useState<string[]>([]);
  const [budget, setBudget] = useState(10);
  const [maxDepth, setMaxDepth] = useState(10);
  const [maxPaths, setMaxPaths] = useState(100);
  const [result, setResult] = useState<OptimizationResponse | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [clientError, setClientError] = useState<string | null>(null);

  // Clear stale state when scenario changes.
  useEffect(() => {
    setActions([]);
    setCandidateIds([]);
    setResult(null);
    setRunError(null);
    setClientError(null);
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
    setClientError(null);
    setCandidateIds((prev) => {
      if (prev.includes(id)) return prev.filter((x) => x !== id);
      if (prev.length >= MAX_CANDIDATE_ACTIONS) {
        setClientError(`At most ${MAX_CANDIDATE_ACTIONS} candidate actions are supported for exact enumeration.`);
        return prev;
      }
      return [...prev, id];
    });
  };

  const run = async () => {
    if (!scenarioId || candidateIds.length === 0) return;
    if (budget < 0) {
      setClientError('Budget must be >= 0.');
      return;
    }
    setIsRunning(true);
    setRunError(null);
    try {
      const r = await api.optimization.run(scenarioId, {
        candidate_action_ids: candidateIds,
        budget,
        max_depth: maxDepth,
        max_paths: maxPaths,
      });
      setResult(r);
    } catch (err) {
      setRunError(err instanceof Error ? err.message : 'Optimization failed');
      setResult(null);
    } finally {
      setIsRunning(false);
    }
  };

  if (!selectedScenario) {
    return (
      <div className="space-y-6">
        <PageHeader title="Budget Optimization" />
        <Card><CardBody><EmptyState title="No Scenario Selected" description="Select a scenario from the header to optimize remediations." /></CardBody></Card>
      </div>
    );
  }

  const selectedTargets = new Set(
    (result?.candidates ?? [])
      .filter((c) => result?.selected_action_ids.includes(c.action_id))
      .map((c) => c.target_id),
  );
  const highlight: Highlight = result ? { nodes: selectedTargets, edges: new Set() } : { nodes: new Set(), edges: new Set() };

  return (
    <div className="space-y-6">
      <PageHeader
        title="Budget Optimization"
        description={`Best set of fixes within a budget for ${selectedScenario.name}. Exact subset enumeration; the backend ranks by crown-jewel paths removed (O1), then feasibility reduced (O2), then lowest cost.`}
      />

      <Toolbar>
        <Input label="Budget" type="number" min={0} step="any" value={budget} onChange={(e) => setBudget(Number(e.target.value))} className="w-32" />
        <Input label="Max depth" type="number" min={0} value={maxDepth} onChange={(e) => setMaxDepth(Math.max(0, Number(e.target.value)))} className="w-28" />
        <Input label="Max paths" type="number" min={1} value={maxPaths} onChange={(e) => setMaxPaths(Math.max(1, Number(e.target.value)))} className="w-28" />
        <Button variant="primary" onClick={run} loading={isRunning} disabled={candidateIds.length === 0}>
          Optimize ({candidateIds.length}/{MAX_CANDIDATE_ACTIONS})
        </Button>
        <Button
          variant="secondary"
          disabled={candidateIds.length === 0}
          onClick={() => navigate(`/explanation?type=optimization&candidates=${candidateIds.map(encodeURIComponent).join(',')}&budget=${budget}`)}
        >
          Explain
        </Button>
      </Toolbar>

      {clientError && (
        <Card><CardBody><p className="text-sm text-[var(--color-danger)]" role="alert">{clientError}</p></CardBody></Card>
      )}

      {isLoadingActions ? (
        <PageLoading message="Loading candidate actions..." />
      ) : actionsError ? (
        <Card><CardBody><ErrorState title="Failed to Load Actions" description={actionsError} /></CardBody></Card>
      ) : actions.length === 0 ? (
        <Card><CardBody><EmptyState title="No Remediation Actions" description="This scenario has no remediation actions defined, so there is nothing to optimize." /></CardBody></Card>
      ) : (
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <h2 className="section-title">Candidate Actions ({actions.length})</h2>
              {candidateIds.length > 0 && (
                <Button variant="ghost" size="sm" onClick={() => setCandidateIds([])}>Clear selection</Button>
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
                    <th>Cost</th>
                  </tr>
                </thead>
                <tbody>
                  {actions.map((a) => {
                    const checked = candidateIds.includes(a.id);
                    return (
                      <tr key={a.id} className={checked ? 'row-selected' : undefined}>
                        <td>
                          <input
                            type="checkbox"
                            checked={checked}
                            onChange={() => toggle(a.id)}
                            aria-label={`Select candidate ${a.id}`}
                            className="h-4 w-4 accent-cyan-400"
                          />
                        </td>
                        <td>
                          <p className="font-medium">{a.title}</p>
                          <p className="font-mono text-xs text-[var(--color-text-muted)]">{a.id}</p>
                        </td>
                        <td><Badge variant="default">{a.action_type}</Badge></td>
                        <td className="font-mono">{num(a.estimated_cost)}</td>
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
        <Card><CardBody><ErrorState title="Optimization Failed" description={runError} action={<Button variant="primary" size="sm" onClick={run}>Retry</Button>} /></CardBody></Card>
      )}

      {result && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
            <StatCard label="Budget" value={num(result.budget)} tone="neutral" />
            <StatCard label="Total cost" value={num(result.selected_total_cost)} hint={result.within_budget ? 'Within budget' : 'Over budget'} tone={result.within_budget ? 'success' : 'danger'} />
            <StatCard label="Objective O1" value={num(result.objective_o1)} hint="Crown-jewel paths" />
            <StatCard label="Objective O2" value={num(result.objective_o2)} hint="Feasibility reduced" />
            <StatCard label="Subsets evaluated" value={result.evaluated_subset_count} tone="neutral" />
            <StatCard label="Selected actions" value={result.selected_action_ids.length} tone="success" />
          </div>

          <Card>
            <CardHeader>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <h2 className="section-title">Selected Actions</h2>
                <Badge variant={result.selection_reason === 'optimal_selection' ? 'success' : 'warning'}>
                  {result.selection_reason}
                </Badge>
              </div>
            </CardHeader>
            <CardBody>
              <p className="text-sm text-[var(--color-text-secondary)]">
                {REASON_LABELS[result.selection_reason] ?? result.selection_reason}
              </p>
              <p className="mt-1 text-xs text-[var(--color-text-muted)]">
                Objective: <span className="font-mono">{result.objective}</span> — exact enumeration,{' '}
                {result.infeasible_subset_count} infeasible / {result.over_budget_subset_count} over budget.
              </p>
              {result.selected_action_ids.length === 0 ? (
                <p className="mt-4 text-sm text-[var(--color-text-muted)]">Empty selection — baseline state retained.</p>
              ) : (
                <div className="mt-4 table-container rounded-lg border border-[var(--color-border-primary)]">
                  <table className="table">
                    <thead><tr><th>Action</th><th>Type</th><th>Cost</th></tr></thead>
                    <tbody>
                      {result.selected_action_ids.map((id) => {
                        const a = actions.find((x) => x.id === id);
                        return (
                          <tr key={id}>
                            <td>
                              <p className="font-medium">{a?.title ?? id}</p>
                              <p className="font-mono text-xs text-[var(--color-text-muted)]">{id}</p>
                            </td>
                            <td>{a ? <Badge variant="default">{a.action_type}</Badge> : '—'}</td>
                            <td className="font-mono">{a ? num(a.estimated_cost) : '—'}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
              {graph && result.selected_action_ids.length > 0 && (
                <div className="mt-4">
                  <p className="text-xs text-[var(--color-text-muted)] mb-2">Selected-action targets highlighted on the baseline graph:</p>
                  <CytoscapeCanvas graph={graph} highlight={highlight} />
                </div>
              )}
            </CardBody>
          </Card>

          {result.reported_infeasible_subsets.length > 0 && (
            <Card>
              <CardHeader><h2 className="section-title">Infeasible Subsets ({result.reported_infeasible_subsets.length} reported)</h2></CardHeader>
              <CardBody className="p-0">
                <div className="table-container max-h-[280px] overflow-y-auto">
                  <table className="table">
                    <thead><tr><th>Subset</th><th>Reason</th></tr></thead>
                    <tbody>
                      {result.reported_infeasible_subsets.map((s, i) => (
                        <tr key={i}>
                          <td className="font-mono text-xs">{s.action_ids.join(', ')}</td>
                          <td className="text-sm">{s.reason}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardBody>
            </Card>
          )}

          <Card>
            <CardHeader><h2 className="section-title">Overall Metric Deltas</h2></CardHeader>
            <CardBody className="p-0"><DeltaTable deltas={result.overall_deltas} /></CardBody>
          </Card>

          <Card>
            <CardHeader><h2 className="section-title">Finding Rank Comparison</h2></CardHeader>
            <CardBody className="p-0"><RankTable rows={result.overall_rank_comparison} /></CardBody>
          </Card>
        </div>
      )}
    </div>
  );
}

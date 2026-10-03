import { useEffect, useState } from 'react';
import { useScenario } from '../../context/ScenarioContext';
import { api } from '../../services/api';
import type { AttackPathMode, AttackPathResponse } from '../../types/api';
import { Card, CardHeader, CardBody, Badge, Button, Select, Input, PageHeader, Toolbar } from '../../components/ui';
import { EmptyState, ErrorState, PageLoading } from '../../components/ui';
import { useScenarioGraph } from '../graph/useScenarioGraph';
import { CytoscapeCanvas, EMPTY_HIGHLIGHT, type Highlight } from '../graph/CytoscapeCanvas';
import { SelectionDetails } from '../graph/SelectionDetails';

export function AttackPathsPage() {
  const { selectedScenario } = useScenario();
  const scenarioId = selectedScenario?.id;
  const { data: graph, isLoading: graphLoading, error: graphError, retry: retryGraph } = useScenarioGraph(scenarioId);

  const [mode, setMode] = useState<AttackPathMode>('all');
  const [maxDepth, setMaxDepth] = useState(10);
  const [maxPaths, setMaxPaths] = useState(100);
  const [paths, setPaths] = useState<AttackPathResponse[]>([]);
  const [pathsLoading, setPathsLoading] = useState(false);
  const [pathsError, setPathsError] = useState<string | null>(null);
  const [queryKey, setQueryKey] = useState(0);
  const [selectedPathId, setSelectedPathId] = useState<string | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);

  // Clear stale analysis selection when scenario changes.
  useEffect(() => {
    setPaths([]);
    setPathsError(null);
    setSelectedPathId(null);
    setSelectedNodeId(null);
    setSelectedEdgeId(null);
  }, [scenarioId]);

  useEffect(() => {
    if (!scenarioId) return;
    let cancelled = false;
    const load = async () => {
      setPathsLoading(true);
      setPathsError(null);
      try {
        const result = await api.attackPaths.get(scenarioId, {
          path_mode: mode,
          max_depth: maxDepth,
          max_paths: maxPaths,
        });
        if (!cancelled) {
          setPaths(result);
          setSelectedPathId(null);
        }
      } catch (err) {
        if (!cancelled) setPathsError(err instanceof Error ? err.message : 'Failed to load attack paths');
      } finally {
        if (!cancelled) setPathsLoading(false);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scenarioId, queryKey]);

  if (!selectedScenario) {
    return (
      <div className="space-y-6">
        <PageHeader title="Attack Paths" />
        <Card><CardBody><EmptyState title="No Scenario Selected" description="Select a scenario from the header to explore attack paths." /></CardBody></Card>
      </div>
    );
  }

  const selectedPath = paths.find((p) => p.id === selectedPathId) ?? null;
  const highlight: Highlight = selectedPath
    ? { nodes: new Set(selectedPath.nodes), edges: new Set(selectedPath.edges) }
    : EMPTY_HIGHLIGHT;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Attack Paths"
        description={
          pathsLoading
            ? 'Loading…'
            : `${paths.length} path${paths.length === 1 ? '' : 's'} from entry points to crown jewels in ${selectedScenario.name}`
        }
      />

      <Toolbar>
        <Select
          label="Mode"
          value={mode}
          onValueChange={(value) => setMode(value as AttackPathMode)}
          options={[
            { value: 'all', label: 'All paths' },
            { value: 'shortest', label: 'Shortest' },
            { value: 'cheapest', label: 'Cheapest' },
          ]}
          className="w-40"
        />
        <Input
          label="Max depth"
          type="number"
          min={0}
          value={maxDepth}
          onChange={(e) => setMaxDepth(Math.max(0, Number(e.target.value)))}
          className="w-28"
        />
        <Input
          label="Max paths"
          type="number"
          min={1}
          value={maxPaths}
          onChange={(e) => setMaxPaths(Math.max(1, Number(e.target.value)))}
          className="w-28"
        />
        <Button variant="primary" onClick={() => setQueryKey((k) => k + 1)} loading={pathsLoading}>
          Run analysis
        </Button>
      </Toolbar>

      {graphLoading ? (
        <PageLoading message="Loading security graph..." />
      ) : graphError || !graph ? (
        <Card><CardBody><ErrorState title="Failed to Load Graph" description={graphError ?? 'Unknown error'} action={<Button variant="primary" onClick={retryGraph}>Retry</Button>} /></CardBody></Card>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 items-start">
          <Card className="xl:col-span-2">
            <CardHeader><h2 className="section-title">Security Graph</h2></CardHeader>
            <CardBody>
              <CytoscapeCanvas
                graph={graph}
                highlight={highlight}
                selectedNodeId={selectedNodeId}
                selectedEdgeId={selectedEdgeId}
                onNodeSelect={(id) => { setSelectedNodeId(id); if (id) setSelectedEdgeId(null); }}
                onEdgeSelect={(id) => { setSelectedEdgeId(id); if (id) setSelectedNodeId(null); }}
              />
              <div className="mt-4">
                <SelectionDetails
                  graph={graph}
                  nodeId={selectedNodeId}
                  edgeId={selectedEdgeId}
                  onClose={() => { setSelectedNodeId(null); setSelectedEdgeId(null); }}
                />
              </div>
            </CardBody>
          </Card>

          <Card>
            <CardHeader><h2 className="section-title">Paths</h2></CardHeader>
            <CardBody className="p-0">
              {pathsLoading ? (
                <p className="p-6 text-sm text-[var(--color-text-muted)]">Loading paths…</p>
              ) : pathsError ? (
                <div className="p-6"><ErrorState title="Failed to Load Paths" description={pathsError} action={<Button variant="primary" size="sm" onClick={() => setQueryKey((k) => k + 1)}>Retry</Button>} /></div>
              ) : paths.length === 0 ? (
                <div className="p-6"><EmptyState title="No Attack Paths" description="No entry-point to crown-jewel paths exist for this scenario and depth. This is a valid result, not an error." /></div>
              ) : (
                <ul className="p-3 space-y-3 max-h-[640px] overflow-y-auto">
                  {paths.map((p, i) => {
                    const active = p.id === selectedPathId;
                    const pct = Math.max(2, Math.min(100, p.total_probability * 100));
                    return (
                      <li key={p.id}>
                        <button
                          type="button"
                          onClick={() => setSelectedPathId(active ? null : p.id)}
                          aria-pressed={active}
                          className={`w-full text-left rounded-xl border p-4 transition-all hover:border-[var(--color-accent)] ${
                            active
                              ? 'border-[var(--color-accent)] bg-[var(--color-accent-bg)] shadow-lg'
                              : 'border-[var(--color-border-primary)] bg-[var(--color-bg-secondary)]'
                          }`}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-sm font-semibold">Path {i + 1}</span>
                            <Badge variant="default">{p.hop_count} {p.hop_count === 1 ? 'hop' : 'hops'}</Badge>
                          </div>

                          <div className="flex items-center gap-2 mt-3 text-xs font-mono">
                            <span className="px-2 py-1 rounded-md bg-[#10281d] text-[#bbf7d0] border border-[#4ade80]/40 truncate">{p.entry_point}</span>
                            <span className="text-[var(--color-text-muted)]" aria-hidden="true">→</span>
                            <span className="px-2 py-1 rounded-md bg-[#33270c] text-[#fef3c7] border border-[#fbbf24]/40 truncate">{p.crown_jewel}</span>
                          </div>

                          <div className="grid grid-cols-2 gap-4 mt-4">
                            <div>
                              <p className="text-[11px] uppercase tracking-wide text-muted">Attacker cost</p>
                              <p className="font-mono text-base mt-0.5">{p.total_traversal_cost.toFixed(2)}</p>
                            </div>
                            <div>
                              <p className="text-[11px] uppercase tracking-wide text-muted">Success probability</p>
                              <p className="font-mono text-base mt-0.5">{(p.total_probability * 100).toFixed(1)}%</p>
                              <div className="h-1.5 mt-1.5 rounded-full bg-[var(--color-bg-tertiary)] overflow-hidden">
                                <div className="h-full rounded-full bg-[var(--color-danger)]" style={{ width: `${pct}%` }} />
                              </div>
                            </div>
                          </div>

                          {active && (
                            <p className="font-mono text-xs text-[var(--color-text-secondary)] mt-4 pt-3 border-t border-[var(--color-border-primary)] leading-relaxed break-words">
                              {p.nodes.join(' → ')}
                            </p>
                          )}
                        </button>
                      </li>
                    );
                  })}
                </ul>
              )}
            </CardBody>
          </Card>
        </div>
      )}
    </div>
  );
}

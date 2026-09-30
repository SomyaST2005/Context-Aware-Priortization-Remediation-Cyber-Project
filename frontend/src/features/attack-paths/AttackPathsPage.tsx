import { useEffect, useState } from 'react';
import { useScenario } from '../../context/ScenarioContext';
import { api } from '../../services/api';
import type { AttackPathMode, AttackPathResponse } from '../../types/api';
import { Card, CardHeader, CardBody, Badge, Button, Select, Input } from '../../components/ui';
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
        <h1 className="page-title">Attack Paths</h1>
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
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="page-title">Attack Paths</h1>
          <p className="text-muted text-sm mt-1">
            {pathsLoading ? 'Loading…' : `${paths.length} path${paths.length === 1 ? '' : 's'} in ${selectedScenario.name}`}
          </p>
        </div>
        <div className="flex flex-wrap items-end gap-3">
          <Select
            label="Mode"
            value={mode}
            onChange={(e) => setMode(e.target.value as AttackPathMode)}
            options={[
              { value: 'all', label: 'All paths' },
              { value: 'shortest', label: 'Shortest' },
              { value: 'cheapest', label: 'Cheapest' },
            ]}
            className="w-36"
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
            Run
          </Button>
        </div>
      </div>

      {graphLoading ? (
        <PageLoading message="Loading security graph..." />
      ) : graphError || !graph ? (
        <Card><CardBody><ErrorState title="Failed to Load Graph" description={graphError ?? 'Unknown error'} action={<Button variant="primary" onClick={retryGraph}>Retry</Button>} /></CardBody></Card>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
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
                <ul className="divide-y divide-[var(--color-border-primary)] max-h-[560px] overflow-y-auto">
                  {paths.map((p) => {
                    const active = p.id === selectedPathId;
                    return (
                      <li key={p.id}>
                        <button
                          type="button"
                          onClick={() => setSelectedPathId(active ? null : p.id)}
                          aria-pressed={active}
                          className={`w-full text-left px-4 py-3 transition-colors hover:bg-[var(--color-bg-tertiary)] ${active ? 'bg-[var(--color-accent-bg)]' : ''}`}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-mono text-sm font-semibold">{p.id}</span>
                            <Badge variant="default">{p.hop_count} hops</Badge>
                          </div>
                          <p className="font-mono text-xs text-[var(--color-text-secondary)] mt-1 break-all">
                            {p.entry_point} → {p.crown_jewel}
                          </p>
                          <dl className="grid grid-cols-2 gap-x-3 gap-y-1 mt-2 text-xs">
                            <div className="flex justify-between"><dt className="text-muted">Cost</dt><dd className="font-mono">{p.total_traversal_cost.toFixed(2)}</dd></div>
                            <div className="flex justify-between"><dt className="text-muted">Prob</dt><dd className="font-mono">{p.total_probability.toFixed(3)}</dd></div>
                          </dl>
                          {active && (
                            <p className="font-mono text-xs text-[var(--color-text-muted)] mt-2 break-all">
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

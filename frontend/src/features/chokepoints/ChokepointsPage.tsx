import { useEffect, useState } from 'react';
import { useScenario } from '../../context/ScenarioContext';
import { api } from '../../services/api';
import type { ChokepointDetailResponse, ChokepointResponse } from '../../types/api';
import { Card, CardHeader, CardBody, Badge, Button, Select } from '../../components/ui';
import { EmptyState, ErrorState, PageLoading } from '../../components/ui';
import { useScenarioGraph } from '../graph/useScenarioGraph';
import { CytoscapeCanvas, EMPTY_HIGHLIGHT, type Highlight } from '../graph/CytoscapeCanvas';
import { SelectionDetails } from '../graph/SelectionDetails';

export function ChokepointsPage() {
  const { selectedScenario } = useScenario();
  const scenarioId = selectedScenario?.id;
  const { data: graph, isLoading: graphLoading, error: graphError, retry: retryGraph } = useScenarioGraph(scenarioId);

  const [entityType, setEntityType] = useState<'all' | 'asset' | 'finding'>('all');
  const [data, setData] = useState<ChokepointResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [retryKey, setRetryKey] = useState(0);
  const [selected, setSelected] = useState<ChokepointDetailResponse | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);

  // Clear stale selection when scenario changes.
  useEffect(() => {
    setData(null);
    setError(null);
    setSelected(null);
    setSelectedNodeId(null);
    setSelectedEdgeId(null);
  }, [scenarioId]);

  useEffect(() => {
    if (!scenarioId) {
      setIsLoading(false);
      return;
    }
    let cancelled = false;
    const load = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await api.chokepoints.get(scenarioId, { entity_type: entityType });
        if (!cancelled) {
          setData(result);
          setSelected(null);
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load chokepoints');
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [scenarioId, entityType, retryKey]);

  if (!selectedScenario) {
    return (
      <div className="space-y-6">
        <h1 className="page-title">Chokepoints</h1>
        <Card><CardBody><EmptyState title="No Scenario Selected" description="Select a scenario from the header to analyze chokepoints." /></CardBody></Card>
      </div>
    );
  }

  const highlight: Highlight = selected
    ? { nodes: new Set([selected.entity_id]), edges: new Set() }
    : EMPTY_HIGHLIGHT;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="page-title">Chokepoints</h1>
          <p className="text-muted text-sm mt-1">
            Bottleneck entities by backend chokepoint score in {selectedScenario.name}
          </p>
        </div>
        <div className="flex flex-wrap items-end gap-3">
          <Select
            label="Entity type"
            value={entityType}
            onChange={(e) => setEntityType(e.target.value as 'all' | 'asset' | 'finding')}
            options={[
              { value: 'all', label: 'All' },
              { value: 'asset', label: 'Assets' },
              { value: 'finding', label: 'Findings' },
            ]}
            className="w-40"
          />
          <Button variant="secondary" size="sm" onClick={() => setRetryKey((k) => k + 1)}>
            Refresh
          </Button>
        </div>
      </div>

      {graphLoading || isLoading ? (
        <PageLoading message="Loading graph and chokepoints..." />
      ) : graphError || !graph ? (
        <Card><CardBody><ErrorState title="Failed to Load Graph" description={graphError ?? 'Unknown error'} action={<Button variant="primary" onClick={retryGraph}>Retry</Button>} /></CardBody></Card>
      ) : error || !data ? (
        <Card><CardBody><ErrorState title="Failed to Load Chokepoints" description={error ?? 'Unknown error'} action={<Button variant="primary" onClick={() => setRetryKey((k) => k + 1)}>Retry</Button>} /></CardBody></Card>
      ) : (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <Card><CardBody><p className="text-2xl font-semibold font-mono">{data.total_entities_analyzed}</p><p className="text-sm text-[var(--color-text-secondary)]">Entities analyzed</p></CardBody></Card>
            <Card><CardBody><p className="text-2xl font-semibold font-mono">{data.max_chokepoint_score.toFixed(3)}</p><p className="text-sm text-[var(--color-text-secondary)]">Max chokepoint score</p></CardBody></Card>
            <Card><CardBody><p className="text-2xl font-semibold font-mono">{data.total_attack_paths_analyzed}</p><p className="text-sm text-[var(--color-text-muted)]">Attack paths analyzed</p></CardBody></Card>
          </div>

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
              <CardHeader><h2 className="section-title">Ranked Entities</h2></CardHeader>
              <CardBody className="p-0">
                {data.chokepoints.length === 0 ? (
                  <div className="p-6"><EmptyState title="No Chokepoints" description="No attack paths exist to analyze, so no chokepoints were found. Valid empty result." /></div>
                ) : (
                  <ul className="divide-y divide-[var(--color-border-primary)] max-h-[560px] overflow-y-auto">
                    {data.chokepoints.map((c) => {
                      const active = selected?.entity_id === c.entity_id;
                      return (
                        <li key={c.entity_id}>
                          <button
                            type="button"
                            onClick={() => {
                              setSelected(active ? null : c);
                              setSelectedNodeId(active ? null : c.entity_id);
                              setSelectedEdgeId(null);
                            }}
                            aria-pressed={active}
                            className={`w-full text-left px-4 py-3 transition-colors hover:bg-[var(--color-bg-tertiary)] ${active ? 'bg-[var(--color-accent-bg)]' : ''}`}
                          >
                            <div className="flex items-center justify-between gap-2">
                              <span className="font-mono text-sm break-all">{c.entity_id}</span>
                              <Badge variant={c.entity_type === 'asset' ? 'default' : 'warning'}>{c.entity_type}</Badge>
                            </div>
                            <dl className="grid grid-cols-3 gap-x-3 gap-y-1 mt-2 text-xs">
                              <div className="flex justify-between"><dt className="text-muted">Score</dt><dd className="font-mono font-semibold">{c.chokepoint_score.toFixed(3)}</dd></div>
                              <div className="flex justify-between"><dt className="text-muted">RWPC</dt><dd className="font-mono">{c.path_feasibility_criticality.toFixed(3)}</dd></div>
                              <div className="flex justify-between"><dt className="text-muted">Paths</dt><dd className="font-mono">{c.path_count}</dd></div>
                            </dl>
                            {active && (
                              <dl className="grid grid-cols-2 gap-x-3 gap-y-1 mt-2 text-xs border-t border-[var(--color-border-primary)] pt-2">
                                <div className="flex justify-between"><dt className="text-muted">Entry points</dt><dd className="font-mono">{c.unique_entry_points}</dd></div>
                                <div className="flex justify-between"><dt className="text-muted">Crown jewels</dt><dd className="font-mono">{c.unique_crown_jewels}</dd></div>
                                <div className="flex justify-between"><dt className="text-muted">Depth</dt><dd className="font-mono">{c.min_path_depth}–{c.max_path_depth}</dd></div>
                              </dl>
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
        </>
      )}
    </div>
  );
}

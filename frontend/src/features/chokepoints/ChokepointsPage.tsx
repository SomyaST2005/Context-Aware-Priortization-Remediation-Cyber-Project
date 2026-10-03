import { useEffect, useState } from 'react';
import { GitBranch, Link2 } from 'lucide-react';
import { useScenario } from '../../context/ScenarioContext';
import { api } from '../../services/api';
import type { ChokepointDetailResponse, ChokepointResponse } from '../../types/api';
import { Card, CardHeader, CardBody, Badge, Button, Select, PageHeader, Toolbar, StatCard } from '../../components/ui';
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
        <PageHeader title="Chokepoints" />
        <Card><CardBody><EmptyState title="No Scenario Selected" description="Select a scenario from the header to analyze chokepoints." /></CardBody></Card>
      </div>
    );
  }

  const highlight: Highlight = selected
    ? { nodes: new Set([selected.entity_id]), edges: new Set() }
    : EMPTY_HIGHLIGHT;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Chokepoints"
        description={`Which entities sit on many attack paths? Fixing one of these cuts the most routes. Scenario: ${selectedScenario.name}`}
      />

      <Toolbar>
        <Select
          label="Entity type"
          value={entityType}
          onValueChange={(value) => setEntityType(value as 'all' | 'asset' | 'finding')}
          options={[
            { value: 'all', label: 'All' },
            { value: 'asset', label: 'Assets' },
            { value: 'finding', label: 'Findings' },
          ]}
          className="w-40"
        />
        <Button variant="secondary" onClick={() => setRetryKey((k) => k + 1)}>
          Refresh
        </Button>
      </Toolbar>

      {graphLoading || isLoading ? (
        <PageLoading message="Loading graph and chokepoints..." />
      ) : graphError || !graph ? (
        <Card><CardBody><ErrorState title="Failed to Load Graph" description={graphError ?? 'Unknown error'} action={<Button variant="primary" onClick={retryGraph}>Retry</Button>} /></CardBody></Card>
      ) : error || !data ? (
        <Card><CardBody><ErrorState title="Failed to Load Chokepoints" description={error ?? 'Unknown error'} action={<Button variant="primary" onClick={() => setRetryKey((k) => k + 1)}>Retry</Button>} /></CardBody></Card>
      ) : (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <StatCard label="Entities analyzed" value={data.total_entities_analyzed} icon={<Link2 className="w-4 h-4" />} tone="neutral" />
            <StatCard label="Max chokepoint score" value={data.max_chokepoint_score.toFixed(3)} hint="Higher = more attack paths pass through it" icon={<Link2 className="w-4 h-4" />} tone="warning" />
            <StatCard label="Attack paths analyzed" value={data.total_attack_paths_analyzed} icon={<GitBranch className="w-4 h-4" />} />
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
                            <div className="h-1.5 mt-2 rounded-full bg-[var(--color-bg-tertiary)] overflow-hidden" aria-hidden="true">
                              <div className="h-full rounded-full bg-[var(--color-warning)]" style={{ width: `${Math.max(2, Math.min(1, c.chokepoint_score) * 100)}%` }} />
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

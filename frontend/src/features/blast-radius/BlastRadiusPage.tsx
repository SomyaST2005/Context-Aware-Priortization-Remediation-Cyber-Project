import { useEffect, useState } from 'react';
import { useScenario } from '../../context/ScenarioContext';
import { api } from '../../services/api';
import type { AssetResponse, BlastRadiusResponse } from '../../types/api';
import { Card, CardHeader, CardBody, Badge, Button, Select, Input } from '../../components/ui';
import { EmptyState, ErrorState, PageLoading } from '../../components/ui';
import { useScenarioGraph } from '../graph/useScenarioGraph';
import { CytoscapeCanvas, EMPTY_HIGHLIGHT, type Highlight } from '../graph/CytoscapeCanvas';
import { SelectionDetails } from '../graph/SelectionDetails';

export function BlastRadiusPage() {
  const { selectedScenario } = useScenario();
  const scenarioId = selectedScenario?.id;
  const { data: graph, isLoading: graphLoading, error: graphError, retry: retryGraph } = useScenarioGraph(scenarioId);

  const [assets, setAssets] = useState<AssetResponse[]>([]);
  const [sourceId, setSourceId] = useState('');
  const [maxDepth, setMaxDepth] = useState(10);
  const [result, setResult] = useState<BlastRadiusResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [queryKey, setQueryKey] = useState(0);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);

  // Clear stale analysis selection when scenario changes.
  useEffect(() => {
    setResult(null);
    setError(null);
    setSourceId('');
    setSelectedNodeId(null);
    setSelectedEdgeId(null);
  }, [scenarioId]);

  // Asset choices for the source selector.
  useEffect(() => {
    if (!scenarioId) {
      setAssets([]);
      return;
    }
    let cancelled = false;
    api.assets.list(scenarioId)
      .then((list) => {
        if (cancelled) return;
        setAssets(list);
        setSourceId((prev) => prev || list[0]?.id || '');
      })
      .catch(() => {
        if (!cancelled) setAssets([]);
      });
    return () => {
      cancelled = true;
    };
  }, [scenarioId]);

  useEffect(() => {
    if (!scenarioId || !sourceId || queryKey === 0) return;
    let cancelled = false;
    const load = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const r = await api.blastRadius.get(scenarioId, sourceId, maxDepth);
        if (!cancelled) setResult(r);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to compute blast radius');
          setResult(null);
        }
      } finally {
        if (!cancelled) setIsLoading(false);
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
        <h1 className="page-title">Blast Radius</h1>
        <Card><CardBody><EmptyState title="No Scenario Selected" description="Select a scenario from the header to analyze blast radius." /></CardBody></Card>
      </div>
    );
  }

  const highlight: Highlight = result
    ? { nodes: new Set(result.affected_assets), edges: new Set() }
    : EMPTY_HIGHLIGHT;

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="page-title">Blast Radius</h1>
          <p className="text-muted text-sm mt-1">
            Downstream reachability from a compromised asset in {selectedScenario.name}
          </p>
        </div>
        <div className="flex flex-wrap items-end gap-3">
          <Select
            label="Source asset"
            value={sourceId}
            onValueChange={(value) => setSourceId(value)}
            options={assets.map((a) => ({ value: a.id, label: `${a.name} (${a.id})` }))}
            placeholder={assets.length === 0 ? 'No assets' : 'Select asset'}
            disabled={assets.length === 0}
            className="w-64"
          />
          <Input
            label="Max depth"
            type="number"
            min={0}
            value={maxDepth}
            onChange={(e) => setMaxDepth(Math.max(0, Number(e.target.value)))}
            className="w-28"
          />
          <Button variant="primary" onClick={() => setQueryKey((k) => k + 1)} loading={isLoading} disabled={!sourceId}>
            Compute
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
            <CardHeader><h2 className="section-title">Result</h2></CardHeader>
            <CardBody>
              {isLoading ? (
                <p className="text-sm text-[var(--color-text-muted)]">Computing…</p>
              ) : error ? (
                <ErrorState title="Computation Failed" description={error} action={<Button variant="primary" size="sm" onClick={() => setQueryKey((k) => k + 1)}>Retry</Button>} />
              ) : !result ? (
                <EmptyState title="No Result Yet" description="Choose a source asset and press Compute." />
              ) : result.affected_asset_count === 0 ? (
                <EmptyState title="No Affected Assets" description={`Asset ${result.source_asset} reaches no other assets within depth ${result.max_depth_reached}. Valid empty result.`} />
              ) : (
                <div className="space-y-4">
                  <dl className="grid grid-cols-2 gap-3 text-sm">
                    <div><dt className="text-muted text-xs">Affected assets</dt><dd className="font-mono text-lg">{result.affected_asset_count}</dd></div>
                    <div><dt className="text-muted text-xs">Max depth reached</dt><dd className="font-mono text-lg">{result.max_depth_reached}</dd></div>
                  </dl>
                  <div>
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-muted)] mb-2">
                      Crown jewels reached ({result.crown_jewels_reached.length})
                    </h3>
                    {result.crown_jewels_reached.length === 0 ? (
                      <p className="text-sm text-[var(--color-text-muted)]">None.</p>
                    ) : (
                      <div className="flex flex-wrap gap-1.5">
                        {result.crown_jewels_reached.map((id) => (
                          <Badge key={id} variant="critical">{id}</Badge>
                        ))}
                      </div>
                    )}
                  </div>
                  <div>
                    <h3 className="text-xs font-semibold uppercase tracking-wider text-[var(--color-text-muted)] mb-2">
                      Reachability details
                    </h3>
                    <div className="table-container max-h-[320px] overflow-y-auto">
                      <table className="table">
                        <thead><tr><th>Asset</th><th>Depth</th><th>Min cost</th><th>Max prob</th></tr></thead>
                        <tbody>
                          {result.reachability_details.map((d) => (
                            <tr key={d.asset_id} className={d.asset_id === result.source_asset ? 'bg-[var(--color-accent-bg)]' : undefined}>
                              <td className="font-mono text-xs">{d.asset_id}</td>
                              <td className="font-mono">{d.depth}</td>
                              <td className="font-mono">{d.min_traversal_cost.toFixed(2)}</td>
                              <td className="font-mono">{d.max_probability.toFixed(3)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}
            </CardBody>
          </Card>
        </div>
      )}
    </div>
  );
}

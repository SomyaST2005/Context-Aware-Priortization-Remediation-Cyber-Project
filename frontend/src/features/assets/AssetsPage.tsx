import { useEffect, useState } from 'react';
import { useScenario } from '../../context/ScenarioContext';
import { api } from '../../services/api';
import type { AssetResponse } from '../../types/api';
import { Card, CardBody, Badge, Select, Button, PageHeader } from '../../components/ui';
import { EmptyState, ErrorState, PageLoading } from '../../components/ui';

export function AssetsPage() {
  const { selectedScenario } = useScenario();
  const [assets, setAssets] = useState<AssetResponse[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filterType, setFilterType] = useState<string>('all');
  const [filterZone, setFilterZone] = useState<string>('all');

  useEffect(() => {
    if (!selectedScenario) {
      setAssets([]);
      setIsLoading(false);
      return;
    }

    const loadAssets = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const data = await api.assets.list(selectedScenario.id);
        setAssets(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load assets');
      } finally {
        setIsLoading(false);
      }
    };

    loadAssets();
  }, [selectedScenario]);

  const filteredAssets = assets.filter((asset) => {
    const typeMatch = filterType === 'all' || asset.type === filterType;
    const zoneMatch = filterZone === 'all' || asset.network_zone === filterZone;
    return typeMatch && zoneMatch;
  });

  const types = Array.from(new Set(assets.map((a) => a.type))).sort();
  const zones = Array.from(new Set(assets.map((a) => a.network_zone))).sort();

  if (!selectedScenario) {
    return (
      <div className="space-y-6">
        <PageHeader title="Assets" />
        <Card>
          <CardBody>
            <EmptyState
              icon={
                <svg className="w-12 h-12" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2 4h.01M17 16h.01" />
                </svg>
              }
              title="No Scenario Selected"
              description="Select a scenario from the header to view assets."
            />
          </CardBody>
        </Card>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Assets" />
        <PageLoading message="Loading assets..." />
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader title="Assets" />
        <Card>
          <CardBody>
            <ErrorState
              title="Failed to Load Assets"
              description={error}
              action={
                <Button variant="primary" onClick={() => window.location.reload()}>
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
      <PageHeader
        title="Assets"
        description={`${filteredAssets.length} of ${assets.length} assets in ${selectedScenario.name}`}
        actions={
          <>
            <Select
              value={filterType}
              onValueChange={(value) => setFilterType(value)}
              options={[
                { value: 'all', label: 'All Types' },
                ...types.map((t) => ({ value: t, label: t.replace('_', ' ').toUpperCase() })),
              ]}
              placeholder="Filter by type"
              className="w-48"
            />
            <Select
              value={filterZone}
              onValueChange={(value) => setFilterZone(value)}
              options={[
                { value: 'all', label: 'All Zones' },
                ...zones.map((z) => ({ value: z, label: z.replace('_', ' ').toUpperCase() })),
              ]}
              placeholder="Filter by zone"
              className="w-48"
            />
          </>
        }
      />

      {filteredAssets.length === 0 ? (
        <Card>
          <CardBody>
            <EmptyState
              title="No Assets Found"
              description={assets.length === 0 ? 'This scenario has no assets.' : 'No assets match the current filters.'}
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
                    <th>Asset ID</th>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Criticality</th>
                    <th>Environment</th>
                    <th>Zone</th>
                    <th>Entry Point</th>
                    <th>Crown Jewel</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredAssets.map((asset) => (
                    <tr key={asset.id}>
                      <td className="font-mono text-sm">{asset.id}</td>
                      <td className="font-medium">{asset.name}</td>
                      <td>
                        <Badge variant="default">
                          {asset.type.replace('_', ' ').toUpperCase()}
                        </Badge>
                      </td>
                      <td>
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 rounded-full bg-[var(--color-bg-tertiary)] overflow-hidden" aria-hidden="true">
                            <div className="h-full rounded-full bg-[var(--color-accent)]" style={{ width: `${Math.max(0, Math.min(10, asset.criticality)) * 10}%` }} />
                          </div>
                          <span className="font-mono">{asset.criticality.toFixed(1)}</span>
                        </div>
                      </td>
                      <td>
                        <Badge variant="default">{asset.environment.toUpperCase()}</Badge>
                      </td>
                      <td>
                        <Badge variant="default">{asset.network_zone.replace('_', ' ').toUpperCase()}</Badge>
                      </td>
                      <td>
                        {asset.is_entry_point ? (
                          <Badge variant="success">Yes</Badge>
                        ) : (
                          <Badge variant="none">No</Badge>
                        )}
                      </td>
                      <td>
                        {asset.is_crown_jewel ? (
                          <Badge variant="critical">Yes</Badge>
                        ) : (
                          <Badge variant="none">No</Badge>
                        )}
                      </td>
                    </tr>
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
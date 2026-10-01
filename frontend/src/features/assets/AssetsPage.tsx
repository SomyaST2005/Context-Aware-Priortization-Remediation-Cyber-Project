import { useEffect, useState } from 'react';
import { useScenario } from '../../context/ScenarioContext';
import { api } from '../../services/api';
import type { AssetResponse } from '../../types/api';
import { Card, CardBody, Badge, Select, Button } from '../../components/ui';
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
        <div className="flex items-center justify-between">
          <h1 className="page-title">Assets</h1>
        </div>
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
        <div className="flex items-center justify-between">
          <h1 className="page-title">Assets</h1>
        </div>
        <PageLoading message="Loading assets..." />
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="page-title">Assets</h1>
        </div>
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

  const getSeverityBadge = (type: AssetResponse['type']) => {
    const badgeMap: Record<string, 'default' | 'critical' | 'high' | 'medium' | 'low' | 'none' | 'success' | 'warning'> = {
      database: 'critical',
      domain_controller: 'critical',
      web_server: 'high',
      api_gateway: 'high',
      app_server: 'medium',
      identity_provider: 'medium',
      workstation: 'low',
      cloud_storage: 'low',
    };
    return badgeMap[type] || 'default';
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="page-title">Assets</h1>
          <p className="text-muted text-sm mt-1">
            {filteredAssets.length} of {assets.length} assets in {selectedScenario.name}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
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
        </div>
      </div>

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
                        <Badge variant={getSeverityBadge(asset.type)}>
                          {asset.type.replace('_', ' ').toUpperCase()}
                        </Badge>
                      </td>
                      <td>
                        <span className="font-mono">{asset.criticality.toFixed(1)}</span>
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
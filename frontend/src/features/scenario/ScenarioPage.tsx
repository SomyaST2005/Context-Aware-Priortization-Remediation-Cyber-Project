import { useEffect, useState } from 'react';
import { Bug, Link2, Server, ShieldCheck } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useScenario } from '../../context/ScenarioContext';
import { api } from '../../services/api';
import type { ScenarioResponse } from '../../types/api';
import { Card, CardHeader, CardBody, Badge, Button, PageHeader, StatCard } from '../../components/ui';
import { LoadingSpinner, EmptyState, ErrorState } from '../../components/ui';

export function ScenarioPage() {
  const navigate = useNavigate();
  const { selectedScenario, refreshScenarios } = useScenario();
  const [scenario, setScenario] = useState<ScenarioResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [retryKey, setRetryKey] = useState(0);
  const [assetCount, setAssetCount] = useState<number | null>(null);
  const [findingCount, setFindingCount] = useState<number | null>(null);
  const [edgeCount, setEdgeCount] = useState<number | null>(null);
  const [entryPointCount, setEntryPointCount] = useState<number | null>(null);
  const [crownJewelCount, setCrownJewelCount] = useState<number | null>(null);

  const scenarioId = selectedScenario?.id;

  useEffect(() => {
    if (!scenarioId) {
      setScenario(null);
      setIsLoading(false);
      return;
    }

    let cancelled = false;
    const loadScenario = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const data = await api.scenarios.get(scenarioId);
        if (cancelled) return;
        setScenario(data);
        // Load counts from backend list endpoints.
        const [assets, findings, edges] = await Promise.all([
          api.assets.list(data.id).catch(() => []),
          api.findings.list(data.id).catch(() => []),
          api.edges.list(data.id).catch(() => []),
        ]);
        if (cancelled) return;
        setAssetCount(assets.length);
        setFindingCount(findings.length);
        setEdgeCount(edges.length);
        setEntryPointCount(assets.filter((a) => a.is_entry_point).length);
        setCrownJewelCount(assets.filter((a) => a.is_crown_jewel).length);
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : 'Failed to load scenario');
        }
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    };

    loadScenario();
    return () => {
      cancelled = true;
    };
  }, [scenarioId, retryKey]);

  if (!selectedScenario) {
    return (
      <div className="space-y-6">
        <PageHeader title="Scenario" />
        <Card>
          <CardBody>
            <EmptyState
              icon={
                <svg className="w-12 h-12" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
                </svg>
              }
              title="No Scenario Selected"
              description="Select a scenario from the header dropdown to view details."
            />
          </CardBody>
        </Card>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Scenario" />
        <div className="flex items-center justify-center min-h-[300px]">
          <LoadingSpinner size="lg" />
        </div>
      </div>
    );
  }

  if (error || !scenario) {
    return (
      <div className="space-y-6">
        <PageHeader title="Scenario" />
        <Card>
          <CardBody>
            <ErrorState
              title="Failed to Load Scenario"
              description={error || 'Unknown error occurred'}
              action={
                <Button variant="primary" onClick={() => setRetryKey((k) => k + 1)}>
                  Retry
                </Button>
              }
            />
          </CardBody>
        </Card>
      </div>
    );
  }

  const formatDate = (isoString: string) => {
    try {
      return new Date(isoString).toLocaleString();
    } catch {
      return isoString;
    }
  };

  return (
    <div className="space-y-6">
      <PageHeader
        title={scenario.name}
        description={
          <>
            Scenario ID: <code className="font-mono text-xs bg-[var(--color-bg-tertiary)] px-1.5 py-0.5 rounded">{scenario.id}</code>
          </>
        }
        actions={
          <>
            <Badge variant="success">Active</Badge>
            <Button variant="secondary" size="sm" onClick={refreshScenarios}>
              Refresh
            </Button>
          </>
        }
      />

      {/* Scenario Info & Counts */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Assets" value={assetCount ?? '—'} icon={<Server className="w-4 h-4" />} />
        <StatCard label="Findings" value={findingCount ?? '—'} icon={<Bug className="w-4 h-4" />} tone="warning" />
        <StatCard label="Network edges" value={edgeCount ?? '—'} icon={<Link2 className="w-4 h-4" />} tone="neutral" />
        <StatCard
          label="Entry points / Crown jewels"
          value={`${entryPointCount ?? '—'} / ${crownJewelCount ?? '—'}`}
          icon={<ShieldCheck className="w-4 h-4" />}
          tone="danger"
        />
      </div>

      {/* Details */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <h2 className="section-title">Scenario Details</h2>
          </CardHeader>
          <CardBody>
            <dl className="space-y-4">
              <div className="grid grid-cols-[auto_1fr] gap-4">
                <dt className="text-muted text-sm">Scenario ID</dt>
                <dd className="font-mono text-sm break-all">{scenario.id}</dd>
              </div>
              <div className="grid grid-cols-[auto_1fr] gap-4">
                <dt className="text-muted text-sm">Created</dt>
                <dd className="text-sm">{formatDate(scenario.created_at)}</dd>
              </div>
              <div className="grid grid-cols-[auto_1fr] gap-4">
                <dt className="text-muted text-sm">Description</dt>
                <dd className="text-sm">{scenario.description || 'No description provided'}</dd>
              </div>
            </dl>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <h2 className="section-title">Quick Actions</h2>
          </CardHeader>
          <CardBody>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <Button variant="secondary" onClick={() => navigate('/assets')}>
                View Assets
              </Button>
              <Button variant="secondary" onClick={() => navigate('/findings')}>
                View Findings
              </Button>
              <Button variant="secondary" onClick={() => navigate('/prioritization')}>
                View Prioritization
              </Button>
              <Button variant="ghost" onClick={() => navigate('/')}>
                Back to Dashboard
              </Button>
            </div>
          </CardBody>
        </Card>
      </div>
    </div>
  );
}

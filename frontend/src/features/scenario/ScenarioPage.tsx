import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useScenario } from '../../context/ScenarioContext';
import { api } from '../../services/api';
import type { ScenarioResponse } from '../../types/api';
import { Card, CardHeader, CardBody, Badge, Button } from '../../components/ui';
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
        <div className="flex items-center justify-between">
          <h1 className="page-title">Scenario</h1>
        </div>
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
        <div className="flex items-center justify-between">
          <h1 className="page-title">Scenario</h1>
        </div>
        <div className="flex items-center justify-center min-h-[300px]">
          <LoadingSpinner size="lg" />
        </div>
      </div>
    );
  }

  if (error || !scenario) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="page-title">Scenario</h1>
        </div>
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
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="page-title">{scenario.name}</h1>
          <p className="text-muted text-sm mt-1">Scenario ID: <code className="font-mono text-xs bg-[var(--color-bg-tertiary)] px-1.5 py-0.5 rounded">{scenario.id}</code></p>
        </div>
        <div className="flex items-center gap-3">
          <Badge variant="success">Active</Badge>
          <Button variant="secondary" size="sm" onClick={refreshScenarios}>
            Refresh
          </Button>
        </div>
      </div>

      {/* Scenario Info & Counts */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card>
          <CardBody className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-lg bg-[var(--color-accent-bg)] flex items-center justify-center text-[var(--color-accent)] flex-shrink-0">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
              </svg>
            </div>
            <div className="min-w-0">
              <h3 className="text-2xl font-semibold text-[var(--color-text-primary)]">{assetCount ?? '—'}</h3>
              <p className="text-sm text-[var(--color-text-secondary)]">Assets</p>
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardBody className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-lg bg-[var(--color-warning-bg)] flex items-center justify-center text-[var(--color-warning)] flex-shrink-0">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104l-.233 1.22a12.06 12.06 0 000 2.93l.233 1.22m0 0l.233 1.22a12.06 12.06 0 000 2.93l-.233 1.22m0 0l-.233 1.22a12.06 12.06 0 010 2.93l.233 1.22m0-14.66l12 3.217" />
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
              </svg>
            </div>
            <div className="min-w-0">
              <h3 className="text-2xl font-semibold text-[var(--color-text-primary)]">{findingCount ?? '—'}</h3>
              <p className="text-sm text-[var(--color-text-secondary)]">Findings</p>
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardBody className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-lg bg-[var(--color-success-bg)] flex items-center justify-center text-[var(--color-success)] flex-shrink-0">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
              </svg>
            </div>
            <div className="min-w-0">
              <h3 className="text-2xl font-semibold text-[var(--color-text-primary)]">{edgeCount ?? '—'}</h3>
              <p className="text-sm text-[var(--color-text-secondary)]">Network Edges</p>
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardBody className="flex items-start gap-4">
            <div className="w-12 h-12 rounded-lg bg-[var(--color-critical)]/10 flex items-center justify-center text-[var(--color-critical)] flex-shrink-0">
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.623 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
            <div className="min-w-0">
              <h3 className="text-2xl font-semibold text-[var(--color-text-primary)]">
                {entryPointCount ?? '—'} / {crownJewelCount ?? '—'}
              </h3>
              <p className="text-sm text-[var(--color-text-secondary)]">Entry points / Crown jewels</p>
            </div>
          </CardBody>
        </Card>
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

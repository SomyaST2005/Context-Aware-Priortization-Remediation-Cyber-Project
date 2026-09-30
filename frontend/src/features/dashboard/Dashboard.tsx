import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useScenario } from '../../context/ScenarioContext';
import { api } from '../../services/api';
import type { PrioritizationResponse } from '../../types/api';
import { Card, CardHeader, CardBody, Button, Badge } from '../../components/ui';

export function Dashboard() {
  const navigate = useNavigate();
  const { selectedScenario } = useScenario();
  const [assetCount, setAssetCount] = useState<number | null>(null);
  const [findingCount, setFindingCount] = useState<number | null>(null);
  const [entryPointCount, setEntryPointCount] = useState<number | null>(null);
  const [crownJewelCount, setCrownJewelCount] = useState<number | null>(null);
  const [topFindings, setTopFindings] = useState<PrioritizationResponse | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const scenarioId = selectedScenario?.id;

  useEffect(() => {
    if (!scenarioId) {
      setAssetCount(null);
      setFindingCount(null);
      setEntryPointCount(null);
      setCrownJewelCount(null);
      setTopFindings(null);
      return;
    }
    let cancelled = false;
    const load = async () => {
      setIsLoading(true);
      try {
        const [assets, findings, prio] = await Promise.all([
          api.assets.list(scenarioId).catch(() => []),
          api.findings.list(scenarioId).catch(() => []),
          api.prioritization.get(scenarioId, { limit: 5 }).catch(() => null),
        ]);
        if (cancelled) return;
        setAssetCount(assets.length);
        setFindingCount(findings.length);
        setEntryPointCount(assets.filter((a) => a.is_entry_point).length);
        setCrownJewelCount(assets.filter((a) => a.is_crown_jewel).length);
        setTopFindings(prio);
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [scenarioId]);

  if (!selectedScenario) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="page-title">Dashboard</h1>
        </div>
        <Card>
          <CardBody>
            <div className="empty-state">
              <svg className="empty-state-icon" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              <h3 className="empty-state-title">No Scenario Selected</h3>
              <p className="empty-state-description">
                Select a scenario from the header to view the security dashboard and access analysis features.
              </p>
            </div>
          </CardBody>
        </Card>
      </div>
    );
  }

  const val = (n: number | null) => (isLoading && n === null ? '…' : n === null ? '—' : String(n));

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="page-title">Dashboard</h1>
          <p className="text-muted text-sm mt-1">Security posture overview for {selectedScenario.name}</p>
        </div>
        <div className="flex items-center gap-3">
          <Badge variant="success">Active</Badge>
          <Button variant="secondary" size="sm" onClick={() => navigate('/scenario')}>Scenario details</Button>
        </div>
      </div>

      {/* Key Metrics Cards (real backend data) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Assets"
          value={val(assetCount)}
          description={entryPointCount !== null ? `${entryPointCount} entry points` : 'From assets endpoint'}
          icon={<ServerIcon />}
        />
        <MetricCard
          title="Findings"
          value={val(findingCount)}
          description="From findings endpoint"
          icon={<BugIcon />}
        />
        <MetricCard
          title="Crown Jewels"
          value={val(crownJewelCount)}
          description="High-value target assets"
          icon={<ShieldIcon />}
        />
        <MetricCard
          title="Top Priority"
          value={topFindings && topFindings.items.length > 0 ? topFindings.items[0].profile.finding_id : val(null)}
          description="Rank #1 by backend ordering"
          icon={<BarChartIcon />}
        />
      </div>

      {/* Top prioritized findings (backend ordering preserved) */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <h2 className="section-title">Top Prioritized Findings</h2>
            <Button variant="ghost" size="sm" onClick={() => navigate('/prioritization')}>
              View all
            </Button>
          </div>
        </CardHeader>
        <CardBody className="p-0">
          {!topFindings || topFindings.items.length === 0 ? (
            <p className="p-6 text-sm text-[var(--color-text-muted)]">
              {isLoading ? 'Loading prioritization…' : 'No prioritized findings returned for this scenario.'}
            </p>
          ) : (
            <div className="table-container">
              <table className="table">
                <thead>
                  <tr>
                    <th>Rank</th>
                    <th>Finding</th>
                    <th>Asset</th>
                    <th>Severity</th>
                    <th>KEV</th>
                    <th>Op. score</th>
                  </tr>
                </thead>
                <tbody>
                  {topFindings.items.map((item) => (
                    <tr key={item.profile.finding_id}>
                      <td className="font-mono font-semibold">#{item.operational_rank}</td>
                      <td className="font-mono text-sm">{item.profile.finding_id}</td>
                      <td className="font-mono text-sm">{item.profile.asset_id}</td>
                      <td>
                        <Badge variant={severityVariant(item.profile.severity_category)}>
                          {item.profile.severity_category}
                        </Badge>
                      </td>
                      <td>
                        {item.profile.known_exploited ? (
                          <Badge variant="warning">KEV</Badge>
                        ) : (
                          <Badge variant="none">—</Badge>
                        )}
                      </td>
                      <td className="font-mono">{item.operational_score.toFixed(3)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardBody>
      </Card>

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <h2 className="section-title">Quick Actions</h2>
        </CardHeader>
        <CardBody>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <ActionCard
              title="View Assets"
              description="Browse scenario assets"
              icon={<ServerIcon />}
              onClick={() => navigate('/assets')}
            />
            <ActionCard
              title="View Findings"
              description="Explore findings"
              icon={<BugIcon />}
              onClick={() => navigate('/findings')}
            />
            <ActionCard
              title="Prioritization"
              description="Contextual ordering + evidence"
              icon={<BarChartIcon />}
              onClick={() => navigate('/prioritization')}
            />
            <ActionCard
              title="Scenario"
              description="Scenario details and counts"
              icon={<ServerIcon />}
              onClick={() => navigate('/scenario')}
            />
          </div>
        </CardBody>
      </Card>

      {/* Status */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card>
          <CardHeader>
            <h2 className="section-title">System Status</h2>
          </CardHeader>
          <CardBody>
            <div className="space-y-3">
              <StatusRow label="API Connection" status="connected" />
              <StatusRow label="Graph Engine" status="connected" />
              <StatusRow label="AI Explanation" status="fallback" description="Using deterministic fallback" />
              <StatusRow label="Database" status="connected" />
            </div>
          </CardBody>
        </Card>

        <Card>
          <CardHeader>
            <h2 className="section-title">Scenario Info</h2>
          </CardHeader>
          <CardBody>
            <dl className="space-y-3">
              <div className="grid grid-cols-[auto_1fr] gap-4">
                <dt className="text-muted text-sm">Scenario ID</dt>
                <dd className="font-mono text-sm">{selectedScenario.id}</dd>
              </div>
              <div className="grid grid-cols-[auto_1fr] gap-4">
                <dt className="text-muted text-sm">Created</dt>
                <dd className="text-sm">{new Date(selectedScenario.created_at).toLocaleString()}</dd>
              </div>
              <div className="grid grid-cols-[auto_1fr] gap-4">
                <dt className="text-muted text-sm">Description</dt>
                <dd className="text-sm">{selectedScenario.description || 'No description'}</dd>
              </div>
            </dl>
          </CardBody>
        </Card>
      </div>
    </div>
  );
}

function severityVariant(s: string): 'critical' | 'high' | 'medium' | 'low' | 'none' {
  switch (s) {
    case 'CRITICAL': return 'critical';
    case 'HIGH': return 'high';
    case 'MEDIUM': return 'medium';
    case 'LOW': return 'low';
    default: return 'none';
  }
}

interface MetricCardProps {
  title: string;
  value: string;
  description: string;
  icon: React.ReactNode;
}

function MetricCard({ title, value, description, icon }: MetricCardProps) {
  return (
    <Card>
      <CardBody className="flex items-start gap-4">
        <div className="w-12 h-12 rounded-lg bg-[var(--color-accent-bg)] flex items-center justify-center text-[var(--color-accent)] flex-shrink-0">
          {icon}
        </div>
        <div className="min-w-0">
          <h3 className="text-lg font-semibold text-[var(--color-text-primary)]">{value}</h3>
          <p className="text-sm text-[var(--color-text-secondary)]">{title}</p>
          <p className="text-xs text-[var(--color-text-muted)] mt-1">{description}</p>
        </div>
      </CardBody>
    </Card>
  );
}

interface ActionCardProps {
  title: string;
  description: string;
  icon: React.ReactNode;
  onClick: () => void;
}

function ActionCard({ title, description, icon, onClick }: ActionCardProps) {
  return (
    <button
      onClick={onClick}
      className="card p-4 text-left hover:border-[var(--color-accent)] transition-colors group"
    >
      <div className="w-10 h-10 rounded-lg bg-[var(--color-bg-tertiary)] flex items-center justify-center text-[var(--color-text-secondary)] group-hover:text-[var(--color-accent)] transition-colors mb-3">
        {icon}
      </div>
      <h3 className="font-medium text-[var(--color-text-primary)]">{title}</h3>
      <p className="text-sm text-[var(--color-text-muted)] mt-1">{description}</p>
    </button>
  );
}

interface StatusRowProps {
  label: string;
  status: 'connected' | 'fallback' | 'disconnected';
  description?: string;
}

function StatusRow({ label, status, description }: StatusRowProps) {
  const statusConfig = {
    connected: { color: 'success' as const, label: 'Connected' },
    fallback: { color: 'warning' as const, label: 'Fallback' },
    disconnected: { color: 'critical' as const, label: 'Disconnected' },
  };

  const config = statusConfig[status];

  return (
    <div className="flex items-center justify-between">
      <div className="flex items-center gap-3">
        <span className="w-2 h-2 rounded-full" style={{ backgroundColor: `var(--color-${config.color})` }} aria-hidden="true" />
        <span className="text-sm text-[var(--color-text-primary)]">{label}</span>
      </div>
      <div className="flex items-center gap-3 text-right">
        {description && <span className="text-xs text-[var(--color-text-muted)]">{description}</span>}
        <Badge variant={config.color}>{config.label}</Badge>
      </div>
    </div>
  );
}

// Icons
function ServerIcon({ className = '' }: { className?: string }) {
  return (
    <svg className={`w-5 h-5 ${className}`} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2 4h.01M17 16h.01" />
    </svg>
  );
}

function BugIcon({ className = '' }: { className?: string }) {
  return (
    <svg className={`w-5 h-5 ${className}`} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104l-.233 1.22a12.06 12.06 0 000 2.93l.233 1.22m0 0l.233 1.22a12.06 12.06 0 000 2.93l-.233 1.22m0 0l-.233 1.22a12.06 12.06 0 010 2.93l.233 1.22m0-14.66l12 3.217" />
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  );
}

function ShieldIcon({ className = '' }: { className?: string }) {
  return (
    <svg className={`w-5 h-5 ${className}`} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  );
}

function BarChartIcon({ className = '' }: { className?: string }) {
  return (
    <svg className={`w-5 h-5 ${className}`} fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
    </svg>
  );
}

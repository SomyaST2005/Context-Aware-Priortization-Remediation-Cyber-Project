import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Bot,
  Bug,
  FlaskConical,
  GitBranch,
  Link2,
  ListOrdered,
  Radar,
  Server,
  ShieldAlert,
  Zap,
  type LucideIcon,
} from 'lucide-react';
import { useScenario } from '../../context/ScenarioContext';
import { api } from '../../services/api';
import type {
  AssetResponse,
  AttackPathResponse,
  FindingResponse,
  PrioritizationResponse,
} from '../../types/api';
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  PageHeader,
  SeverityBadge,
  StatCard,
} from '../../components/ui';

/** `null` means the request failed (shown as unavailable, never as zero). */
interface DashboardData {
  assets: AssetResponse[] | null;
  findings: FindingResponse[] | null;
  prioritization: PrioritizationResponse | null;
  attackPaths: AttackPathResponse[] | null;
  apiHealthy: boolean;
}

const WORKFLOW: Array<{ path: string; title: string; description: string; icon: LucideIcon }> = [
  { path: '/attack-paths', title: 'Attack Paths', description: 'How an attacker can reach crown jewels', icon: GitBranch },
  { path: '/prioritization', title: 'Prioritization', description: 'Findings ordered by environment context', icon: ListOrdered },
  { path: '/blast-radius', title: 'Blast Radius', description: 'What a compromised asset exposes', icon: Radar },
  { path: '/chokepoints', title: 'Chokepoints', description: 'Entities that many paths pass through', icon: Link2 },
  { path: '/remediation', title: 'What-If Simulation', description: 'See paths change before you fix anything', icon: FlaskConical },
  { path: '/optimization', title: 'Optimization', description: 'Best set of fixes within a budget', icon: Zap },
  { path: '/explanation', title: 'Explanation', description: 'Evidence-grounded reasoning for any result', icon: Bot },
];

export function Dashboard() {
  const navigate = useNavigate();
  const { selectedScenario } = useScenario();
  const [data, setData] = useState<DashboardData | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const scenarioId = selectedScenario?.id;

  useEffect(() => {
    if (!scenarioId) {
      setData(null);
      return;
    }
    let cancelled = false;
    const load = async () => {
      setIsLoading(true);
      try {
        const [assets, findings, prioritization, attackPaths, apiHealthy] = await Promise.all([
          api.assets.list(scenarioId).catch(() => null),
          api.findings.list(scenarioId).catch(() => null),
          api.prioritization.get(scenarioId).catch(() => null),
          api.attackPaths.get(scenarioId, { path_mode: 'all', max_depth: 10, max_paths: 100 }).catch(() => null),
          api.health().then(() => true).catch(() => false),
        ]);
        if (!cancelled) setData({ assets, findings, prioritization, attackPaths, apiHealthy });
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
        <PageHeader title="Dashboard" />
        <Card>
          <CardBody>
            <EmptyState
              title="No Scenario Selected"
              description="Select a scenario from the header to view the security dashboard and access analysis features."
            />
          </CardBody>
        </Card>
      </div>
    );
  }

  const show = (n: number | null | undefined) => (n === null || n === undefined ? (isLoading ? '…' : '—') : n);

  const assets = data?.assets ?? null;
  const prio = data?.prioritization ?? null;
  const entryPoints = assets ? assets.filter((a) => a.is_entry_point).length : null;
  const crownJewels = assets ? assets.filter((a) => a.is_crown_jewel).length : null;
  // Counts of backend flags over the full prioritization result (no new scoring).
  const crownExposed = prio ? prio.items.filter((i) => i.profile.crown_jewel_reachable).length : null;
  const kevCount = prio ? prio.items.filter((i) => i.profile.known_exploited).length : null;
  const topItems = prio ? prio.items.slice(0, 5) : [];

  return (
    <div className="space-y-6">
      <PageHeader
        title="Dashboard"
        description={`Security posture overview for ${selectedScenario.name}`}
        actions={
          <>
            <Badge variant="success">Active</Badge>
            <Button variant="secondary" size="sm" onClick={() => navigate('/scenario')}>
              Scenario details
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard
          label="Assets"
          value={show(assets?.length)}
          hint={entryPoints !== null ? `${entryPoints} entry point${entryPoints === 1 ? '' : 's'} · ${crownJewels} crown jewel${crownJewels === 1 ? '' : 's'}` : undefined}
          icon={<Server className="w-4 h-4" />}
        />
        <StatCard
          label="Findings"
          value={show(data?.findings?.length)}
          hint={kevCount !== null ? `${kevCount} known exploited (KEV)` : undefined}
          icon={<Bug className="w-4 h-4" />}
          tone="warning"
        />
        <StatCard
          label="Attack paths"
          value={show(data?.attackPaths?.length)}
          hint="Entry point → crown jewel"
          icon={<GitBranch className="w-4 h-4" />}
        />
        <StatCard
          label="Crown-jewel exposed"
          value={show(crownExposed)}
          hint={prio ? `of ${prio.total_findings} prioritized findings` : undefined}
          icon={<ShieldAlert className="w-4 h-4" />}
          tone={crownExposed ? 'danger' : 'success'}
        />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6 items-start">
        <Card className="xl:col-span-2">
          <CardHeader>
            <div className="flex items-center justify-between">
              <h2 className="section-title">Top Prioritized Findings</h2>
              <Button variant="ghost" size="sm" onClick={() => navigate('/prioritization')}>
                View all
              </Button>
            </div>
          </CardHeader>
          <CardBody className="p-0">
            {topItems.length === 0 ? (
              <p className="p-6 text-sm text-[var(--color-text-muted)]">
                {isLoading ? 'Loading prioritization…' : prio ? 'No prioritized findings returned for this scenario.' : 'Prioritization is unavailable.'}
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
                      <th>Flags</th>
                      <th>Op. score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {topItems.map((item) => (
                      <tr key={item.profile.finding_id}>
                        <td>
                          <span className="inline-flex items-center justify-center min-w-7 h-6 px-1.5 rounded-md bg-[var(--color-accent-bg)] text-[var(--color-accent)] font-mono text-xs font-semibold">
                            #{item.operational_rank}
                          </span>
                        </td>
                        <td className="font-mono text-xs">{item.profile.finding_id}</td>
                        <td className="font-mono text-xs">{item.profile.asset_id}</td>
                        <td><SeverityBadge severity={item.profile.severity_category} /></td>
                        <td>
                          <div className="flex flex-wrap gap-1">
                            {item.profile.known_exploited && <Badge variant="warning">KEV</Badge>}
                            {item.profile.crown_jewel_reachable && <Badge variant="critical">Crown jewel reachable</Badge>}
                            {!item.profile.known_exploited && !item.profile.crown_jewel_reachable && (
                              <span className="text-[var(--color-text-muted)]">—</span>
                            )}
                          </div>
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

        <Card>
          <CardHeader><h2 className="section-title">System Status</h2></CardHeader>
          <CardBody>
            <div className="space-y-3">
              <StatusRow label="API" state={data ? (data.apiHealthy ? 'ok' : 'down') : 'unknown'} />
              <StatusRow label="Database" state={data ? (data.assets && data.findings ? 'ok' : 'down') : 'unknown'} detail="Assets and findings load" />
              <StatusRow label="Graph engine" state={data ? (data.prioritization && data.attackPaths ? 'ok' : 'down') : 'unknown'} detail="Paths and prioritization compute" />
              <StatusRow label="AI explanation" state="info" detail="Reported with each explanation" />
            </div>
            <dl className="mt-5 pt-4 border-t border-[var(--color-border-primary)] space-y-2 text-sm">
              <div className="flex justify-between gap-4">
                <dt className="text-[var(--color-text-muted)]">Scenario ID</dt>
                <dd className="font-mono text-xs break-all text-right">{selectedScenario.id}</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-[var(--color-text-muted)]">Created</dt>
                <dd className="text-xs text-right">{new Date(selectedScenario.created_at).toLocaleString()}</dd>
              </div>
              <div>
                <dt className="text-[var(--color-text-muted)]">Description</dt>
                <dd className="mt-0.5 text-xs text-[var(--color-text-secondary)]">{selectedScenario.description || 'No description'}</dd>
              </div>
            </dl>
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader><h2 className="section-title">Analysis Workflow</h2></CardHeader>
        <CardBody>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            {WORKFLOW.map((step, i) => (
              <button
                key={step.path}
                type="button"
                onClick={() => navigate(step.path)}
                className="group text-left rounded-lg border border-[var(--color-border-primary)] bg-[var(--color-bg-secondary)] p-3.5 transition-colors hover:border-[var(--color-accent)]"
              >
                <div className="flex items-center gap-2.5">
                  <span className="w-7 h-7 rounded-md bg-[var(--color-bg-tertiary)] text-[var(--color-text-secondary)] group-hover:text-[var(--color-accent)] flex items-center justify-center transition-colors">
                    <step.icon className="w-4 h-4" aria-hidden="true" />
                  </span>
                  <span className="text-sm font-medium text-[var(--color-text-primary)]">
                    <span className="text-[var(--color-text-muted)] font-mono mr-1.5">{i + 1}</span>
                    {step.title}
                  </span>
                </div>
                <p className="mt-2 text-xs text-[var(--color-text-secondary)]">{step.description}</p>
              </button>
            ))}
          </div>
        </CardBody>
      </Card>
    </div>
  );
}

type Health = 'ok' | 'down' | 'unknown' | 'info';

function StatusRow({ label, state, detail }: { label: string; state: Health; detail?: string }) {
  const cfg: Record<Health, { badge: 'success' | 'critical' | 'none' | 'info'; text: string; dot: string }> = {
    ok: { badge: 'success', text: 'Operational', dot: 'var(--color-success)' },
    down: { badge: 'critical', text: 'Unavailable', dot: 'var(--color-critical)' },
    unknown: { badge: 'none', text: 'Checking', dot: 'var(--color-none)' },
    info: { badge: 'info', text: 'Per request', dot: 'var(--color-accent)' },
  };
  const c = cfg[state];
  return (
    <div className="flex items-center justify-between gap-3">
      <div className="flex items-center gap-2.5 min-w-0">
        <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: c.dot }} aria-hidden="true" />
        <div className="min-w-0">
          <p className="text-sm text-[var(--color-text-primary)]">{label}</p>
          {detail && <p className="text-xs text-[var(--color-text-muted)]">{detail}</p>}
        </div>
      </div>
      <Badge variant={c.badge}>{c.text}</Badge>
    </div>
  );
}

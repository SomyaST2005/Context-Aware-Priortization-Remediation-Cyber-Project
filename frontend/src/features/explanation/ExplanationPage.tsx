import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useScenario } from '../../context/ScenarioContext';
import { api } from '../../services/api';
import type {
  ExplanationRequest,
  ExplanationResponse,
  ExplanationType,
  FindingResponse,
  RemediationActionResponse,
} from '../../types/api';
import { MAX_CANDIDATE_ACTIONS } from '../../types/api';
import { Card, CardHeader, CardBody, Badge, Button, Select, Input, PageHeader } from '../../components/ui';
import { EmptyState, ErrorState, PageLoading } from '../../components/ui';
import { ExplanationResult } from './ExplanationResult';

type Tab = ExplanationType;

function parseInitialTab(params: URLSearchParams): Tab {
  const t = params.get('type');
  return t === 'simulation' || t === 'optimization' ? t : 'finding';
}

export function ExplanationPage() {
  const { selectedScenario } = useScenario();
  const scenarioId = selectedScenario?.id;
  const [searchParams] = useSearchParams();

  const [tab, setTab] = useState<Tab>(() => parseInitialTab(searchParams));
  const [findings, setFindings] = useState<FindingResponse[]>([]);
  const [actions, setActions] = useState<RemediationActionResponse[]>([]);
  const [isLoadingTargets, setIsLoadingTargets] = useState(true);
  const [targetsError, setTargetsError] = useState<string | null>(null);

  // Per-type selections, prefilled from deep links (?finding_id=, ?actions=, ?candidates=&budget=).
  const [findingId, setFindingId] = useState(() => searchParams.get('finding_id') ?? '');
  const [simIds, setSimIds] = useState<string[]>(() => searchParams.get('actions')?.split(',').filter(Boolean) ?? []);
  const [candIds, setCandIds] = useState<string[]>(() => searchParams.get('candidates')?.split(',').filter(Boolean) ?? []);
  const [budget, setBudget] = useState(() => Number(searchParams.get('budget') ?? 10));
  const [question, setQuestion] = useState('');

  const [result, setResult] = useState<ExplanationResponse | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  const [runError, setRunError] = useState<string | null>(null);
  const [clientError, setClientError] = useState<string | null>(null);

  // Load target data + clear stale state on scenario change.
  useEffect(() => {
    setResult(null);
    setRunError(null);
    setClientError(null);
    setFindingId('');
    setSimIds([]);
    setCandIds([]);
    if (!scenarioId) {
      setFindings([]);
      setActions([]);
      setIsLoadingTargets(false);
      return;
    }
    let cancelled = false;
    const load = async () => {
      setIsLoadingTargets(true);
      setTargetsError(null);
      try {
        const [f, a] = await Promise.all([
          api.findings.list(scenarioId),
          api.remediationActions.list(scenarioId).catch(() => [] as RemediationActionResponse[]),
        ]);
        if (cancelled) return;
        setFindings(f);
        setActions(a);
        setFindingId((prev) => prev || f[0]?.id || '');
      } catch (err) {
        if (!cancelled) setTargetsError(err instanceof Error ? err.message : 'Failed to load targets');
      } finally {
        if (!cancelled) setIsLoadingTargets(false);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [scenarioId]);

  const switchTab = (t: Tab) => {
    setTab(t);
    setResult(null);
    setRunError(null);
    setClientError(null);
  };

  const toggleId = (list: string[], id: string, limit?: number): string[] | null => {
    if (list.includes(id)) return list.filter((x) => x !== id);
    if (limit !== undefined && list.length >= limit) {
      setClientError(`At most ${limit} actions are supported.`);
      return null;
    }
    return [...list, id];
  };

  const buildRequest = (): ExplanationRequest | null => {
    const q = question.trim() ? question.trim() : undefined;
    if (tab === 'finding') {
      if (!findingId) {
        setClientError('Select a finding to explain.');
        return null;
      }
      return { explanation_type: 'finding', finding_id: findingId, ...(q ? { user_question: q } : {}) };
    }
    if (tab === 'simulation') {
      if (simIds.length === 0) {
        setClientError('Select at least one remediation action.');
        return null;
      }
      return { explanation_type: 'simulation', remediation_action_ids: simIds, ...(q ? { user_question: q } : {}) };
    }
    if (candIds.length === 0) {
      setClientError('Select at least one candidate action.');
      return null;
    }
    if (!Number.isFinite(budget) || budget < 0) {
      setClientError('Budget must be a number >= 0.');
      return null;
    }
    return { explanation_type: 'optimization', candidate_action_ids: candIds, budget, ...(q ? { user_question: q } : {}) };
  };

  const run = async () => {
    if (!scenarioId) return;
    setClientError(null);
    const req = buildRequest();
    if (!req) return;
    setIsRunning(true);
    setRunError(null);
    try {
      const r = await api.explanation.explain(scenarioId, req);
      setResult(r.explanation);
    } catch (err) {
      setRunError(err instanceof Error ? err.message : 'Explanation request failed');
      setResult(null);
    } finally {
      setIsRunning(false);
    }
  };

  if (!selectedScenario) {
    return (
      <div className="space-y-6">
        <PageHeader title="AI Explanation" />
        <Card><CardBody><EmptyState title="No Scenario Selected" description="Select a scenario from the header to request explanations." /></CardBody></Card>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="AI Explanation"
        description={`Explanations of deterministic analysis in ${selectedScenario.name}. The backend assembles the evidence and validates every claim; the status shows whether an AI model or a deterministic template wrote the text.`}
      />

      {/* Type selector */}
      <div className="inline-flex gap-1 p-1 rounded-lg bg-[var(--color-bg-secondary)] border border-[var(--color-border-primary)]" role="tablist" aria-label="Explanation type">
        {(['finding', 'simulation', 'optimization'] as Tab[]).map((t) => (
          <button
            key={t}
            role="tab"
            aria-selected={tab === t}
            onClick={() => switchTab(t)}
            className={`px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
              tab === t
                ? 'bg-[var(--color-accent-bg)] text-[var(--color-accent)]'
                : 'text-[var(--color-text-secondary)] hover:text-[var(--color-text-primary)]'
            }`}
          >
            {t === 'finding' ? 'Finding' : t === 'simulation' ? 'Simulation' : 'Optimization'}
          </button>
        ))}
      </div>

      {isLoadingTargets ? (
        <PageLoading message="Loading explanation targets..." />
      ) : targetsError ? (
        <Card><CardBody><ErrorState title="Failed to Load Targets" description={targetsError} /></CardBody></Card>
      ) : (
        <Card>
          <CardHeader><h2 className="section-title">Request Configuration</h2></CardHeader>
          <CardBody className="space-y-4">
            {tab === 'finding' && (
              findings.length === 0 ? (
                <EmptyState title="No Findings" description="This scenario has no findings to explain." />
              ) : (
                <Select
                  label="Finding"
                  value={findingId}
                  onValueChange={(value) => setFindingId(value)}
                  options={findings.map((f) => ({ value: f.id, label: `${f.id} (asset ${f.asset_id}, ${f.status})` }))}
                  className="max-w-md"
                />
              )
            )}

            {tab === 'simulation' && (
              actions.length === 0 ? (
                <EmptyState title="No Remediation Actions" description="This scenario has no remediation actions, so a simulation explanation cannot be constructed." />
              ) : (
                <ActionChecklist
                  actions={actions}
                  checked={simIds}
                  onToggle={(id) => {
                    const next = toggleId(simIds, id);
                    if (next) setSimIds(next);
                  }}
                />
              )
            )}

            {tab === 'optimization' && (
              actions.length === 0 ? (
                <EmptyState title="No Remediation Actions" description="This scenario has no candidate actions, so an optimization explanation cannot be constructed." />
              ) : (
                <>
                  <ActionChecklist
                    actions={actions}
                    checked={candIds}
                    limit={MAX_CANDIDATE_ACTIONS}
                    onToggle={(id) => {
                      const next = toggleId(candIds, id, MAX_CANDIDATE_ACTIONS);
                      if (next) setCandIds(next);
                    }}
                  />
                  <Input
                    label={`Budget (max ${MAX_CANDIDATE_ACTIONS} candidates)`}
                    type="number"
                    min={0}
                    step="any"
                    value={budget}
                    onChange={(e) => setBudget(Number(e.target.value))}
                    className="w-48"
                  />
                </>
              )
            )}

            <div>
              <label htmlFor="user-question" className="block text-sm font-medium text-[var(--color-text-primary)] mb-1.5">
                Optional question (emphasis only)
              </label>
              <textarea
                id="user-question"
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                placeholder="e.g. Focus on crown-jewel reachability"
                rows={2}
                maxLength={500}
                className="input max-w-2xl"
              />
              <p className="mt-1.5 text-xs text-[var(--color-text-muted)] max-w-2xl">
                Sent to the backend as untrusted data: it selects emphasis only and cannot change
                security calculations or override grounding rules.
              </p>
            </div>

            {clientError && (
              <p className="text-sm text-[var(--color-danger)]" role="alert">{clientError}</p>
            )}

            <Button variant="primary" onClick={run} loading={isRunning}>
              Explain {tab}
            </Button>
          </CardBody>
        </Card>
      )}

      {runError && (
        <Card><CardBody><ErrorState title="Explanation Request Failed" description={runError} action={<Button variant="primary" size="sm" onClick={run}>Retry</Button>} /></CardBody></Card>
      )}

      {result && <ExplanationResult explanation={result} />}
    </div>
  );
}

function ActionChecklist({
  actions,
  checked,
  limit,
  onToggle,
}: {
  actions: RemediationActionResponse[];
  checked: string[];
  limit?: number;
  onToggle: (id: string) => void;
}) {
  return (
    <div>
      <p className="text-sm font-medium text-[var(--color-text-primary)] mb-2">
        {checked.length} selected{limit !== undefined ? ` (max ${limit})` : ''}
      </p>
      <ul className="space-y-1.5 max-h-64 overflow-y-auto rounded-md border border-[var(--color-border-primary)] p-2">
        {actions.map((a) => (
          <li key={a.id}>
            <label className="flex items-start gap-2.5 px-2 py-1.5 rounded hover:bg-[var(--color-bg-tertiary)] cursor-pointer">
              <input
                type="checkbox"
                checked={checked.includes(a.id)}
                onChange={() => onToggle(a.id)}
                className="mt-1 h-4 w-4 accent-cyan-400"
              />
              <span className="min-w-0">
                <span className="block text-sm text-[var(--color-text-primary)]">
                  {a.title} <span className="font-mono text-xs text-[var(--color-text-muted)]">{a.id}</span>
                </span>
                <span className="mt-1 flex flex-wrap gap-1">
                  <Badge variant="default">{a.action_type}</Badge>
                  <Badge variant="default">cost {a.estimated_cost}</Badge>
                </span>
              </span>
            </label>
          </li>
        ))}
      </ul>
    </div>
  );
}

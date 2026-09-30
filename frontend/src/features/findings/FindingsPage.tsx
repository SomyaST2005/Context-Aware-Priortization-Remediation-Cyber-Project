import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useScenario } from '../../context/ScenarioContext';
import { api } from '../../services/api';
import type { FindingResponse } from '../../types/api';
import { Card, CardBody, Badge, Select, Input, Button } from '../../components/ui';
import { EmptyState, ErrorState, PageLoading } from '../../components/ui';

export function FindingsPage() {
  const navigate = useNavigate();
  const { selectedScenario } = useScenario();
  const [findings, setFindings] = useState<FindingResponse[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState<string>('all');

  useEffect(() => {
    if (!selectedScenario) {
      setFindings([]);
      setIsLoading(false);
      return;
    }

    const loadFindings = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const data = await api.findings.list(selectedScenario.id);
        setFindings(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load findings');
      } finally {
        setIsLoading(false);
      }
    };

    loadFindings();
  }, [selectedScenario]);

  const filteredFindings = findings.filter((finding) => {
    const searchMatch = searchTerm === '' ||
      finding.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      finding.asset_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
      finding.vulnerability_id.toLowerCase().includes(searchTerm.toLowerCase());
    const statusMatch = filterStatus === 'all' || finding.status === filterStatus;
    return searchMatch && statusMatch;
  });

  const statuses = Array.from(new Set(findings.map((f) => f.status))).sort();

  if (!selectedScenario) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="page-title">Findings</h1>
        </div>
        <Card>
          <CardBody>
            <EmptyState
              icon={
                <svg className="w-12 h-12" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104l-.233 1.22a12.06 12.06 0 000 2.93l.233 1.22m0 0l.233 1.22a12.06 12.06 0 000 2.93l-.233 1.22m0 0l-.233 1.22a12.06 12.06 0 010 2.93l.233 1.22m0-14.66l12 3.217" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
              }
              title="No Scenario Selected"
              description="Select a scenario from the header to view findings."
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
          <h1 className="page-title">Findings</h1>
        </div>
        <PageLoading message="Loading findings..." />
      </div>
    );
  }

  if (error) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="page-title">Findings</h1>
        </div>
        <Card>
          <CardBody>
            <ErrorState
              title="Failed to Load Findings"
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

  const getSeverityBadge = (status: FindingResponse['status']) => {
    const badgeMap: Record<string, 'default' | 'critical' | 'high' | 'medium' | 'low' | 'none' | 'success' | 'warning'> = {
      active: 'critical',
      in_progress: 'warning',
      remediated: 'success',
      suppressed: 'none',
    };
    return badgeMap[status] || 'default';
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="page-title">Findings</h1>
          <p className="text-muted text-sm mt-1">
            {filteredFindings.length} of {findings.length} findings in {selectedScenario.name}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Input
            placeholder="Search by ID, asset, or vulnerability..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-64"
          />
          <Select
            value={filterStatus}
            onChange={(e) => setFilterStatus(e.target.value)}
            options={[
              { value: 'all', label: 'All Statuses' },
              ...statuses.map((s) => ({ value: s, label: s.replace('_', ' ').toUpperCase() })),
            ]}
            placeholder="Filter by status"
            className="w-40"
          />
        </div>
      </div>

      {filteredFindings.length === 0 ? (
        <Card>
          <CardBody>
            <EmptyState
              title="No Findings Found"
              description={findings.length === 0 ? 'This scenario has no findings.' : 'No findings match the current filters.'}
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
                    <th>Finding ID</th>
                    <th>Asset</th>
                    <th>Vulnerability</th>
                    <th>Port</th>
                    <th>Service</th>
                    <th>Status</th>
                    <th>Discovered</th>
                    <th><span className="sr-only">Explain</span></th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.map((finding) => (
                    <tr key={finding.id}>
                      <td className="font-mono text-sm">{finding.id}</td>
                      <td className="font-mono text-sm">{finding.asset_id}</td>
                      <td className="font-mono text-sm">{finding.vulnerability_id}</td>
                      <td className="font-mono text-sm">{finding.port ?? '—'}</td>
                      <td className="text-sm">{finding.service_name ?? '—'}</td>
                      <td>
                        <Badge variant={getSeverityBadge(finding.status)}>
                          {finding.status.replace('_', ' ').toUpperCase()}
                        </Badge>
                      </td>
                      <td className="text-sm">
                        {finding.discovered_at
                          ? new Date(finding.discovered_at).toLocaleDateString()
                          : '—'}
                      </td>
                      <td>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => navigate(`/explanation?type=finding&finding_id=${encodeURIComponent(finding.id)}`)}
                        >
                          Explain
                        </Button>
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
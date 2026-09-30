import { useState } from 'react';
import type { ScenarioResponse } from '../../types/api';
import { Button, Select } from '../ui';
import { api } from '../../services/api';

interface HeaderProps {
  onMenuClick: () => void;
  selectedScenario: ScenarioResponse | null;
  onScenarioChange: (scenario: ScenarioResponse) => void;
  isLoadingScenarios: boolean;
}

export function Header({ onMenuClick, selectedScenario, onScenarioChange, isLoadingScenarios }: HeaderProps) {
  const [scenarios, setScenarios] = useState<ScenarioResponse[]>([]);

  const loadScenarios = async () => {
    try {
      const data = await api.scenarios.list({ limit: 100 });
      setScenarios(data);
    } catch (error) {
      console.error('Failed to load scenarios:', error);
    }
  };

  // Load scenarios on mount
  if (scenarios.length === 0 && !isLoadingScenarios) {
    loadScenarios();
  }

  const handleScenarioSelect = (scenarioId: string) => {
    const scenario = scenarios.find((s) => s.id === scenarioId);
    if (scenario) {
      onScenarioChange(scenario);
    }
  };

  return (
    <header className="sticky top-0 z-30 bg-[var(--color-bg-secondary)]/95 backdrop-blur-sm border-b border-[var(--color-border-primary)]">
      <div className="flex items-center justify-between h-16 px-4 lg:px-6">
        {/* Left: Menu button + Scenario selector */}
        <div className="flex items-center gap-4 min-w-0 flex-1">
          <button
            onClick={onMenuClick}
            className="lg:hidden btn-ghost p-2"
            aria-label="Toggle navigation menu"
            aria-expanded="false"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M4 6h16M4 12h16M4 18h16" />
            </svg>
          </button>

          <div className="relative w-full max-w-xs lg:max-w-md">
            <Select
              value={selectedScenario?.id || ''}
              onChange={(e) => handleScenarioSelect(e.target.value)}
              options={scenarios.map((s) => ({ value: s.id, label: s.name }))}
              placeholder="Select a scenario..."
              disabled={isLoadingScenarios || scenarios.length === 0}
              className="w-full"
              aria-label="Select scenario"
            />
            {isLoadingScenarios && (
              <div className="absolute right-3 top-1/2 -translate-y-1/2">
                <span className="loading-spinner w-4 h-4 border-1.5" aria-hidden="true" />
              </div>
            )}
            {scenarios.length === 0 && !isLoadingScenarios && (
              <p className="text-xs text-[var(--color-text-muted)] mt-1">No scenarios available</p>
            )}
          </div>
        </div>

        {/* Right: Status / Actions */}
        <div className="flex items-center gap-3">
          {selectedScenario && (
            <div className="hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[var(--color-bg-tertiary)] border border-[var(--color-border-primary)]">
              <span className="w-2 h-2 rounded-full bg-[var(--color-success)]" aria-hidden="true" />
              <span className="text-sm font-medium text-[var(--color-text-primary)]">{selectedScenario.name}</span>
            </div>
          )}

          <Button variant="ghost" size="sm" className="hidden sm:block">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
          </Button>

          <Button variant="ghost" size="sm" className="hidden sm:block">
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24" aria-hidden="true">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </Button>
        </div>
      </div>
    </header>
  );
}
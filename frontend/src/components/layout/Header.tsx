import { Menu } from 'lucide-react';
import type { ScenarioResponse } from '../../types/api';
import { Select } from '../ui';

interface HeaderProps {
  onMenuClick: () => void;
  scenarios: ScenarioResponse[];
  selectedScenario: ScenarioResponse | null;
  onScenarioChange: (scenario: ScenarioResponse) => void;
  isLoadingScenarios: boolean;
}

export function Header({ onMenuClick, scenarios, selectedScenario, onScenarioChange, isLoadingScenarios }: HeaderProps) {
  const handleScenarioSelect = (scenarioId: string) => {
    const scenario = scenarios.find((s) => s.id === scenarioId);
    if (scenario) onScenarioChange(scenario);
  };

  return (
    <header className="sticky top-0 z-30 bg-[var(--color-bg-secondary)]/95 backdrop-blur-sm border-b border-[var(--color-border-primary)]">
      <div className="flex items-center gap-4 h-16 px-4 lg:px-8">
        <button
          type="button"
          onClick={onMenuClick}
          className="lg:hidden btn-ghost p-2 rounded-lg"
          aria-label="Open navigation menu"
        >
          <Menu className="w-5 h-5" aria-hidden="true" />
        </button>

        <div className="flex items-center gap-3 min-w-0">
          <span className="hidden sm:block text-xs font-medium uppercase tracking-wider text-[var(--color-text-muted)]">
            Scenario
          </span>
          <Select
            value={selectedScenario?.id || ''}
            onValueChange={handleScenarioSelect}
            options={scenarios.map((s) => ({ value: s.id, label: s.name }))}
            placeholder={isLoadingScenarios ? 'Loading scenarios…' : 'Select a scenario…'}
            disabled={isLoadingScenarios || scenarios.length === 0}
            className="w-64 sm:w-72"
          />
          {!isLoadingScenarios && scenarios.length === 0 && (
            <span className="text-xs text-[var(--color-text-muted)]">No scenarios available</span>
          )}
        </div>

        {selectedScenario && (
          <div className="ml-auto hidden md:flex items-center gap-2 text-xs text-[var(--color-text-secondary)]">
            <span className="w-1.5 h-1.5 rounded-full bg-[var(--color-success)]" aria-hidden="true" />
            <span className="font-mono">{selectedScenario.id}</span>
          </div>
        )}
      </div>
    </header>
  );
}

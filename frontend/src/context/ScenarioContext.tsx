import { createContext, useContext, useState, useEffect, type ReactNode } from 'react';
import type { ScenarioResponse } from '../types/api';
import { api } from '../services/api';

interface ScenarioContextType {
  selectedScenario: ScenarioResponse | null;
  setSelectedScenario: (scenario: ScenarioResponse | null) => void;
  scenarios: ScenarioResponse[];
  isLoadingScenarios: boolean;
  refreshScenarios: () => Promise<void>;
}

const ScenarioContext = createContext<ScenarioContextType | undefined>(undefined);

export function ScenarioProvider({ children }: { children: ReactNode }) {
  const [selectedScenario, setSelectedScenario] = useState<ScenarioResponse | null>(null);
  const [scenarios, setScenarios] = useState<ScenarioResponse[]>([]);
  const [isLoadingScenarios, setIsLoadingScenarios] = useState(true);

  const refreshScenarios = async () => {
    setIsLoadingScenarios(true);
    try {
      const data = await api.scenarios.list({ limit: 100 });
      setScenarios(data);
      // If current selection is no longer valid, clear it
      if (selectedScenario && !data.find((s) => s.id === selectedScenario.id)) {
        setSelectedScenario(null);
      }
    } catch (error) {
      console.error('Failed to load scenarios:', error);
    } finally {
      setIsLoadingScenarios(false);
    }
  };

  useEffect(() => {
    refreshScenarios();
  }, []);

  return (
    <ScenarioContext.Provider value={{
      selectedScenario,
      setSelectedScenario,
      scenarios,
      isLoadingScenarios,
      refreshScenarios,
    }}>
      {children}
    </ScenarioContext.Provider>
  );
}

export function useScenario() {
  const context = useContext(ScenarioContext);
  if (!context) {
    throw new Error('useScenario must be used within a ScenarioProvider');
  }
  return context;
}
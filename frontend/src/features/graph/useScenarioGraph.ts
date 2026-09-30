import { useEffect, useState } from 'react';
import { api } from '../../services/api';
import type { GraphResponse } from '../../types/api';

interface GraphState {
  data: GraphResponse | null;
  isLoading: boolean;
  error: string | null;
  retry: () => void;
}

/** Fetch the canonical graph for a scenario; refetches when scenarioId changes. */
export function useScenarioGraph(scenarioId: string | undefined): GraphState {
  const [data, setData] = useState<GraphResponse | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [retryKey, setRetryKey] = useState(0);

  useEffect(() => {
    if (!scenarioId) {
      setData(null);
      setIsLoading(false);
      return;
    }
    let cancelled = false;
    const load = async () => {
      setIsLoading(true);
      setError(null);
      try {
        const result = await api.graph.get(scenarioId);
        if (!cancelled) setData(result);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : 'Failed to load graph');
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    };
    load();
    return () => {
      cancelled = true;
    };
  }, [scenarioId, retryKey]);

  return { data, isLoading, error, retry: () => setRetryKey((k) => k + 1) };
}

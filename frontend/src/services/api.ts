// Centralized API Client
// Base URL configured via VITE_API_BASE_URL env var, defaults to proxied /api

import type {
  ScenarioResponse,
  ScenarioCreate,
  ScenarioUpdate,
  AssetResponse,
  FindingResponse,
  PrioritizationResponse,
  PrioritizationParams,
  ScenarioListParams,
  GraphResponse,
  AttackPathResponse,
  AttackPathParams,
  BlastRadiusResponse,
  ChokepointResponse,
  ChokepointParams,
  RemediationActionResponse,
  SimulationRequest,
  SimulationResponse,
  OptimizationRequest,
  OptimizationResponse,
  ExplanationRequest,
  ExplainResponse,
} from '../types/api';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

interface ApiError {
  status: number;
  detail: string;
  originalError?: unknown;
}

function createApiError(status: number, detail: string, originalError?: unknown): ApiError {
  return { status, detail, originalError };
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    let detail = `HTTP ${response.status}: ${response.statusText}`;
    try {
      const errorData = await response.json();
      detail = errorData.detail || detail;
    } catch {
      // Use default detail if response is not JSON
    }
    throw createApiError(response.status, detail);
  }

  // Handle 204 No Content
  if (response.status === 204) {
    return undefined as T;
  }

  return response.json();
}

export const api = {
  // Health
  health: async (): Promise<{ status: string; service: string }> => {
    const response = await fetch(`${API_BASE_URL}/api/health`);
    return handleResponse(response);
  },

  // Scenarios
  scenarios: {
    list: async (params?: ScenarioListParams): Promise<ScenarioResponse[]> => {
      const searchParams = new URLSearchParams();
      if (params?.skip) searchParams.set('skip', String(params.skip));
      if (params?.limit) searchParams.set('limit', String(params.limit));
      const response = await fetch(`${API_BASE_URL}/api/scenarios?${searchParams.toString()}`);
      return handleResponse(response);
    },

    get: async (id: string): Promise<ScenarioResponse> => {
      const response = await fetch(`${API_BASE_URL}/api/scenarios/${encodeURIComponent(id)}`);
      return handleResponse(response);
    },

    create: async (data: ScenarioCreate): Promise<ScenarioResponse> => {
      const response = await fetch(`${API_BASE_URL}/api/scenarios`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      return handleResponse(response);
    },

    update: async (id: string, data: ScenarioUpdate): Promise<ScenarioResponse> => {
      const response = await fetch(`${API_BASE_URL}/api/scenarios/${encodeURIComponent(id)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      return handleResponse(response);
    },

    delete: async (id: string): Promise<void> => {
      const response = await fetch(`${API_BASE_URL}/api/scenarios/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      return handleResponse(response);
    },
  },

  // Assets
  assets: {
    list: async (scenarioId: string): Promise<AssetResponse[]> => {
      const response = await fetch(`${API_BASE_URL}/api/scenarios/${encodeURIComponent(scenarioId)}/assets`);
      return handleResponse(response);
    },
  },

  // Findings
  findings: {
    list: async (scenarioId: string): Promise<FindingResponse[]> => {
      const response = await fetch(`${API_BASE_URL}/api/scenarios/${encodeURIComponent(scenarioId)}/findings`);
      return handleResponse(response);
    },
  },

  // Prioritization
  prioritization: {
    get: async (scenarioId: string, params?: PrioritizationParams): Promise<PrioritizationResponse> => {
      const searchParams = new URLSearchParams();
      if (params) {
        Object.entries(params).forEach(([key, value]) => {
          if (value !== undefined && value !== null) {
            searchParams.set(key, String(value));
          }
        });
      }
      const response = await fetch(`${API_BASE_URL}/api/scenarios/${encodeURIComponent(scenarioId)}/prioritization?${searchParams.toString()}`);
      return handleResponse(response);
    },
  },

  // Graph
  graph: {
    get: async (scenarioId: string): Promise<GraphResponse> => {
      const response = await fetch(`${API_BASE_URL}/api/scenarios/${encodeURIComponent(scenarioId)}/graph`);
      return handleResponse(response);
    },
  },

  // Attack Paths
  attackPaths: {
    get: async (scenarioId: string, params?: AttackPathParams): Promise<AttackPathResponse[]> => {
      const searchParams = new URLSearchParams();
      if (params?.path_mode) searchParams.set('path_mode', params.path_mode);
      if (params?.max_depth) searchParams.set('max_depth', String(params.max_depth));
      if (params?.max_paths) searchParams.set('max_paths', String(params.max_paths));
      const response = await fetch(`${API_BASE_URL}/api/scenarios/${encodeURIComponent(scenarioId)}/attack-paths?${searchParams.toString()}`);
      return handleResponse(response);
    },
  },

  // Blast Radius
  blastRadius: {
    get: async (scenarioId: string, sourceAssetId: string, maxDepth?: number): Promise<BlastRadiusResponse> => {
      const searchParams = new URLSearchParams();
      if (maxDepth !== undefined) searchParams.set('max_depth', String(maxDepth));
      const response = await fetch(`${API_BASE_URL}/api/scenarios/${encodeURIComponent(scenarioId)}/blast-radius/${encodeURIComponent(sourceAssetId)}?${searchParams.toString()}`);
      return handleResponse(response);
    },
  },

  // Chokepoints
  chokepoints: {
    get: async (scenarioId: string, params?: ChokepointParams): Promise<ChokepointResponse> => {
      const searchParams = new URLSearchParams();
      if (params?.max_depth) searchParams.set('max_depth', String(params.max_depth));
      if (params?.max_paths) searchParams.set('max_paths', String(params.max_paths));
      if (params?.entity_type) searchParams.set('entity_type', params.entity_type);
      if (params?.min_score !== undefined) searchParams.set('min_score', String(params.min_score));
      if (params?.limit) searchParams.set('limit', String(params.limit));
      const response = await fetch(`${API_BASE_URL}/api/scenarios/${encodeURIComponent(scenarioId)}/chokepoints?${searchParams.toString()}`);
      return handleResponse(response);
    },
  },

  // Remediation actions (discovery for simulation/optimization requests)
  remediationActions: {
    list: async (scenarioId: string): Promise<RemediationActionResponse[]> => {
      const response = await fetch(`${API_BASE_URL}/api/scenarios/${encodeURIComponent(scenarioId)}/remediation-actions`);
      return handleResponse(response);
    },
  },

  // Remediation Simulation
  simulation: {
    run: async (scenarioId: string, data: SimulationRequest): Promise<SimulationResponse> => {
      const response = await fetch(`${API_BASE_URL}/api/scenarios/${encodeURIComponent(scenarioId)}/simulate-remediation`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      return handleResponse(response);
    },
  },

  // Budget Optimization
  optimization: {
    run: async (scenarioId: string, data: OptimizationRequest): Promise<OptimizationResponse> => {
      const response = await fetch(`${API_BASE_URL}/api/scenarios/${encodeURIComponent(scenarioId)}/optimize-remediation`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      return handleResponse(response);
    },
  },

  // AI Explanation
  explanation: {
    explain: async (scenarioId: string, data: ExplanationRequest): Promise<ExplainResponse> => {
      const response = await fetch(`${API_BASE_URL}/api/scenarios/${encodeURIComponent(scenarioId)}/explain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });
      return handleResponse(response);
    },
  },

  // Edges
  edges: {
    list: async (scenarioId: string): Promise<unknown[]> => {
      const response = await fetch(`${API_BASE_URL}/api/scenarios/${encodeURIComponent(scenarioId)}/edges`);
      return handleResponse(response);
    },
  },
};

// Re-export types
export type { ApiError };
export type {
  ScenarioResponse,
  ScenarioCreate,
  ScenarioUpdate,
  AssetResponse,
  FindingResponse,
  PrioritizationResponse,
  PrioritizationParams,
  GraphResponse,
  AttackPathResponse,
  AttackPathParams,
  BlastRadiusResponse,
  ChokepointResponse,
  ChokepointParams,
  RemediationActionResponse,
  SimulationRequest,
  SimulationResponse,
  OptimizationRequest,
  OptimizationResponse,
  ExplanationRequest,
  ExplainResponse,
} from '../types/api';
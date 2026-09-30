// API Types - matching backend Pydantic schemas

// ============================================
// Scenario Types
// ============================================
export interface ScenarioResponse {
  id: string;
  name: string;
  description: string | null;
  created_at: string; // ISO datetime
}

export interface ScenarioCreate {
  id: string;
  name: string;
  description?: string;
}

export interface ScenarioUpdate {
  name?: string;
  description?: string;
}

// ============================================
// Asset Types (matching AssetResponse)
// ============================================
export type AssetType =
  | 'workstation'
  | 'web_server'
  | 'app_server'
  | 'database'
  | 'identity_provider'
  | 'cloud_storage'
  | 'api_gateway'
  | 'domain_controller';

export type Environment =
  | 'production'
  | 'staging'
  | 'development'
  | 'dmz'
  | 'internal';

export type NetworkZone =
  | 'external'
  | 'dmz'
  | 'app_tier'
  | 'db_tier'
  | 'management';

export interface AssetResponse {
  id: string;
  name: string;
  type: AssetType;
  criticality: number; // 1.0 - 10.0
  environment: Environment;
  network_zone: NetworkZone;
  is_entry_point: boolean;
  is_crown_jewel: boolean;
  owner: string;
  ip_address: string | null;
  description: string | null;
  created_at: string;
  updated_at: string;
}

// ============================================
// Finding Types (matching FindingResponse)
// ============================================
export type FindingStatus = 'active' | 'remediated' | 'suppressed' | 'in_progress';

export interface FindingResponse {
  id: string;
  asset_id: string;
  vulnerability_id: string;
  port: number | null;
  service_name: string | null;
  status: FindingStatus;
  discovered_at: string | null;
  created_at: string;
  updated_at: string;
}

// ============================================
// Vulnerability Types (for finding context)
// ============================================
export type VulnerabilitySeverity = 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface VulnerabilityResponse {
  id: string;
  cve_id: string | null;
  title: string;
  description: string;
  cvss_score: number;
  severity: VulnerabilitySeverity;
  epss_score: number | null;
  known_exploited: boolean;
  attack_vector: string | null;
  attack_complexity: string | null;
  privileges_required: string | null;
  user_interaction: string | null;
  remediation_effort: number | null;
  created_at: string;
  updated_at: string;
}

// ============================================
// Prioritization Types (matching PrioritizationResponse)
// ============================================

export interface VulnerabilityEvidenceResponse {
  cvss_normalized: number;
  epss_score: number | null;
  known_exploited: boolean;
  severity_category: VulnerabilitySeverity;
}

export interface AttackPathEvidenceResponse {
  path_count: number;
  max_feasibility: number;
  avg_feasibility: number;
  crown_jewel_reachable: boolean;
  unique_entry_points: number;
  unique_crown_jewels: number;
  max_depth: number;
  min_depth: number;
}

export interface EnvironmentalEvidenceResponse {
  asset_criticality_normalized: number;
  is_entry_point: boolean;
  is_crown_jewel: boolean;
  network_zone: string | null;
  blast_radius_assets: number;
  blast_radius_crown_jewels: number;
  blast_radius_max_depth: number;
  blast_radius_min_cost: number;
  blast_radius_max_prob: number;
}

export interface ChokepointEvidenceResponse {
  finding_chokepoint_score: number;
  finding_path_feasibility_criticality: number;
  finding_path_count: number;
  asset_chokepoint_score: number;
  asset_path_feasibility_criticality: number;
  asset_path_count: number;
}

export interface RemediationEvidenceResponse {
  remediation_cost: number;
  implementation_complexity: 'LOW' | 'MEDIUM' | 'HIGH' | null;
  downtime_required: boolean;
  action_type: string | null;
}

export interface EvidenceBreakdownResponse {
  vulnerability_intrinsic: VulnerabilityEvidenceResponse;
  attack_path_context: AttackPathEvidenceResponse;
  environmental: EnvironmentalEvidenceResponse;
  chokepoint: ChokepointEvidenceResponse;
  remediation_context: RemediationEvidenceResponse;
}

export interface PriorityProfileResponse {
  finding_id: string;
  asset_id: string;
  vulnerability_id: string;
  cvss_normalized: number;
  epss_score: number | null;
  epss_available: boolean;
  known_exploited: boolean;
  severity_category: VulnerabilitySeverity;
  path_participation_count: number;
  max_path_feasibility: number;
  max_path_feasibility_normalized: number;
  avg_path_feasibility: number;
  crown_jewel_reachable: boolean;
  unique_entry_points: number;
  unique_crown_jewels: number;
  min_path_depth: number;
  max_path_depth: number;
  asset_criticality_normalized: number;
  is_entry_point: boolean;
  is_crown_jewel: boolean;
  network_zone: string | null;
  blast_radius_asset_count: number;
  blast_radius_crown_jewels: number;
  blast_radius_max_depth: number;
  blast_radius_min_cost: number;
  blast_radius_max_prob: number;
  finding_chokepoint_score: number;
  finding_path_feasibility_criticality: number;
  finding_path_count: number;
  asset_chokepoint_score: number;
  asset_path_feasibility_criticality: number;
  asset_path_count: number;
  remediation_cost: number;
  implementation_complexity: 'LOW' | 'MEDIUM' | 'HIGH' | null;
  downtime_required: boolean;
  action_type: string | null;
  baseline_is_entry_point: boolean | null;
}

export interface OrderingKeysResponse {
  tiers: number[];
  composite_score: number;
  tiebreaker: string;
  finding_id: string;
  asset_id: string;
}

export interface OrderingPolicyResponse {
  crown_jewel_first: boolean;
  entry_point_first: boolean;
  kev_tier: boolean;
  chokepoint_weight: number;
  feasibility_weight: number;
  cvss_weight: number;
  epss_weight: number;
  asset_criticality_weight: number;
  tiebreaker: 'finding_id' | 'asset_id';
}

export interface PrioritizationResultResponse {
  profile: PriorityProfileResponse;
  operational_rank: number;
  ordering_keys: OrderingKeysResponse;
  operational_score: number;
  evidence: EvidenceBreakdownResponse;
  scenario_id: string;
  computed_at: string;
}

export interface PrioritizationResponse {
  scenario_id: string;
  total_findings: number;
  returned_findings: number;
  max_depth_used: number;
  max_paths_used: number;
  min_operational_score: number;
  sort_by: 'operational_rank' | 'chokepoint_score' | 'cvss' | 'feasibility' | 'asset_criticality';
  policy: OrderingPolicyResponse;
  items: PrioritizationResultResponse[];
}

// ============================================
// Canonical Graph Types (matching GET /graph)
// NOTE: backend excludes node `type` from node data; kinds are inferred
// from attribute presence (see features/graph/graphModel.ts).
// ============================================
export interface GraphNodeData {
  id: string;
  [key: string]: unknown;
}

export interface GraphEdgeData {
  id: string;
  source: string;
  target: string;
  edge_type?: string;
  traversal_cost?: number;
  probability?: number;
  finding_id?: string | null;
  [key: string]: unknown;
}

export interface GraphElements {
  nodes: Array<{ data: GraphNodeData }>;
  edges: Array<{ data: GraphEdgeData }>;
}

export interface GraphResponse {
  elements: GraphElements;
  metadata: {
    scenario_id: string;
    node_count: number;
    edge_count: number;
    builder_stats: Record<string, unknown>;
  };
}

// ============================================
// Attack Path Types (matching AttackPath.to_dict)
// ============================================
export type AttackPathMode = 'all' | 'shortest' | 'cheapest';

export interface AttackPathResponse {
  id: string;
  entry_point: string;
  crown_jewel: string;
  nodes: string[];
  edges: string[];
  hop_count: number;
  total_traversal_cost: number;
  total_probability: number;
}

export interface AttackPathParams {
  path_mode?: AttackPathMode;
  max_depth?: number;
  max_paths?: number;
}

// ============================================
// Blast Radius Types (matching BlastRadiusResponse)
// ============================================
export interface ReachabilityDetailResponse {
  asset_id: string;
  depth: number;
  min_traversal_cost: number;
  max_probability: number;
}

export interface BlastRadiusResponse {
  source_asset: string;
  affected_assets: string[];
  affected_asset_count: number;
  crown_jewels_reached: string[];
  max_depth_reached: number;
  reachability_details: ReachabilityDetailResponse[];
}

// ============================================
// Chokepoint Types (matching ChokepointResponse)
// ============================================
export type ChokepointEntityType = 'asset' | 'finding';

export interface ChokepointDetailResponse {
  entity_id: string;
  entity_type: ChokepointEntityType;
  chokepoint_score: number;
  path_feasibility_criticality: number;
  path_count: number;
  unique_entry_points: number;
  unique_crown_jewels: number;
  min_path_depth: number;
  max_path_depth: number;
}

export interface ChokepointResponse {
  chokepoints: ChokepointDetailResponse[];
  total_entities_analyzed: number;
  max_chokepoint_score: number;
  total_attack_paths_analyzed: number;
  max_depth_used: number;
  max_paths_used: number;
}

export interface ChokepointParams {
  max_depth?: number;
  max_paths?: number;
  entity_type?: 'all' | ChokepointEntityType;
  min_score?: number;
  limit?: number;
}

// ============================================
// Remediation Action Types (matching RemediationActionResponse)
// ============================================
export type RemediationActionType =
  | 'PATCH_VULNERABILITY'
  | 'REMOVE_VULNERABILITY'
  | 'DISABLE_SERVICE'
  | 'REMOVE_NETWORK_PATH'
  | 'SEGMENT_NETWORK'
  | 'RESTRICT_PORT'
  | 'REMOVE_TRUST_RELATIONSHIP'
  | 'REDUCE_PRIVILEGE'
  | 'CHANGE_ACCESS_POLICY'
  | 'ISOLATE_ASSET';

export const MVP_ACTION_TYPES: RemediationActionType[] = [
  'PATCH_VULNERABILITY',
  'REMOVE_VULNERABILITY',
  'REMOVE_NETWORK_PATH',
  'RESTRICT_PORT',
  'ISOLATE_ASSET',
];

export const DEFERRED_ACTION_TYPES: RemediationActionType[] = [
  'DISABLE_SERVICE',
  'SEGMENT_NETWORK',
  'REMOVE_TRUST_RELATIONSHIP',
  'REDUCE_PRIVILEGE',
  'CHANGE_ACCESS_POLICY',
];

export interface RemediationActionResponse {
  id: string;
  title: string;
  description: string;
  action_type: RemediationActionType;
  target_asset_id: string | null;
  target_finding_id: string | null;
  target_edge_id: string | null;
  estimated_cost: number;
  implementation_complexity: 'LOW' | 'MEDIUM' | 'HIGH';
  downtime_required: boolean;
  created_at: string;
  updated_at: string;
}

// ============================================
// Simulation Types (matching SimulationResponse)
// ============================================
export interface SimulationActionResponse {
  action_id: string;
  action_type: string;
  target_id: string;
  target_type: 'finding' | 'asset' | 'edge';
}

export interface MetricDeltaResponse {
  metric_name: string;
  before: number | null;
  after: number | null;
  absolute_delta: number | null;
  /** Null means "not applicable" (e.g. percent change from zero) — never render as 0. */
  percent_change: number | null;
}

export interface FindingRankComparisonResponse {
  finding_id: string;
  asset_id: string;
  status: 'ACTIVE' | 'REMEDIATED';
  baseline_rank: number | null;
  simulated_rank: number | null;
  rank_delta: number | null;
  baseline_operational_score: number | null;
  simulated_operational_score: number | null;
}

export interface StateSummaryResponse {
  total_attack_paths: number;
  crown_jewel_path_count: number;
  distinct_crown_jewels: number;
  sum_path_feasibility: number;
  max_path_feasibility: number;
  min_path_depth: number | null;
  max_path_depth: number | null;
  blast_affected_assets: number;
  blast_crown_jewels: number;
  blast_max_depth: number;
  chokepoint_count: number;
  max_chokepoint_score: number;
  sum_chokepoint_criticality: number;
  prioritization_count: number;
  max_operational_score: number;
}

export interface SimulationStepResponse {
  action: SimulationActionResponse;
  state: StateSummaryResponse;
  incremental_deltas: MetricDeltaResponse[];
  incremental_rank_comparison: FindingRankComparisonResponse[];
}

export interface SimulationRequest {
  remediation_action_ids: string[];
  max_depth?: number;
  max_paths?: number;
}

export interface SimulationResponse {
  scenario_id: string;
  action_ids: string[];
  applied_actions: SimulationActionResponse[];
  baseline: StateSummaryResponse;
  steps: SimulationStepResponse[];
  final: StateSummaryResponse;
  overall_deltas: MetricDeltaResponse[];
  overall_rank_comparison: FindingRankComparisonResponse[];
  remediated_findings: string[];
  max_depth_used: number;
  max_paths_used: number;
  policy_snapshot: Record<string, unknown>;
  simulated_at: string;
}

// ============================================
// Optimization Types (matching OptimizationResponse)
// ============================================
export interface CandidateActionResponse {
  action_id: string;
  action_type: string;
  target_id: string;
  target_type: 'finding' | 'asset' | 'edge';
  estimated_cost: number;
  validation_status: 'VALID';
}

export interface InfeasibleSubsetResponse {
  action_ids: string[];
  reason: string;
}

export interface OptimizationRequest {
  candidate_action_ids: string[];
  budget: number;
  max_depth?: number;
  max_paths?: number;
}

export type OptimizationSelectionReason =
  | 'optimal_selection'
  | 'zero_path_baseline'
  | 'all_infeasible'
  | 'all_exceed_budget'
  | 'no_positive_improvement';

export interface OptimizationResponse {
  scenario_id: string;
  budget: number;
  objective: string;
  candidates: CandidateActionResponse[];
  selected_action_ids: string[];
  selected_total_cost: number;
  within_budget: boolean;
  objective_o1: number;
  objective_o2: number;
  selection_reason: OptimizationSelectionReason;
  baseline: StateSummaryResponse;
  selected: StateSummaryResponse;
  overall_deltas: MetricDeltaResponse[];
  overall_rank_comparison: FindingRankComparisonResponse[];
  remediated_findings: string[];
  evaluated_subset_count: number;
  infeasible_subset_count: number;
  over_budget_subset_count: number;
  reported_infeasible_subsets: InfeasibleSubsetResponse[];
  max_depth_used: number;
  max_paths_used: number;
  optimized_at: string;
}

/** Backend exact-enumeration ceiling for optimization candidates. */
export const MAX_CANDIDATE_ACTIONS = 12;

// ============================================
// Explanation Types (matching schemas/explanation.py)
// ============================================
export type ExplanationType = 'finding' | 'simulation' | 'optimization';

export interface FindingExplanationRequest {
  explanation_type: 'finding';
  finding_id: string;
  max_depth?: number;
  max_paths?: number;
  user_question?: string | null;
}

export interface SimulationExplanationRequest {
  explanation_type: 'simulation';
  remediation_action_ids: string[];
  max_depth?: number;
  max_paths?: number;
  user_question?: string | null;
}

export interface OptimizationExplanationRequest {
  explanation_type: 'optimization';
  candidate_action_ids: string[];
  budget?: number;
  max_depth?: number;
  max_paths?: number;
  user_question?: string | null;
}

export type ExplanationRequest =
  | FindingExplanationRequest
  | SimulationExplanationRequest
  | OptimizationExplanationRequest;

export interface EvidenceRefResponse {
  ref_id: string;
  source_path: string;
  value?: number | string | boolean | null;
}

export interface ExplanationClaimResponse {
  type: 'FACT' | 'INTERPRETATION' | 'LIMITATION';
  statement: string;
  evidence_refs: EvidenceRefResponse[];
}

export interface ExplanationSummaryResponse {
  statement: string;
  evidence_refs: EvidenceRefResponse[];
}

export type ExplanationStatus = 'AVAILABLE' | 'FALLBACK' | 'UNAVAILABLE';
export type ExplanationOrigin = 'model' | 'fallback-template' | 'none';

export interface ExplanationResponse {
  scenario_id: string;
  explanation_type: ExplanationType;
  summary: ExplanationSummaryResponse;
  key_factors: ExplanationClaimResponse[];
  impact: ExplanationClaimResponse[];
  changes: ExplanationClaimResponse[];
  limitations: ExplanationClaimResponse[];
  status: ExplanationStatus;
  origin: ExplanationOrigin;
}

export interface ExplainResponse {
  deterministic_result: Record<string, unknown>;
  explanation: ExplanationResponse;
}
export interface HealthResponse {
  status: string;
  service: string;
}

export interface ApiError {
  detail: string;
}

// ============================================
// Query Parameters
// ============================================
export interface ScenarioListParams {
  skip?: number;
  limit?: number;
}

export interface PrioritizationParams {
  max_depth?: number;
  max_paths?: number;
  min_operational_score?: number;
  limit?: number;
  sort_by?: 'operational_rank' | 'chokepoint_score' | 'cvss' | 'feasibility' | 'asset_criticality';
  crown_jewel_first?: boolean;
  entry_point_first?: boolean;
  kev_tier?: boolean;
  chokepoint_weight?: number;
  feasibility_weight?: number;
  cvss_weight?: number;
  epss_weight?: number;
  asset_criticality_weight?: number;
  tiebreaker?: 'finding_id' | 'asset_id';
}
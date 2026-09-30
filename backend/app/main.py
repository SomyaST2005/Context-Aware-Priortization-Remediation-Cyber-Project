"""
FastAPI application entrypoint for the cybersecurity remediation prioritization system.
"""
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List, Optional, Literal
import networkx as nx

from backend.app.models.database import (
    Base,
    Scenario,
    Asset,
    Finding,
    Edge,
)
from backend.app.schemas.asset import AssetResponse
from backend.app.schemas.finding import FindingResponse
from backend.app.schemas.edge import EdgeResponse
from backend.app.schemas.remediation import RemediationActionResponse
from backend.app.schemas.scenario import ScenarioCreate, ScenarioResponse, ScenarioUpdate
from backend.app.graph.builder import build_canonical_graph, CanonicalGraphBuilder
from backend.app.analysis.path_analysis import find_attack_paths, get_shortest_path, get_cheapest_path
from backend.app.analysis.blast_radius import compute_blast_radius
from backend.app.analysis.chokepoint import compute_chokepoints
from backend.app.schemas.blast_radius import BlastRadiusResponse
from backend.app.schemas.chokepoint import ChokepointResponse
from backend.app.core.database import get_db, engine
from backend.app.analysis.prioritization import OrderingPolicy, compute_prioritization
from backend.app.schemas.prioritization import PrioritizationResponse
from backend.app.analysis.remediation_simulation import (
    resolve_simulation_action,
    run_simulation,
)
from backend.app.analysis.budget_optimization import (
    MAX_CANDIDATE_ACTIONS,
    optimize,
    resolve_candidates,
)
from backend.app.models.database import RemediationAction
from backend.app.schemas.remediation_simulation import (
    SimulationRequest,
    SimulationResponse,
)
from backend.app.schemas.budget_optimization import (
    OptimizationRequest,
    OptimizationResponse,
)
from backend.app.schemas.explanation import (
    FindingExplanationRequest,
    OptimizationExplanationRequest,
    SimulationExplanationRequest,
)

# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AI-Assisted Context-Aware Cybersecurity Remediation Prioritization",
    description="A graph-based cybersecurity decision-support system for context-aware vulnerability and remediation prioritization",
    version="0.1.0",
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, replace with specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "service": "cybersecurity-remediation-prioritization"}


# Scenario endpoints
@app.post("/api/scenarios", response_model=ScenarioResponse, status_code=status.HTTP_201_CREATED, tags=["Scenarios"])
async def create_scenario(scenario: ScenarioCreate, db: Session = Depends(get_db)):
    """Create a new scenario."""
    db_scenario = Scenario(**scenario.model_dump())
    db.add(db_scenario)
    db.commit()
    db.refresh(db_scenario)
    return db_scenario


@app.get("/api/scenarios", response_model=List[ScenarioResponse], tags=["Scenarios"])
async def list_scenarios(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """List all scenarios."""
    scenarios = db.query(Scenario).offset(skip).limit(limit).all()
    return scenarios


@app.get("/api/scenarios/{scenario_id}", response_model=ScenarioResponse, tags=["Scenarios"])
async def get_scenario(scenario_id: str, db: Session = Depends(get_db)):
    """Get a specific scenario by ID."""
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    return scenario


@app.put("/api/scenarios/{scenario_id}", response_model=ScenarioResponse, tags=["Scenarios"])
async def update_scenario(scenario_id: str, scenario: ScenarioUpdate, db: Session = Depends(get_db)):
    """Update a specific scenario."""
    db_scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if db_scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    update_data = scenario.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(db_scenario, field, value)
    
    db.commit()
    db.refresh(db_scenario)
    return db_scenario


@app.delete("/api/scenarios/{scenario_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Scenarios"])
async def delete_scenario(scenario_id: str, db: Session = Depends(get_db)):
    """Delete a specific scenario."""
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    db.delete(scenario)
    db.commit()
    return None


# Graph endpoints
@app.get("/api/scenarios/{scenario_id}/graph", tags=["Graph"])
async def get_scenario_graph(scenario_id: str, db: Session = Depends(get_db)):
    """
    Get the canonical security graph for a scenario in Cytoscape-compatible format.
    """
    # Build the graph
    graph = build_canonical_graph(db, scenario_id)
    
    # Convert to Cytoscape-compatible JSON format
    nodes = []
    edges = []
    
    # Add nodes
    for node_id, node_data in graph.nodes(data=True):
        # Create Cytoscape node format
        cyto_node = {
            "data": {
                "id": node_id,
                **{k: v for k, v in node_data.items() if k != 'type'}  # Exclude internal type field
            }
        }
        nodes.append(cyto_node)
    
    # Add edges
    for source, target, edge_data in graph.edges(data=True):
        # Create Cytoscape edge format
        cyto_edge = {
            "data": {
                "id": edge_data.get('edge_id', f"{source}-{target}"),
                "source": source,
                "target": target,
                **{k: v for k, v in edge_data.items() if k not in ['source_id', 'target_id', 'type']}  # Exclude internal fields
            }
        }
        edges.append(cyto_edge)
    
    # Add metadata
    elements = {
        "nodes": nodes,
        "edges": edges
    }
    
    # Add graph-level metadata
    cypher_data = {
        "elements": elements,
        "metadata": {
            "scenario_id": scenario_id,
            "node_count": graph.number_of_nodes(),
            "edge_count": graph.number_of_edges(),
            "builder_stats": {}  # Could add stats from builder here
        }
    }
    
    return cypher_data


@app.post("/api/scenarios/{scenario_id}/graph/validate", tags=["Graph"])
async def validate_scenario_graph(scenario_id: str, db: Session = Depends(get_db)):
    """
    Validate the canonical security graph for a scenario.
    """
    try:
        # Build the graph
        graph = build_canonical_graph(db, scenario_id)
        
        # Validate the graph
        from backend.app.graph.validators import validate_graph
        is_valid, errors = validate_graph(graph)
        
        if is_valid:
            return {"valid": True, "message": "Graph is valid"}
        else:
            return {"valid": False, "errors": errors}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to validate graph: {str(e)}"
        )


# Attack path endpoints
@app.get("/api/scenarios/{scenario_id}/attack-paths", tags=["Attack Paths"])
async def get_attack_paths(
    scenario_id: str,
path_mode: Literal["all", "shortest", "cheapest"] = "all",
    max_depth: int = 10,
    max_paths: int = 100,
    db: Session = Depends(get_db),
):
    """
    Get attack paths from entry points to crown jewels for a scenario.
    """
    # Verify scenario exists
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    # Build the graph
    graph = build_canonical_graph(db, scenario_id)
    
    # Get paths based on mode
    if path_mode == "shortest":
        path = get_shortest_path(graph, max_depth=max_depth)
        paths = [path] if path else []
    elif path_mode == "cheapest":
        path = get_cheapest_path(graph, max_depth=max_depth)
        paths = [path] if path else []
    else:  # "all" or any other value defaults to all
        paths = find_attack_paths(graph, max_depth=max_depth, max_paths=max_paths)
    
    # Convert to list of dictionaries
    return [path.to_dict() for path in paths if path is not None]


# Blast radius endpoints
@app.get(
    "/api/scenarios/{scenario_id}/blast-radius/{source_asset_id}",
    response_model=BlastRadiusResponse,
    tags=["Blast Radius"],
)
async def get_blast_radius(
    scenario_id: str,
    source_asset_id: str,
    max_depth: int = 10,
    db: Session = Depends(get_db),
):
    """
    Compute the blast radius from a compromised asset in a scenario.
    """
    # Verify scenario exists
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    # Build the graph
    graph = build_canonical_graph(db, scenario_id)

    # Compute blast radius
    try:
        result = compute_blast_radius(
            graph,
            source_asset_id,
            max_depth=max_depth,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    return result.to_dict()


# Chokepoint endpoints
@app.get(
    "/api/scenarios/{scenario_id}/chokepoints",
    response_model=ChokepointResponse,
    tags=["Chokepoint"],
)
async def get_chokepoints(
    scenario_id: str,
    max_depth: int = 10,
    max_paths: int = 100,
    entity_type: Literal["all", "asset", "finding"] = "all",
    min_score: float = 0.0,
    limit: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """
    Compute chokepoints from attack paths in a scenario.
    
    Chokepoints are actionable entities (assets and findings) whose remediation
    would eliminate a significant amount of attack-path feasibility between
    entry points and crown jewels.
    
    Query Parameters:
    - max_depth: Maximum attack path depth (default: 10)
    - max_paths: Maximum attack paths to analyze (default: 100)
    - entity_type: Entity types to analyze - "all", "asset", or "finding" (default: "all")
    - min_score: Minimum chokepoint score threshold for filtering (default: 0.0)
    - limit: Maximum number of chokepoints to return (default: no limit)
    """
    # Verify scenario exists
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    # Validate query parameters
    if max_depth < 0:
        raise HTTPException(status_code=400, detail="max_depth must be >= 0")
    if max_paths < 0:
        raise HTTPException(status_code=400, detail="max_paths must be >= 0")
    if limit is not None and limit < 0:
        raise HTTPException(status_code=400, detail="limit must be >= 0")
    if not (0.0 <= min_score <= 1.0):
        raise HTTPException(status_code=400, detail="min_score must be between 0.0 and 1.0")

    # Build the graph
    graph = build_canonical_graph(db, scenario_id)

    # Compute chokepoints
    try:
        result = compute_chokepoints(
            graph,
            max_depth=max_depth,
            max_paths=max_paths,
            entity_types=entity_type,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Apply API-level filtering
    chokepoints = result.chokepoints
    
    # Filter by min_score
    if min_score > 0.0:
        chokepoints = [c for c in chokepoints if c.chokepoint_score >= min_score]
    
    # Apply limit
    if limit is not None:
        chokepoints = chokepoints[:limit]

    # Build response preserving original metadata
    response = ChokepointResponse(
        chokepoints=chokepoints,
        total_entities_analyzed=result.total_entities_analyzed,
        max_chokepoint_score=result.max_chokepoint_score,
        total_attack_paths_analyzed=result.total_attack_paths_analyzed,
        max_depth_used=result.max_depth_used,
        max_paths_used=result.max_paths_used,
    )

    return response


# Basic asset endpoints (for testing/seeding)
@app.get("/api/scenarios/{scenario_id}/assets", response_model=List[AssetResponse], tags=["Assets"])
async def get_scenario_assets(scenario_id: str, db: Session = Depends(get_db)):
    """Get all assets in a scenario."""
    # Verify scenario exists
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    # For now, return all assets (in future, we might filter by scenario)
    assets = db.query(Asset).filter(Asset.scenario_id == scenario_id).all()
    return assets



# Basic finding endpoints (for testing/seeding)
@app.get("/api/scenarios/{scenario_id}/findings", response_model=List[FindingResponse], tags=["Findings"])
async def get_scenario_findings(scenario_id: str, db: Session = Depends(get_db)):
    """Get all findings in a scenario."""
    # Verify scenario exists
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    # For now, return all findings (in future, we might filter by scenario)
    findings = db.query(Finding).filter(Finding.scenario_id == scenario_id).all()
    return findings



# Basic edge endpoints (for testing/seeding)
@app.get("/api/scenarios/{scenario_id}/edges", response_model=List[EdgeResponse], tags=["Edges"])
async def get_scenario_edges(scenario_id: str, db: Session = Depends(get_db)):
    """Get all edges in a scenario."""
    # Verify scenario exists
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    # For now, return all edges (in future, we might filter by scenario)
    edges = db.query(Edge).filter(Edge.scenario_id == scenario_id).all()
    return edges


# Remediation action listing (read-only; mirrors the assets/findings/edges
# pattern so the frontend can discover available action IDs for simulation
# and optimization requests. No analysis logic lives here.)
@app.get("/api/scenarios/{scenario_id}/remediation-actions", response_model=List[RemediationActionResponse], tags=["Remediation"])
async def get_scenario_remediation_actions(scenario_id: str, db: Session = Depends(get_db)):
    """Get all remediation actions in a scenario."""
    # Verify scenario exists
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    actions = db.query(RemediationAction).filter(RemediationAction.scenario_id == scenario_id).all()
    return actions


@app.get(
    "/api/scenarios/{scenario_id}/prioritization",
    response_model=PrioritizationResponse,
    tags=["Prioritization"],
)
async def get_prioritization(
    scenario_id: str,
    max_depth: int = 10,
    max_paths: int = 100,
    min_operational_score: float = 0.0,
    limit: Optional[int] = None,
    sort_by: Literal[
        "operational_rank",
        "chokepoint_score",
        "cvss",
        "feasibility",
        "asset_criticality",
    ] = "operational_rank",
    crown_jewel_first: bool = True,
    entry_point_first: bool = True,
    kev_tier: bool = True,
    chokepoint_weight: float = 1.0,
    feasibility_weight: float = 1.0,
    cvss_weight: float = 1.0,
    epss_weight: float = 0.5,
    asset_criticality_weight: float = 0.5,
    tiebreaker: Literal["finding_id", "asset_id"] = "finding_id",
    db: Session = Depends(get_db),
) -> PrioritizationResponse:
    """Return contextual prioritization profiles for all active findings."""
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    if max_depth < 0:
        raise HTTPException(status_code=400, detail="max_depth must be >= 0")
    if max_paths < 0:
        raise HTTPException(status_code=400, detail="max_paths must be >= 0")
    if min_operational_score < 0:
        raise HTTPException(
            status_code=400,
            detail="min_operational_score must be >= 0",
        )
    if limit is not None and limit < 0:
        raise HTTPException(status_code=400, detail="limit must be >= 0")

    weight_values = {
        "chokepoint_weight": chokepoint_weight,
        "feasibility_weight": feasibility_weight,
        "cvss_weight": cvss_weight,
        "epss_weight": epss_weight,
        "asset_criticality_weight": asset_criticality_weight,
    }
    for name, value in weight_values.items():
        if value < 0:
            raise HTTPException(
                status_code=400,
                detail=f"{name} must be >= 0",
            )

    try:
        policy = OrderingPolicy(
            crown_jewel_first=crown_jewel_first,
            entry_point_first=entry_point_first,
            kev_tier=kev_tier,
            chokepoint_weight=chokepoint_weight,
            feasibility_weight=feasibility_weight,
            cvss_weight=cvss_weight,
            epss_weight=epss_weight,
            asset_criticality_weight=asset_criticality_weight,
            tiebreaker=tiebreaker,
        )
        graph = build_canonical_graph(db, scenario_id)
        all_results = compute_prioritization(
            graph,
            max_depth=max_depth,
            max_paths=max_paths,
            policy=policy,
            scenario_id=scenario_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # Filter AFTER analysis. The operational score itself is not recalculated.
    total_findings = len(all_results)
    results = [
        result
        for result in all_results
        if result.operational_score >= min_operational_score
    ]

    # Presentation-only sorting. operational_rank remains unchanged.
    if sort_by != "operational_rank":
        sort_keys = {
            "chokepoint_score": lambda r: (-r.profile.finding_chokepoint_score, r.profile.finding_id),
            "cvss": lambda r: (-r.profile.cvss_normalized, r.profile.finding_id),
            "feasibility": lambda r: (
                -r.profile.max_path_feasibility_normalized,
                r.profile.finding_id,
            ),
            "asset_criticality": lambda r: (
                -r.profile.asset_criticality_normalized,
                r.profile.finding_id,
            ),
        }
        results = sorted(results, key=sort_keys[sort_by])

    if limit is not None:
        results = results[:limit]

    return PrioritizationResponse(
        scenario_id=scenario_id,
        total_findings=total_findings,
        returned_findings=len(results),
        max_depth_used=max_depth,
        max_paths_used=max_paths,
        min_operational_score=min_operational_score,
        sort_by=sort_by,
        policy={
            "crown_jewel_first": policy.crown_jewel_first,
            "entry_point_first": policy.entry_point_first,
            "kev_tier": policy.kev_tier,
            "chokepoint_weight": policy.chokepoint_weight,
            "feasibility_weight": policy.feasibility_weight,
            "cvss_weight": policy.cvss_weight,
            "epss_weight": policy.epss_weight,
            "asset_criticality_weight": policy.asset_criticality_weight,
            "tiebreaker": policy.tiebreaker,
        },
        items=[result.to_dict() for result in results],
    )


@app.post(
    "/api/scenarios/{scenario_id}/simulate-remediation",
    response_model=SimulationResponse,
    tags=["Simulation"],
)
async def simulate_remediation(
    scenario_id: str,
    request: SimulationRequest,
    db: Session = Depends(get_db),
) -> SimulationResponse:
    """Run deterministic what-if remediation simulation (no persistent mutation)."""
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    if not request.remediation_action_ids:
        raise HTTPException(
            status_code=400, detail="At least one remediation action is required"
        )
    if request.max_depth < 0:
        raise HTTPException(status_code=400, detail="max_depth must be >= 0")
    if request.max_paths < 0:
        raise HTTPException(status_code=400, detail="max_paths must be >= 0")

    try:
        policy = OrderingPolicy(
            crown_jewel_first=request.crown_jewel_first,
            entry_point_first=request.entry_point_first,
            kev_tier=request.kev_tier,
            chokepoint_weight=request.chokepoint_weight,
            feasibility_weight=request.feasibility_weight,
            cvss_weight=request.cvss_weight,
            epss_weight=request.epss_weight,
            asset_criticality_weight=request.asset_criticality_weight,
            tiebreaker=request.tiebreaker,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    rows = (
        db.query(RemediationAction)
        .filter(RemediationAction.id.in_(request.remediation_action_ids))
        .all()
    )
    found_ids = {str(row.id) for row in rows}
    for requested_id in request.remediation_action_ids:
        if requested_id not in found_ids:
            raise HTTPException(
                status_code=404,
                detail=f"Remediation action '{requested_id}' not found",
            )

    try:
        actions = [
            resolve_simulation_action(row, scenario_id)
            for row in sorted(rows, key=lambda r: request.remediation_action_ids.index(str(r.id)))
        ]
        # Preserve request order including duplicates for fail-fast semantics.
        ordered: list = []
        by_id = {a.action_id: a for a in actions}
        for requested_id in request.remediation_action_ids:
            ordered.append(by_id[requested_id])
        graph = build_canonical_graph(db, scenario_id)
        result = run_simulation(
            graph,
            ordered,
            max_depth=request.max_depth,
            max_paths=request.max_paths,
            policy=policy,
            scenario_id=scenario_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return SimulationResponse(**result.to_dict())


@app.post(
    "/api/scenarios/{scenario_id}/optimize-remediation",
    response_model=OptimizationResponse,
    tags=["Optimization"],
)
async def optimize_remediation(
    scenario_id: str,
    request: OptimizationRequest,
    db: Session = Depends(get_db),
) -> OptimizationResponse:
    """Select the optimal feasible remediation set under a budget (read-only)."""
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    if not request.candidate_action_ids:
        raise HTTPException(
            status_code=400, detail="At least one candidate action is required"
        )
    if len(request.candidate_action_ids) > MAX_CANDIDATE_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"At most {MAX_CANDIDATE_ACTIONS} candidate actions are supported "
                f"for exact enumeration, got {len(request.candidate_action_ids)}"
            ),
        )
    if len(set(request.candidate_action_ids)) != len(request.candidate_action_ids):
        raise HTTPException(
            status_code=400, detail="Duplicate candidate_action_ids are not allowed"
        )
    if request.budget < 0:
        raise HTTPException(status_code=400, detail="budget must be >= 0")
    if request.max_depth < 0:
        raise HTTPException(status_code=400, detail="max_depth must be >= 0")
    if request.max_paths < 0:
        raise HTTPException(status_code=400, detail="max_paths must be >= 0")

    rows = (
        db.query(RemediationAction)
        .filter(RemediationAction.id.in_(request.candidate_action_ids))
        .all()
    )
    found_ids = {str(row.id) for row in rows}
    for requested_id in request.candidate_action_ids:
        if requested_id not in found_ids:
            raise HTTPException(
                status_code=404,
                detail=f"Remediation action '{requested_id}' not found",
            )

    try:
        candidates = resolve_candidates(rows, scenario_id)
        graph = build_canonical_graph(db, scenario_id)
        result = optimize(
            graph,
            candidates,
            budget=request.budget,
            max_depth=request.max_depth,
            max_paths=request.max_paths,
            scenario_id=scenario_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return OptimizationResponse(**result.to_dict())


@app.post(
    "/api/scenarios/{scenario_id}/explain",
    tags=["Explanation"],
)
async def explain(
    scenario_id: str,
    request: dict,
    db: Session = Depends(get_db),
) -> dict:
    """Explain deterministic analysis results (read-only; never mutates state)."""
    from backend.app.analysis import explanation as explanation_mod
    from backend.app.services import explanation_provider as provider_mod

    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")

    if not isinstance(request, dict):
        raise HTTPException(status_code=400, detail="Request body must be an object")
    explanation_type = request.get("explanation_type")
    if explanation_type == "finding":
        try:
            typed = FindingExplanationRequest(**request)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        deterministic, assembled = _explain_finding_evidence(
            db, scenario_id, typed, explanation_mod
        )
    elif explanation_type == "simulation":
        try:
            typed = SimulationExplanationRequest(**request)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        deterministic, assembled = _explain_simulation_evidence(
            db, scenario_id, typed, explanation_mod
        )
    elif explanation_type == "optimization":
        try:
            typed = OptimizationExplanationRequest(**request)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        deterministic, assembled = _explain_optimization_evidence(
            db, scenario_id, typed, explanation_mod
        )
    else:
        raise HTTPException(
            status_code=400,
            detail=(
                "Unsupported explanation_type; must be one of "
                "finding, simulation, optimization"
            ),
        )

    try:
        provider = provider_mod.get_default_provider()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    explanation, status, origin = explanation_mod.explain_with_provider(
        assembled, provider, request.get("user_question")
    )
    return {
        "deterministic_result": deterministic,
        "explanation": {
            "scenario_id": scenario_id,
            "explanation_type": explanation_type,
            **explanation,
            "status": status,
            "origin": origin,
        },
    }


def _explain_finding_evidence(db: Session, scenario_id: str, typed, explanation_mod):
    """Reconstruct finding evidence from current prioritization output."""
    from backend.app.analysis.prioritization import OrderingPolicy, compute_prioritization

    if typed.max_depth < 0:
        raise HTTPException(status_code=400, detail="max_depth must be >= 0")
    if typed.max_paths < 0:
        raise HTTPException(status_code=400, detail="max_paths must be >= 0")
    try:
        policy = OrderingPolicy(
            crown_jewel_first=typed.crown_jewel_first,
            entry_point_first=typed.entry_point_first,
            kev_tier=typed.kev_tier,
            chokepoint_weight=typed.chokepoint_weight,
            feasibility_weight=typed.feasibility_weight,
            cvss_weight=typed.cvss_weight,
            epss_weight=typed.epss_weight,
            asset_criticality_weight=typed.asset_criticality_weight,
            tiebreaker=typed.tiebreaker,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    graph = build_canonical_graph(db, scenario_id)
    try:
        results = compute_prioritization(
            graph,
            max_depth=typed.max_depth,
            max_paths=typed.max_paths,
            policy=policy,
            scenario_id=scenario_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    match = next(
        (r for r in results if r.profile.finding_id == typed.finding_id), None
    )
    if match is None:
        raise HTTPException(
            status_code=404,
            detail=(
                f"Finding '{typed.finding_id}' is not represented in the current "
                "active-finding prioritization view and cannot be explained "
                "through it"
            ),
        )
    deterministic = match.to_dict()
    assembled = explanation_mod.assemble_finding_evidence(deterministic)
    return deterministic, assembled


def _explain_simulation_evidence(db: Session, scenario_id: str, typed, explanation_mod):
    """Reconstruct simulation evidence by running the Phase 6 simulation."""
    from backend.app.analysis.prioritization import OrderingPolicy

    if not typed.remediation_action_ids:
        raise HTTPException(
            status_code=400, detail="At least one remediation action is required"
        )
    if typed.max_depth < 0:
        raise HTTPException(status_code=400, detail="max_depth must be >= 0")
    if typed.max_paths < 0:
        raise HTTPException(status_code=400, detail="max_paths must be >= 0")
    try:
        policy = OrderingPolicy(
            crown_jewel_first=typed.crown_jewel_first,
            entry_point_first=typed.entry_point_first,
            kev_tier=typed.kev_tier,
            chokepoint_weight=typed.chokepoint_weight,
            feasibility_weight=typed.feasibility_weight,
            cvss_weight=typed.cvss_weight,
            epss_weight=typed.epss_weight,
            asset_criticality_weight=typed.asset_criticality_weight,
            tiebreaker=typed.tiebreaker,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    rows = (
        db.query(RemediationAction)
        .filter(RemediationAction.id.in_(typed.remediation_action_ids))
        .all()
    )
    found_ids = {str(row.id) for row in rows}
    for requested_id in typed.remediation_action_ids:
        if requested_id not in found_ids:
            raise HTTPException(
                status_code=404,
                detail=f"Remediation action '{requested_id}' not found",
            )
    try:
        actions = [
            resolve_simulation_action(row, scenario_id)
            for row in sorted(
                rows,
                key=lambda r: typed.remediation_action_ids.index(str(r.id)),
            )
        ]
        ordered: list = []
        by_id = {a.action_id: a for a in actions}
        for requested_id in typed.remediation_action_ids:
            ordered.append(by_id[requested_id])
        graph = build_canonical_graph(db, scenario_id)
        result = run_simulation(
            graph,
            ordered,
            max_depth=typed.max_depth,
            max_paths=typed.max_paths,
            policy=policy,
            scenario_id=scenario_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    deterministic = result.to_dict()
    # Datetimes are not JSON-serializable here; the assembler only needs metrics.
    deterministic["simulated_at"] = str(deterministic.get("simulated_at"))
    assembled = explanation_mod.assemble_simulation_evidence(deterministic)
    return deterministic, assembled


def _explain_optimization_evidence(db: Session, scenario_id: str, typed, explanation_mod):
    """Reconstruct optimization evidence by running the Phase 7 optimizer."""
    from backend.app.analysis.budget_optimization import (
        MAX_CANDIDATE_ACTIONS,
        optimize,
        resolve_candidates,
    )

    if not typed.candidate_action_ids:
        raise HTTPException(
            status_code=400, detail="At least one candidate action is required"
        )
    if len(typed.candidate_action_ids) > MAX_CANDIDATE_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=(
                f"At most {MAX_CANDIDATE_ACTIONS} candidate actions are supported "
                f"for exact enumeration, got {len(typed.candidate_action_ids)}"
            ),
        )
    if len(set(typed.candidate_action_ids)) != len(typed.candidate_action_ids):
        raise HTTPException(
            status_code=400, detail="Duplicate candidate_action_ids are not allowed"
        )
    if typed.budget < 0:
        raise HTTPException(status_code=400, detail="budget must be >= 0")
    if typed.max_depth < 0:
        raise HTTPException(status_code=400, detail="max_depth must be >= 0")
    if typed.max_paths < 0:
        raise HTTPException(status_code=400, detail="max_paths must be >= 0")
    rows = (
        db.query(RemediationAction)
        .filter(RemediationAction.id.in_(typed.candidate_action_ids))
        .all()
    )
    found_ids = {str(row.id) for row in rows}
    for requested_id in typed.candidate_action_ids:
        if requested_id not in found_ids:
            raise HTTPException(
                status_code=404,
                detail=f"Remediation action '{requested_id}' not found",
            )
    try:
        candidates = resolve_candidates(rows, scenario_id)
        graph = build_canonical_graph(db, scenario_id)
        result = optimize(
            graph,
            candidates,
            budget=typed.budget,
            max_depth=typed.max_depth,
            max_paths=typed.max_paths,
            scenario_id=scenario_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    deterministic = result.to_dict()
    deterministic["optimized_at"] = str(deterministic.get("optimized_at"))
    # computed_at datetimes inside prioritization items are not JSON-safe here;
    # the assembler only consumes metric fields.
    assembled = explanation_mod.assemble_optimization_evidence(deterministic)
    return deterministic, assembled


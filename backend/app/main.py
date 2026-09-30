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


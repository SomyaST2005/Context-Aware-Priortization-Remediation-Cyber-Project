"""
FastAPI application entrypoint for the cybersecurity remediation prioritization system.
"""
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from typing import List
import networkx as nx

from backend.app.models.database import Base, Scenario
from backend.app.schemas.scenario import ScenarioCreate, ScenarioResponse, ScenarioUpdate
from backend.app.schemas.asset import AssetResponse
from backend.app.schemas.finding import FindingResponse
from backend.app.schemas.edge import EdgeResponse
from backend.app.graph.builder import build_canonical_graph, CanonicalGraphBuilder
from backend.app.core.database import get_db, engine

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


# Basic asset endpoints (for testing/seeding)
@app.get("/api/scenarios/{scenario_id}/assets", response_model=List[AssetResponse], tags=["Assets"])
async def get_scenario_assets(scenario_id: str, db: Session = Depends(get_db)):
    """Get all assets in a scenario."""
    # Verify scenario exists
    scenario = db.query(Scenario).filter(Scenario.id == scenario_id).first()
    if scenario is None:
        raise HTTPException(status_code=404, detail="Scenario not found")
    
    # For now, return all assets (in future, we might filter by scenario)
    assets = db.query(Asset).all()
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
    findings = db.query(Finding).all()
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
    edges = db.query(Edge).all()
    return edges
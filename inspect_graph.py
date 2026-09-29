from backend.app.core.database import SessionLocal
from backend.app.graph.builder import build_canonical_graph
from backend.app.models.database import Scenario

db = SessionLocal()
try:
    scenario = db.query(Scenario).filter(Scenario.id == 'basic_test_scenario').first()
    graph = build_canonical_graph(db, scenario.id)
    print('Nodes:')
    for node_id, node_data in graph.nodes(data=True):
        print(f'  {node_id}: type={node_data.get("type")}, is_entry_point={node_data.get("is_entry_point")}, is_crown_jewel={node_data.get("is_crown_jewel")}')
    print()
    print('Edges:')
    for u, v, edge_data in graph.edges(data=True):
        print(f'  {u} -> {v}: edge_type={edge_data.get("edge_type")}, cost={edge_data.get("traversal_cost")}, prob={edge_data.get("probability")}, edge_id={edge_data.get("edge_id")}')
finally:
    db.close()
"""Focused tests for Phase 10 demo remediation seed data.

Idempotent by construction: ensure_remediation_seed_data() never duplicates.
Does not delete seed rows (they are permanent demo data).
"""
from fastapi.testclient import TestClient

from backend.app.core.database import SessionLocal
from backend.data.seeds.seed_data import (
    _remediation_seed_rows,
    ensure_remediation_seed_data,
)
from backend.app.main import app
from backend.app.models.database import RemediationAction

SID = "basic_test_scenario"
client = TestClient(app)

MVP_TYPES = {
    "PATCH_VULNERABILITY",
    "REMOVE_VULNERABILITY",
    "REMOVE_NETWORK_PATH",
    "RESTRICT_PORT",
    "ISOLATE_ASSET",
}


def test_seed_rows_use_mvp_types_and_real_targets():
    from backend.app.models.database import Asset, Edge, Finding

    db = SessionLocal()
    try:
        asset_ids = {r.id for r in db.query(Asset.id).all()}
        finding_ids = {r.id for r in db.query(Finding.id).all()}
        edge_ids = {r.id for r in db.query(Edge.id).all()}
    finally:
        db.close()
    assert len(_remediation_seed_rows()) >= 3
    for row in _remediation_seed_rows():
        assert row.action_type.value in MVP_TYPES
        targets = [
            t for t in (row.target_asset_id, row.target_finding_id, row.target_edge_id)
            if t is not None
        ]
        assert len(targets) == 1, f"{row.id} must have exactly one target"
        target = targets[0]
        assert target in asset_ids | finding_ids | edge_ids, f"dangling target {target}"


def test_seed_ensure_is_idempotent():
    db = SessionLocal()
    try:
        before = db.query(RemediationAction).count()
        ensure_remediation_seed_data(db)
        db.commit()
        after_first = db.query(RemediationAction).count()
        ensure_remediation_seed_data(db)
        db.commit()
        after_second = db.query(RemediationAction).count()
    finally:
        db.close()
    assert after_first >= 3
    assert after_second == after_first


def test_list_remediation_actions_endpoint():
    response = client.get(f"/api/scenarios/{SID}/remediation-actions")
    assert response.status_code == 200
    body = response.json()
    assert len(body) >= 3
    ids = {a["id"] for a in body}
    assert {r.id for r in _remediation_seed_rows()} <= ids


def test_list_remediation_actions_unknown_scenario():
    assert client.get("/api/scenarios/nope/remediation-actions").status_code == 404


def test_seed_entities_are_scenario_scoped():
    """Fresh seeds must scope every row so scenario-filtered endpoints work."""
    from backend.app.models.database import Asset, Edge, Finding, Vulnerability

    db = SessionLocal()
    try:
        for model in (Asset, Finding, Edge, Vulnerability, RemediationAction):
            rows = db.query(model).filter(model.scenario_id == SID).all()
            assert len(rows) > 0, f"{model.__name__} has no rows for {SID}"
            assert db.query(model).filter(model.scenario_id.is_(None)).count() == 0
    finally:
        db.close()

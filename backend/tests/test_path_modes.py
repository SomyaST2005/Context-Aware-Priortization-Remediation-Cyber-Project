"""
Regression tests for shortest/cheapest path modes.

get_shortest_path and get_cheapest_path must return the GLOBALLY optimal
feasible path (not merely the first one discovered), with deterministic
tie-breaking, cycle safety, depth limits, and MultiDiGraph parallel-edge
support. find_attack_paths ("all" mode) semantics are asserted unchanged.

All graphs here are synthetic NetworkX objects; no database is involved.
"""
import networkx as nx
import pytest

from backend.app.analysis.path_analysis import (
    find_attack_paths,
    get_cheapest_path,
    get_shortest_path,
)


def make_graph():
    return nx.MultiDiGraph()


def add_node(g, node_id, entry=False, crown=False):
    g.add_node(
        node_id, type="asset", is_entry_point=entry, is_crown_jewel=crown
    )


def add_edge(g, edge_id, source, target, cost=1.0, prob=0.5):
    g.add_edge(
        source,
        target,
        edge_id=edge_id,
        edge_type="CAN_REACH",
        traversal_cost=cost,
        probability=prob,
    )


def test_shortest_prefers_later_entry_with_fewer_hops():
    """A: entry inserted first has a long chain; later entry is direct."""
    g = make_graph()
    add_node(g, "entry-a", entry=True)
    add_node(g, "entry-b", entry=True)
    add_node(g, "x")
    add_node(g, "y")
    add_node(g, "crown", crown=True)
    add_edge(g, "e-a-x", "entry-a", "x")
    add_edge(g, "e-x-y", "x", "y")
    add_edge(g, "e-y-c", "y", "crown")
    add_edge(g, "e-b-c", "entry-b", "crown")

    shortest = get_shortest_path(g)
    assert shortest is not None
    assert shortest.hop_count == 1
    assert shortest.entry_point == "entry-b"
    assert shortest.crown_jewel == "crown"
    assert shortest.nodes == ["entry-b", "crown"]


def test_cheapest_found_despite_many_earlier_paths():
    """B: 1100 cheap-to-discover 2-hop decoys precede one cheap 4-hop path.

    The old implementation capped enumeration at 1000 paths and would have
    returned a cost-9.0 decoy. The fix must return the global optimum.
    """
    g = make_graph()
    add_node(g, "entry", entry=True)
    add_node(g, "crown", crown=True)
    for i in range(1100):
        mid = f"decoy-{i:04d}"
        add_node(g, mid)
        add_edge(g, f"e-in-{i:04d}", "entry", mid, cost=4.5)
        add_edge(g, f"e-out-{i:04d}", mid, "crown", cost=4.5)
    add_node(g, "m1")
    add_node(g, "m2")
    add_node(g, "m3")
    add_edge(g, "e-c0", "entry", "m1", cost=0.2)
    add_edge(g, "e-c1", "m1", "m2", cost=0.1)
    add_edge(g, "e-c2", "m2", "m3", cost=0.1)
    add_edge(g, "e-c3", "m3", "crown", cost=0.1)

    cheapest = get_cheapest_path(g)
    assert cheapest is not None
    assert cheapest.total_traversal_cost == pytest.approx(0.5)
    assert cheapest.hop_count == 4
    assert cheapest.nodes == ["entry", "m1", "m2", "m3", "crown"]


def test_shortest_tiebreak_is_deterministic():
    """C: equal-hop, equal-cost candidates break ties deterministically."""
    g = make_graph()
    # Insertion order: entry-b first, so entry-order tiebreak picks it.
    add_node(g, "entry-b", entry=True)
    add_node(g, "entry-a", entry=True)
    add_node(g, "crown", crown=True)
    add_edge(g, "e-b", "entry-b", "crown", cost=2.0)
    add_edge(g, "e-a", "entry-a", "crown", cost=2.0)

    first = get_shortest_path(g)
    second = get_shortest_path(g)
    assert first is not None and second is not None
    assert first.entry_point == "entry-b"
    assert first.to_dict() == second.to_dict()

    # Parallel edges: lexicographically smaller edge id wins the tie,
    # regardless of insertion order (edge-b inserted first).
    g2 = make_graph()
    add_node(g2, "entry", entry=True)
    add_node(g2, "crown", crown=True)
    add_edge(g2, "edge-b", "entry", "crown", cost=5.0)
    add_edge(g2, "edge-a", "entry", "crown", cost=5.0)
    winner = get_shortest_path(g2)
    assert winner is not None
    assert winner.edges == ["edge-a"]
    assert get_shortest_path(g2).to_dict() == winner.to_dict()


def test_cheapest_tiebreak_prefers_fewer_hops_and_repeats():
    """D: equal-cost candidates break ties deterministically."""
    g = make_graph()
    add_node(g, "entry", entry=True)
    add_node(g, "mid", entry=False)
    add_node(g, "crown", crown=True)
    add_edge(g, "e-direct", "entry", "crown", cost=4.0)
    add_edge(g, "e-1", "entry", "mid", cost=2.0)
    add_edge(g, "e-2", "mid", "crown", cost=2.0)

    first = get_cheapest_path(g)
    second = get_cheapest_path(g)
    assert first is not None and second is not None
    assert first.total_traversal_cost == pytest.approx(4.0)
    assert first.hop_count == 1
    assert first.to_dict() == second.to_dict()


def test_depth_limits_are_respected():
    """E: paths deeper than max_depth are invisible to both modes."""
    g = make_graph()
    add_node(g, "entry", entry=True)
    add_node(g, "a")
    add_node(g, "b")
    add_node(g, "crown", crown=True)
    add_edge(g, "e0", "entry", "a")
    add_edge(g, "e1", "a", "b")
    add_edge(g, "e2", "b", "crown")

    assert get_shortest_path(g, max_depth=2) is None
    assert get_cheapest_path(g, max_depth=2) is None
    assert get_shortest_path(g, max_depth=0) is None
    short = get_shortest_path(g, max_depth=3)
    cheap = get_cheapest_path(g, max_depth=3)
    assert short is not None and short.hop_count == 3
    assert cheap is not None and cheap.hop_count == 3


def test_parallel_edges_cheapest_uses_cheapest_edge():
    """F: parallel MultiDiGraph edges are distinguished by edge id."""
    g = make_graph()
    add_node(g, "entry", entry=True)
    add_node(g, "mid")
    add_node(g, "crown", crown=True)
    add_edge(g, "e-high", "entry", "mid", cost=3.0, prob=0.9)
    add_edge(g, "e-low", "entry", "mid", cost=1.0, prob=0.5)
    add_edge(g, "e-mid-c", "mid", "crown", cost=1.0, prob=0.5)

    cheapest = get_cheapest_path(g)
    assert cheapest is not None
    assert cheapest.total_traversal_cost == pytest.approx(2.0)
    assert cheapest.edges == ["e-low", "e-mid-c"]
    assert cheapest.total_probability == pytest.approx(0.25)


def test_all_mode_behavior_unchanged():
    """G: find_attack_paths keeps its cap, ordering, ids, and cycle safety."""
    g = make_graph()
    add_node(g, "entry", entry=True)
    add_node(g, "mid")
    add_node(g, "crown", crown=True)
    add_edge(g, "e-direct", "entry", "crown", cost=3.0)
    add_edge(g, "e-1", "entry", "mid", cost=1.0)
    add_edge(g, "e-2", "mid", "crown", cost=1.0)
    # Back edge creates a cycle; enumeration must terminate without revisits.
    add_edge(g, "e-back", "mid", "entry", cost=1.0)

    paths = find_attack_paths(g, max_depth=10, max_paths=100)
    assert [p.id for p in paths] == ["path_0", "path_1"]
    assert [(p.hop_count, p.total_traversal_cost) for p in paths] == [(1, 3.0), (2, 2.0)]
    for p in paths:
        assert len(set(p.nodes)) == len(p.nodes)

    assert len(find_attack_paths(g, max_depth=10, max_paths=1)) == 1
    assert find_attack_paths(g, max_depth=0) == []

from __future__ import annotations

import time
from pathlib import Path

from conftest import envelopes

from semgrep_relay.store import Store

FINDING = envelopes("finding")[0]
SCAN = envelopes("scan")[0]


def make_store(tmp_path: Path) -> Store:
    return Store(str(tmp_path / "relay.db"))


def test_accept_queues_one_delivery_per_connector(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    result = store.accept([(FINDING, ["siem", "chat"]), (SCAN, [])])
    assert (result.new_events, result.duplicate_events, result.deliveries_created) == (2, 0, 2)
    jobs = store.due_deliveries(limit=10)
    assert sorted(job.connector for job in jobs) == ["chat", "siem"]
    assert jobs[0].envelope == FINDING


def test_duplicate_events_queue_nothing(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.accept([(FINDING, ["siem"])])
    again = store.accept([(FINDING.model_copy(update={"delivery_id": "other"}), ["siem"])])
    assert (again.new_events, again.duplicate_events, again.deliveries_created) == (0, 1, 0)
    assert len(store.due_deliveries(limit=10)) == 1


def test_events_survive_reopening(tmp_path: Path) -> None:
    make_store(tmp_path).accept([(FINDING, ["siem"])])
    assert len(make_store(tmp_path).due_deliveries(limit=10)) == 1


def test_due_deliveries_skips_in_flight_and_future(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.accept([(FINDING, ["siem"]), (SCAN, ["siem"])])
    first, second = store.due_deliveries(limit=10)
    assert [j.id for j in store.due_deliveries(limit=10, exclude_ids=[first.id])] == [second.id]
    store.mark_retry(second.id, 1, time.time() + 60, "HTTP 503")
    assert [j.id for j in store.due_deliveries(limit=10)] == [first.id]


def test_retry_dead(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.accept([(FINDING, ["siem"]), (SCAN, ["chat"])])
    for job in store.due_deliveries(limit=10):
        store.mark_dead(job.id, 3, "HTTP 401")
    assert store.status_counts() == {"pending": 0, "delivered": 0, "dead": 2}
    assert store.retry_dead("chat") == 1
    assert store.retry_dead() == 1
    assert {j.attempts for j in store.due_deliveries(limit=10)} == {0}


def test_prune_keeps_events_with_pending_deliveries(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.accept([(FINDING, ["siem"]), (SCAN, ["siem"])])
    delivered = next(j for j in store.due_deliveries(limit=10) if j.event_id == SCAN.event_id)
    store.mark_delivered(delivered.id, 1)
    assert store.prune(older_than=time.time() + 1) == 1
    assert [j.event_id for j in store.due_deliveries(limit=10)] == [FINDING.event_id]
    # A pruned event is no longer a duplicate.
    assert store.accept([(SCAN, ["siem"])]).new_events == 1


def test_errors_are_truncated(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    store.accept([(FINDING, ["siem"])])
    [job] = store.due_deliveries(limit=1)
    store.mark_retry(job.id, 1, 0, "x" * 5000)
    row = store._conn.execute("SELECT last_error FROM deliveries").fetchone()
    assert len(row[0]) == 500


def test_correlations(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    assert store.get_correlation("tickets", "finding:1") is None
    store.put_correlation("tickets", "finding:1", "SEC-1")
    store.put_correlation("tickets", "finding:1", "SEC-2")
    assert store.get_correlation("tickets", "finding:1") == "SEC-2"

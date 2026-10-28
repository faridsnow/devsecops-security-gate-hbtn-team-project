#!/usr/bin/env python3
"""
Test suite for DevSecOps Live Security Dashboard Flask Application (app.py).
Tests:
  1. GET / returns 200 and loads HTML with 'DevSecOps Live Security Dashboard'
  2. GET /api/health returns 200 and 'healthy'
  3. GET /api/report returns 200 and valid JSON
  4. POST /api/webhook without X-API-Key returns 403
  5. POST /api/webhook with correct X-API-Key ('devsecops-local-dev') updates latest_report.json and returns 200
  6. GET /api/history returns 200 and has the newly posted scan in history
"""

import json
import pytest
from pathlib import Path
from app import app, REPORT_FILE, HISTORY_FILE, API_KEY


@pytest.fixture
def client():
    app.config["TESTING"] = True
    rep_backup = REPORT_FILE.read_bytes() if REPORT_FILE.exists() else None
    hist_backup = HISTORY_FILE.read_bytes() if HISTORY_FILE.exists() else None
    with app.test_client() as client:
        yield client
    if rep_backup is not None:
        REPORT_FILE.write_bytes(rep_backup)
    elif REPORT_FILE.exists():
        REPORT_FILE.unlink()
    if hist_backup is not None:
        HISTORY_FILE.write_bytes(hist_backup)
    elif HISTORY_FILE.exists():
        HISTORY_FILE.unlink()


@pytest.fixture
def sample_payload():
    return {
        "timestamp": "2026-09-22T01:15:00Z",
        "scanner_version": "1.0.0",
        "status": "PASSED",
        "summary": {
            "files_scanned": 12,
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        },
        "findings": [],
        "git_info": {
            "commit": "a1b2c3d4e5f6",
            "branch": "feature/testing",
            "author": "Agent-001",
            "message": "Verify automated security gate webhook"
        }
    }


def test_get_dashboard_html(client):
    """GET / returns 200 and loads HTML with 'DevSecOps Live Security Dashboard'"""
    response = client.get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "DevSecOps Live Security Dashboard" in html


def test_get_api_health(client):
    """GET /api/health returns 200 and 'healthy'"""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.get_json()
    assert data is not None
    assert "healthy" in data.get("status", "")


def test_get_api_report(client):
    """GET /api/report returns 200 and valid JSON"""
    response = client.get("/api/report")
    assert response.status_code == 200
    data = response.get_json()
    assert isinstance(data, dict)
    assert "status" in data
    assert "summary" in data


def test_post_webhook_without_api_key(client, sample_payload):
    """POST /api/webhook without X-API-Key returns 403"""
    response = client.post(
        "/api/webhook",
        json=sample_payload
    )
    assert response.status_code == 403


def test_post_webhook_with_invalid_api_key(client, sample_payload):
    """POST /api/webhook with wrong X-API-Key returns 403"""
    response = client.post(
        "/api/webhook",
        headers={"X-API-Key": "wrong-key"},
        json=sample_payload
    )
    assert response.status_code == 403


def test_post_webhook_with_valid_key_updates_report(client, sample_payload):
    """
    POST /api/webhook with correct X-API-Key ('devsecops-local-dev')
    updates latest_report.json and returns 200
    """
    response = client.post(
        "/api/webhook",
        headers={"X-API-Key": "devsecops-local-dev"},
        json=sample_payload
    )
    assert response.status_code == 200
    resp_data = response.get_json()
    assert resp_data["status"] == "ok"
    assert resp_data["findings"] == 0

    # Verify latest_report.json file on disk
    assert REPORT_FILE.exists()
    with open(REPORT_FILE, "r", encoding="utf-8") as f:
        saved_report = json.load(f)
    assert saved_report["git_info"]["commit"] == sample_payload["git_info"]["commit"]
    assert saved_report["git_info"]["message"] == sample_payload["git_info"]["message"]
    assert saved_report["status"] == "PASSED"


def test_get_history_has_newly_posted_scan(client, sample_payload):
    """GET /api/history returns 200 and has the newly posted scan in history"""
    # First post the sample
    client.post(
        "/api/webhook",
        headers={"X-API-Key": API_KEY},
        json=sample_payload
    )

    response = client.get("/api/history")
    assert response.status_code == 200
    history = response.get_json()
    assert isinstance(history, list)
    assert len(history) > 0

    # Check the latest history entry matches the scan
    latest_entry = history[0]
    expected_short_commit = sample_payload["git_info"]["commit"][:7]
    assert latest_entry["commit"] == expected_short_commit
    assert latest_entry["branch"] == sample_payload["git_info"]["branch"]
    assert latest_entry["status"] == sample_payload["status"]


def test_post_webhook_invalid_payload(client):
    """POST /api/webhook with invalid payload returns 400"""
    response = client.post(
        "/api/webhook",
        headers={"X-API-Key": API_KEY},
        data="not-a-valid-json",
        content_type="text/plain"
    )
    assert response.status_code == 400


def test_post_webhook_null_or_sparse_fields(client):
    """POST /api/webhook with sparse/null fields should not crash"""
    sparse_payload = {
        "status": "UNKNOWN",
        "summary": None,
        "git_info": None
    }
    response = client.post(
        "/api/webhook",
        headers={"X-API-Key": API_KEY},
        json=sparse_payload
    )
    assert response.status_code == 200
    assert response.get_json()["status"] == "ok"


def test_load_report_with_fallback(client):
    """load_report returns valid structure and default when file is empty/missing"""
    from app import load_report, REPORT_FILE
    # ensure it returns a valid dict with status, summary, git_info
    rep = load_report()
    assert isinstance(rep, dict)
    assert "status" in rep
    assert "summary" in rep
    assert "git_info" in rep


if __name__ == "__main__":
    pytest.main(["-v", __file__])

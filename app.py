#!/usr/bin/env python3
"""
=============================================================================
 DevSecOps Live Dashboard — Flask Web Application
-----------------------------------------------------------------------------
 Render.com-da deploy olunan canlı təhlükəsizlik paneli.
 GitHub Actions scan nəticələrini webhook vasitəsilə qəbul edir.
=============================================================================
"""

import os
import json
import hmac
from pathlib import Path
from datetime import datetime, timezone
from flask import Flask, render_template, jsonify, request, abort

app = Flask(__name__)

DATA_DIR = Path(__file__).parent / "data"
REPORT_FILE = DATA_DIR / "latest_report.json"
HISTORY_FILE = DATA_DIR / "scan_history.json"

# API key webhook-u qorumaq üçün
API_KEY = os.environ.get("DASHBOARD_API_KEY", "devsecops-local-dev")


def get_default_report():
    """Boş/default hesabat qaytarır."""
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scanner_version": "1.0.0",
        "status": "NO_DATA",
        "summary": {
            "files_scanned": 0,
            "total_findings": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0
        },
        "findings": [],
        "git_info": {
            "commit": "N/A",
            "branch": "N/A",
            "author": "N/A",
            "message": "Hələ heç bir skan nəticəsi alınmayıb"
        }
    }


def load_report():
    """Ən son scan hesabatını yükləyir."""
    if REPORT_FILE.exists():
        try:
            with open(REPORT_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict) and isinstance(data.get("summary"), dict) and isinstance(data.get("git_info"), dict):
                    return data
        except (json.JSONDecodeError, IOError):
            pass
    return get_default_report()


def save_report(data):
    """Scan hesabatını saxlayır."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_history():
    """Skan tarixçəsini yükləyir."""
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return []


def save_to_history(report):
    """Son 20 skan nəticəsini tarixçədə saxlayır."""
    history = load_history()
    git_info = report.get("git_info") or {}
    summary = report.get("summary") or {}
    commit_val = git_info.get("commit") or "N/A"
    msg_val = git_info.get("message") or "N/A"
    entry = {
        "timestamp": report.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        "status": report.get("status") or "UNKNOWN",
        "total_findings": summary.get("total_findings", 0),
        "critical": summary.get("critical", 0),
        "high": summary.get("high", 0),
        "commit": str(commit_val)[:7],
        "branch": str(git_info.get("branch") or "N/A"),
        "message": str(msg_val)[:60]
    }
    history.insert(0, entry)
    history = history[:20]  # Son 20 nəticə
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(HISTORY_FILE, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)


# ─── Routes ────────────────────────────────────────────────────────────────

@app.route("/")
def dashboard():
    """Ana dashboard səhifəsi."""
    return render_template("index.html")


@app.route("/api/report")
def get_report():
    """Son scan nəticəsini JSON olaraq qaytarır."""
    return jsonify(load_report())


@app.route("/api/history")
def get_history():
    """Skan tarixçəsini qaytarır."""
    return jsonify(load_history())


@app.route("/api/webhook", methods=["POST"])
def receive_webhook():
    """GitHub Actions-dan scan nəticəsini qəbul edir."""
    # API key yoxlaması
    auth_key = request.headers.get("X-API-Key", "")
    if not hmac_compare(auth_key, API_KEY):
        abort(403, description="Invalid API key")

    data = request.get_json(force=True, silent=True)
    if not data or not isinstance(data, dict):
        abort(400, description="Invalid JSON payload")

    save_report(data)
    save_to_history(data)

    summary = data.get("summary") or {}
    return jsonify({
        "status": "ok",
        "message": "Report received and dashboard updated",
        "findings": summary.get("total_findings", 0)
    }), 200


@app.route("/api/health")
def health():
    """Sağlamlıq yoxlaması."""
    return jsonify({"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()})


def hmac_compare(a: str, b: str) -> bool:
    """Sabit vaxtlı müqayisə (timing attack-lardan qorunma)."""
    return hmac.compare_digest(str(a), str(b))


# ─── Main ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    app.run(host=host, port=port, debug=False)

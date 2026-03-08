import argparse
import json
import os
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
import hmac
import hashlib
import re

from flask import Flask, jsonify, render_template, render_template_string, request

ROOT = Path(__file__).resolve().parent
PACKAGE_TEMPLATES = ROOT / "anomalyx_core" / "templates"
DEV_TEMPLATES = ROOT / "templates"

_template_dir = PACKAGE_TEMPLATES if PACKAGE_TEMPLATES.exists() else DEV_TEMPLATES
app = Flask(__name__, template_folder=str(_template_dir))

SERVER_TOKEN = os.getenv("DASHBOARD_SERVER_TOKEN", "change-me")
SERVER_TOKEN_HASH = os.getenv("DASHBOARD_SERVER_TOKEN_HASH", "")
if not SERVER_TOKEN_HASH:
    SERVER_TOKEN_HASH = hashlib.sha256(SERVER_TOKEN.encode("utf-8")).hexdigest()

STRICT_AUTH = os.getenv("DASHBOARD_STRICT_AUTH", "1") == "1"
MAX_BODY_BYTES = int(os.getenv("DASHBOARD_MAX_BODY_BYTES", "262144"))
MAX_EVENTS_PER_AGENT = int(os.getenv("DASHBOARD_MAX_EVENTS_PER_AGENT", "600"))
RATE_LIMIT_PER_MIN = int(os.getenv("DASHBOARD_RATE_LIMIT_PER_MIN", "1800"))
ALLOWED_ORIGIN = os.getenv("DASHBOARD_ALLOWED_ORIGIN", "")
TIMESTAMP_SKEW_SEC = int(os.getenv("DASHBOARD_TIMESTAMP_SKEW_SEC", "120"))
ADMIN_TOKEN = os.getenv("DASHBOARD_ADMIN_TOKEN", SERVER_TOKEN)

AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{3,64}$")

agent_status = {}
agent_events = defaultdict(lambda: deque(maxlen=MAX_EVENTS_PER_AGENT))
agent_last_seen = {}
rate_buckets = defaultdict(deque)
agent_commands = defaultdict(lambda: deque(maxlen=200))


def now_iso():
    return datetime.utcnow().isoformat()


def _safe_compare_hash(token_value):
    token_hash = hashlib.sha256((token_value or "").encode("utf-8")).hexdigest()
    return hmac.compare_digest(token_hash, SERVER_TOKEN_HASH)


def _client_key(req):
    return request.remote_addr or "unknown"


def _rate_limit_ok(req, route_key):
    now = time.time()
    key = f"{_client_key(req)}:{route_key}"
    bucket = rate_buckets[key]
    while bucket and (now - bucket[0]) > 60.0:
        bucket.popleft()
    if len(bucket) >= RATE_LIMIT_PER_MIN:
        return False
    bucket.append(now)
    return True


def _validate_agent_id(agent_id):
    return bool(AGENT_ID_PATTERN.match(str(agent_id or "")))


def _validate_signature(req, raw_body):
    # Backward compatibility path if strict auth is disabled.
    if not STRICT_AUTH:
        return _safe_compare_hash(req.headers.get("X-Agent-Token", "")), "token_only"

    token = req.headers.get("X-Agent-Token", "")
    header_agent_id = req.headers.get("X-Agent-Id", "")
    header_ts = req.headers.get("X-Agent-Timestamp", "")
    header_sig = req.headers.get("X-Agent-Signature", "")

    if not (_safe_compare_hash(token) and header_agent_id and header_ts and header_sig):
        return False, "missing_or_invalid_auth_headers"

    try:
        ts_int = int(header_ts)
    except ValueError:
        return False, "invalid_timestamp"

    if abs(int(time.time()) - ts_int) > TIMESTAMP_SKEW_SEC:
        return False, "timestamp_out_of_window"

    message = f"{header_agent_id}.{header_ts}.{raw_body.decode('utf-8', errors='ignore')}".encode("utf-8")
    expected = hmac.new(token.encode("utf-8"), message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, header_sig):
        return False, "signature_mismatch"

    return True, "signed"


def _sanitize_value(value, depth=0):
    if depth > 5:
        return "<max_depth>"

    if isinstance(value, dict):
        out = {}
        for k, v in list(value.items())[:80]:
            key = str(k)[:80]
            out[key] = _sanitize_value(v, depth + 1)
        return out

    if isinstance(value, list):
        return [_sanitize_value(v, depth + 1) for v in value[:120]]

    if isinstance(value, str):
        return value[:1500]

    if isinstance(value, (int, float, bool)) or value is None:
        return value

    return str(value)[:200]


def _require_admin_token(req):
    supplied = req.headers.get("X-Admin-Token", "")
    if not supplied:
        return False
    supplied_hash = hashlib.sha256(supplied.encode("utf-8")).hexdigest()
    expected_hash = hashlib.sha256((ADMIN_TOKEN or "").encode("utf-8")).hexdigest()
    return hmac.compare_digest(supplied_hash, expected_hash)


def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _agent_rollup(agent_id):
    status = agent_status.get(agent_id) or {}
    actions = status.get("actions") or {}
    events = list(agent_events[agent_id])

    alert_count = _safe_int(actions.get("alert", 0))
    temp_block_count = _safe_int(actions.get("temp_block_ip", 0))
    block_count = _safe_int(actions.get("block_ip", 0))

    # If status counters are missing/stale, fallback to event-derived counts.
    if alert_count == 0 and temp_block_count == 0 and block_count == 0 and events:
        for ev in events:
            act = str((ev.get("decision") or {}).get("action") or "").lower()
            if act == "alert":
                alert_count += 1
            elif act == "temp_block_ip":
                temp_block_count += 1
            elif act == "block_ip":
                block_count += 1

    applied = 0
    failed = 0
    skipped = 0
    for ev in events:
        enf_status = str((ev.get("enforcement") or {}).get("status") or "").lower()
        if enf_status == "applied":
            applied += 1
        elif enf_status == "failed":
            failed += 1
        elif enf_status == "skipped":
            skipped += 1

    return {
        "agent_id": agent_id,
        "last_seen": agent_last_seen.get(agent_id),
        "running": bool(status.get("running", False)),
        "processed_packets": _safe_int(status.get("processed_packets", 0)),
        "alerts": alert_count,
        "temp_blocks": temp_block_count,
        "blocks": block_count,
        "enforcement": {
            "applied": applied,
            "failed": failed,
            "skipped": skipped,
        },
        "actions": actions,
    }


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = ALLOWED_ORIGIN if ALLOWED_ORIGIN else request.host_url.rstrip("/")
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-Agent-Token, X-Agent-Id, X-Agent-Timestamp, X-Agent-Signature, X-Admin-Token"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"
    return response


@app.route("/")
def home():
        try:
                return render_template("landing.html")
        except Exception:
                return render_template_string(
                        """
                        <!doctype html>
                        <html>
                        <head>
                            <meta charset=\"utf-8\" />
                            <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
                            <title>AnomalyX Dashboard</title>
                            <style>
                                body { font-family: Segoe UI, sans-serif; margin: 24px; background: #f6f8fb; }
                                .card { max-width: 640px; margin: 0 auto; background: #fff; border-radius: 12px; padding: 20px; box-shadow: 0 6px 20px rgba(0,0,0,.08); }
                                input, button { font-size: 16px; padding: 10px 12px; }
                                input { width: 70%; }
                                button { margin-left: 8px; cursor: pointer; }
                            </style>
                        </head>
                        <body>
                            <div class=\"card\">
                                <h2>AnomalyX Relay</h2>
                                <p>Enter an Agent ID to open live monitoring.</p>
                                <input id=\"agentId\" placeholder=\"win-vm-001\" />
                                <button onclick=\"go()\">Open</button>
                            </div>
                            <script>
                                function go() {
                                    const id = (document.getElementById('agentId').value || '').trim();
                                    if (!id) return;
                                    window.location.href = '/dashboard/' + encodeURIComponent(id);
                                }
                            </script>
                        </body>
                        </html>
                        """
                )


@app.route("/dashboard/<agent_id>")
def dashboard(agent_id):
        try:
                return render_template("dashboard.html", agent_id=agent_id)
        except Exception:
                return render_template_string(
                        """
                        <!doctype html>
                        <html>
                        <head>
                            <meta charset=\"utf-8\" />
                            <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
                            <title>AnomalyX Live</title>
                            <style>
                                body { font-family: Segoe UI, sans-serif; margin: 18px; background: #f6f8fb; }
                                .row { display: flex; gap: 12px; flex-wrap: wrap; }
                                .card { background: #fff; border-radius: 10px; padding: 12px; box-shadow: 0 4px 14px rgba(0,0,0,.06); }
                                .full { width: 100%; }
                                pre { white-space: pre-wrap; word-break: break-word; font-size: 12px; }
                            </style>
                        </head>
                        <body>
                            <h2>AnomalyX Agent: {{ agent_id }}</h2>
                            <div class=\"row\">
                                <div class=\"card full\"><strong>Status</strong><pre id=\"status\">loading...</pre></div>
                                <div class=\"card full\"><strong>Recent Events</strong><pre id=\"events\">loading...</pre></div>
                            </div>
                            <script>
                                async function refresh() {
                                    const r = await fetch('/api/agent/{{ agent_id }}/snapshot');
                                    const data = await r.json();
                                    document.getElementById('status').textContent = JSON.stringify(data.status || {}, null, 2);
                                    document.getElementById('events').textContent = JSON.stringify((data.events || []).slice(0, 20), null, 2);
                                }
                                refresh();
                                setInterval(refresh, 2000);
                            </script>
                        </body>
                        </html>
                        """,
                        agent_id=agent_id,
                )


@app.route("/api/agent/<agent_id>/event", methods=["POST"])
def ingest_event(agent_id):
    if not _validate_agent_id(agent_id):
        return jsonify({"error": "invalid_agent_id"}), 400
    if not _rate_limit_ok(request, "event"):
        return jsonify({"error": "rate_limited"}), 429

    raw = request.get_data(cache=False, as_text=False)
    if len(raw) > MAX_BODY_BYTES:
        return jsonify({"error": "payload_too_large"}), 413

    auth_ok, auth_mode = _validate_signature(request, raw)
    if not auth_ok:
        return jsonify({"error": "unauthorized", "mode": auth_mode}), 401

    try:
        payload = json.loads(raw.decode("utf-8", errors="ignore") or "{}")
    except json.JSONDecodeError:
        return jsonify({"error": "invalid_json"}), 400
    event = payload.get("event")
    if not event:
        return jsonify({"error": "missing_event"}), 400

    agent_events[agent_id].appendleft(_sanitize_value(event))
    agent_last_seen[agent_id] = now_iso()
    return jsonify({"status": "ok", "auth_mode": auth_mode})


@app.route("/api/agent/<agent_id>/status", methods=["POST"])
def ingest_status(agent_id):
    if not _validate_agent_id(agent_id):
        return jsonify({"error": "invalid_agent_id"}), 400
    if not _rate_limit_ok(request, "status"):
        return jsonify({"error": "rate_limited"}), 429

    raw = request.get_data(cache=False, as_text=False)
    if len(raw) > MAX_BODY_BYTES:
        return jsonify({"error": "payload_too_large"}), 413

    auth_ok, auth_mode = _validate_signature(request, raw)
    if not auth_ok:
        return jsonify({"error": "unauthorized", "mode": auth_mode}), 401

    try:
        payload = json.loads(raw.decode("utf-8", errors="ignore") or "{}")
    except json.JSONDecodeError:
        return jsonify({"error": "invalid_json"}), 400
    status = payload.get("status")
    if status is None:
        return jsonify({"error": "missing_status"}), 400

    agent_status[agent_id] = _sanitize_value(status)
    agent_last_seen[agent_id] = payload.get("timestamp") or now_iso()
    return jsonify({"status": "ok", "auth_mode": auth_mode})


@app.route("/api/agent/<agent_id>/snapshot", methods=["GET"])
def snapshot(agent_id):
    if not _validate_agent_id(agent_id):
        return jsonify({"error": "invalid_agent_id"}), 400
    return jsonify(
        {
            "agent_id": agent_id,
            "last_seen": agent_last_seen.get(agent_id),
            "status": agent_status.get(agent_id, {}),
            "events": list(agent_events[agent_id])[:120],
            "summary": _agent_rollup(agent_id),
        }
    )


@app.route("/api/agent/<agent_id>/events", methods=["GET"])
def get_agent_events(agent_id):
    if not _validate_agent_id(agent_id):
        return jsonify({"error": "invalid_agent_id"}), 400

    limit = max(1, min(300, _safe_int(request.args.get("limit", 120), 120)))
    action_filter = str(request.args.get("action") or "").strip().lower()
    enf_filter = str(request.args.get("enforcement") or "").strip().lower()
    min_risk = float(request.args.get("min_risk") or 0)

    filtered = []
    for ev in list(agent_events[agent_id]):
        decision = ev.get("decision") or {}
        enforcement = ev.get("enforcement") or {}
        action = str(decision.get("action") or "").lower()
        enf_status = str(enforcement.get("status") or "").lower()
        risk = float(decision.get("risk") or 0)

        if action_filter and action != action_filter:
            continue
        if enf_filter and enf_status != enf_filter:
            continue
        if risk < min_risk:
            continue
        filtered.append(ev)
        if len(filtered) >= limit:
            break

    return jsonify({"agent_id": agent_id, "events": filtered, "count": len(filtered)})


@app.route("/api/agent/<agent_id>/commands/pull", methods=["POST"])
def pull_agent_commands(agent_id):
    if not _validate_agent_id(agent_id):
        return jsonify({"error": "invalid_agent_id"}), 400
    if not _rate_limit_ok(request, "command_pull"):
        return jsonify({"error": "rate_limited"}), 429

    raw = request.get_data(cache=False, as_text=False)
    if len(raw) > MAX_BODY_BYTES:
        return jsonify({"error": "payload_too_large"}), 413

    auth_ok, auth_mode = _validate_signature(request, raw)
    if not auth_ok:
        return jsonify({"error": "unauthorized", "mode": auth_mode}), 401

    out = []
    queue = agent_commands[agent_id]
    while queue and len(out) < 15:
        out.append(queue.popleft())

    return jsonify({"agent_id": agent_id, "commands": out, "count": len(out)})


@app.route("/api/agent/<agent_id>/command/unblock", methods=["POST"])
def enqueue_unblock_command(agent_id):
    if not _validate_agent_id(agent_id):
        return jsonify({"error": "invalid_agent_id"}), 400
    if not _require_admin_token(request):
        return jsonify({"error": "admin_token_required"}), 401
    if not _rate_limit_ok(request, "ui_unblock"):
        return jsonify({"error": "rate_limited"}), 429

    payload = request.get_json(silent=True) or {}
    remote_ip = str(payload.get("remote_ip") or "").strip()
    reason = str(payload.get("reason") or "ui_manual_unblock").strip()[:120]
    if not remote_ip:
        return jsonify({"error": "missing_remote_ip"}), 400

    cmd = {
        "id": hashlib.sha1(f"{agent_id}:{remote_ip}:{time.time()}".encode("utf-8")).hexdigest()[:16],
        "timestamp": now_iso(),
        "action": "unblock_ip",
        "remote_ip": remote_ip,
        "reason": reason,
    }
    agent_commands[agent_id].append(cmd)
    return jsonify({"status": "queued", "agent_id": agent_id, "command": cmd})


@app.route("/api/agents", methods=["GET"])
def list_agents():
    ids = sorted(set(list(agent_status.keys()) + list(agent_events.keys())))
    rows = [_agent_rollup(aid) for aid in ids]
    return jsonify({"agents": rows})


def parse_args():
    parser = argparse.ArgumentParser(description="Public relay + dashboard for standalone IPS agents")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8600)
    parser.add_argument("--dev-flask", action="store_true", help="Use Flask dev server instead of waitress")
    return parser.parse_args()


def main():
    args = parse_args()
    if args.dev_flask:
        app.run(host=args.host, port=args.port, debug=False)
        return

    try:
        serve = __import__("waitress", fromlist=["serve"]).serve
        serve(app, host=args.host, port=args.port, threads=8)
    except Exception:
        # Fallback for environments where waitress is not installed yet.
        app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()

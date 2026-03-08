# Edge Suite (Separate Standalone App + Public Dashboard)

This folder is independent from your existing `backend/` and `frontend/` website setup.
It provides:

1. A **standalone IPS agent** (`agent_runner.py`) for Ubuntu and Windows VMs.
2. A **public dashboard relay server** (`dashboard_server.py`) where users enter a unique agent ID and monitor live traffic decisions.

It can be installed as a Python package and run with one-command CLIs.

## PyPI Package

- Package link: https://pypi.org/project/anomalyx/0.1.13/

```powershell
pip install anomalyx==0.1.13
```
## Demo Video

Short demo showing **agent setup, attack simulation, and live dashboard monitoring**.

[![Watch the demo](https://img.shields.io/badge/Watch-Demo-blue?style=for-the-badge&logo=google-drive)](https://drive.google.com/file/d/1rXNQ7FJMxSsrN8BRfoEt0k7hFC0SwA7A/view?usp=sharing)

## Enterprise UI and Ops

- High-signal dashboard widgets for `alerts`, `temp_block_ip`, `block_ip`, and enforcement failures.
- Filterable event stream by action, enforcement status, and minimum risk.
- Critical strip that surfaces high-risk/blocked traffic immediately even during high traffic rates.
- In-UI unblock workflow: queue `unblock_ip` command directly from dashboard (admin token protected).
- Landing page fleet view now includes per-agent alerts/temp-blocks/blocks and running state.
- Ops CLI search commands for rapid triage from terminal.

## Architecture

- Ubuntu or Windows VM (defender) runs `agent_runner.py`:
   - Uses embedded package runtime (`signature + ML + zero-day + fusion + enforcement`)
  - Captures traffic + enforces decisions locally
  - Pushes event/status telemetry to relay server with unique `AGENT_ID`

- Public relay/dashboard server runs `dashboard_server.py`:
  - Accepts agent telemetry via authenticated ingest API
  - Serves web UI:
    - landing page with agent ID input
    - live dashboard at `/dashboard/<agent_id>`

## Files

- `agent_runner.py` - standalone agent process
- `dashboard_server.py` - relay + dashboard web server
- `templates/landing.html` - unique-ID entry page
- `templates/dashboard.html` - live monitoring page
- `start_agent.ps1` - helper script for agent
- `start_dashboard_server.ps1` - helper script for relay server
- `.env.example` - configuration template

## Setup

### 1) Install dependencies

```powershell
cd edge-suite
pip install -r requirements.txt
```

### 1b) Install package entrypoints (recommended)

```powershell
cd edge-suite
pip install -e .
```

This gives commands:
- `anomalyx`
- `anomalyx-agent`
- `anomalyx-dashboard`
- `anomalyx-review-enforcement`
- (also keeps `edge-agent` and `edge-dashboard` for compatibility)

### 2) Configure env

Copy `.env.example` to `.env` and set values:

```env
AGENT_ID=ubuntu-vm-001
AGENT_TOKEN=<long-random-token>
RELAY_URL=http://<public-server-ip>:8600
DASHBOARD_SERVER_TOKEN=<same-long-random-token>

DASHBOARD_STRICT_AUTH=1
DASHBOARD_RATE_LIMIT_PER_MIN=240
DASHBOARD_MAX_BODY_BYTES=262144
DASHBOARD_TIMESTAMP_SKEW_SEC=120
DASHBOARD_ALLOWED_ORIGIN=

IPS_ENFORCEMENT_ENABLED=1
IPS_DROP_TTL_SEC=120
IPS_BLOCK_TTL_SEC=3600
IPS_ENABLE_REVERSE_DNS=0
```

Use same token value for:
- Agent: `AGENT_TOKEN`
- Server: `DASHBOARD_SERVER_TOKEN`

## Run

### Run with one command

```powershell
anomalyx setup
anomalyx dashboard --host 0.0.0.0 --port 8600
anomalyx agent --agent-id ubuntu-vm-001 --relay-url http://<server-ip>:8600
```

`anomalyx setup` installs Python packet-capture dependencies and auto-attempts Npcap install on Windows.

### Install globally on a VM

Preferred for isolated global CLI install:

```powershell
pip install pipx
pipx ensurepath
pipx install anomalyx
```

Then use from anywhere:

```powershell
anomalyx setup
anomalyx dashboard --host 0.0.0.0 --port 8600
anomalyx agent --agent-id win-vm-001 --relay-url http://<server-ip>:8600
```

### Run relay/dashboard server (public host)

```powershell
cd edge-suite
python dashboard_server.py --host 0.0.0.0 --port 8600
```

Or one-command CLI:

```powershell
anomalyx-dashboard --host 0.0.0.0 --port 8600
```

Open:
- `http://<server-ip>:8600/`
- enter agent id (e.g. `win-vm-001`)

### Run standalone agent

Ubuntu VM (recommended):

```bash
sudo anomalyx agent --agent-id ubuntu-vm-001 --relay-url http://<server-ip>:8600 --interface eth0
```

Windows VM (run elevated Administrator terminal):

```powershell
cd edge-suite
python agent_runner.py --agent-id win-vm-001 --relay-url http://<server-ip>:8600
```

Or one-command CLI:

```powershell
anomalyx-agent --agent-id win-vm-001 --relay-url http://<server-ip>:8600
```

or

```powershell
powershell -ExecutionPolicy Bypass -File start_agent.ps1 -AgentId win-vm-001 -RelayUrl http://<server-ip>:8600
```

## Validation checklist

1. On dashboard landing page, agent appears in known agents list.
2. In `/dashboard/<agent_id>`, you see:
   - processed counters increasing
   - per-event action (`allow/alert/drop/block_ip`)
   - enforcement status in event rows
3. On Windows VM, local logs update:
   - `anomalyx-logs/agent_runtime.log`
   - `anomalyx-logs/agent_events.jsonl`
4. Backend enforcement audit (from existing backend module) updates:
   - `anomalyx-logs/enforcement_actions.log`

## CLI triage commands

```powershell
anomalyx search-events --action temp_block_ip --min-risk 60 --limit 20
anomalyx search-enforcement --status applied --action temp_block_ip --limit 20
anomalyx search-enforcement --ip 1.1.1.1 --limit 20
anomalyx unblock-ip --ip 1.1.1.1
```

## CALDERA test plan (Ubuntu attacker -> Ubuntu/Windows defender)

1. Start relay server on accessible host.
2. Start defender agent on Ubuntu (sudo) or Windows (administrator terminal).
3. Launch CALDERA operation from Ubuntu against Windows VM.
4. Watch dashboard in real time via unique agent ID.
5. Verify detect + prevent + log:
   - detection events on dashboard
   - non-allow actions (`alert/drop/block_ip`)
   - enforcement logs showing `applied` for block/drop actions

## Notes

- This is additive and does not change your original website setup.
- On Ubuntu, run agent with `sudo` and specify `--interface` when auto-detection is unstable.
- Keep Windows terminal elevated for host firewall enforcement.
- Ensure VM networking allows Ubuntu -> Windows traffic for realistic testing.

## Security features included

- HMAC-signed agent payloads with timestamp window validation
- Constant-time token hash comparison on server
- Strict auth mode (`DASHBOARD_STRICT_AUTH=1`)
- Per-IP route rate limiting
- Request body size limits
- Input sanitization + bounded in-memory event buffers
- Security headers (CSP, X-Frame-Options, no-store cache, etc.)
- Waitress production server option for relay/dashboard

## Help file

See `edge-suite/HELP.md` for exact run/build/log commands.

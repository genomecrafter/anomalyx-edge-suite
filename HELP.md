# Edge Suite Help (One-Command Run + Logs)

This file gives exact commands for running the standalone tool and dashboard.

## 1) Install as package (recommended)

```powershell
cd edge-suite
pip install -e .
```

After this you get CLI commands:
- `anomalyx`
- `anomalyx-agent`
- `anomalyx-dashboard`
- `anomalyx-review-enforcement`

## 2) Configure `.env`

Create `edge-suite/.env` from `.env.example` and set secure values:

```env
AGENT_ID=win-vm-001
AGENT_TOKEN=<long-random-token>
RELAY_URL=http://<relay-ip>:8600
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

## 3) One-command run

Run prerequisite setup first (Scapy + Npcap on Windows):

```powershell
anomalyx setup
```

### Unified command

```powershell
anomalyx dashboard --host 0.0.0.0 --port 8600
anomalyx agent --agent-id win-vm-001 --relay-url http://<relay-ip>:8600
```

Useful setup flags:

```powershell
anomalyx setup --check-only
anomalyx setup --skip-npcap
anomalyx setup --python-deps-only
```

### Relay + dashboard server

```powershell
anomalyx-dashboard --host 0.0.0.0 --port 8600
```

### Agent (Windows VM, run terminal as Administrator)

```powershell
anomalyx-agent --agent-id win-vm-001 --relay-url http://<relay-ip>:8600
```

### Agent (Ubuntu VM, run with sudo)

```bash
sudo anomalyx-agent --agent-id ubuntu-vm-001 --relay-url http://<relay-ip>:8600 --interface eth0
```

## 4) Logs to monitor

### Agent host

- `anomalyx-logs/agent_runtime.log` (default packaged CLI path)
- `anomalyx-logs/agent_events.jsonl` (default packaged CLI path)
- `anomalyx-logs/enforcement_actions.log`

## 4b) CLI search and unblock

```powershell
anomalyx search-events --action alert --min-risk 40 --limit 20
anomalyx search-events --action temp_block_ip --min-risk 60 --limit 20
anomalyx search-enforcement --status applied --action temp_block_ip --limit 20
anomalyx search-enforcement --ip 1.1.1.1 --limit 20
anomalyx unblock-ip --ip 1.1.1.1
```

Dashboard unblock action:
- Enter `DASHBOARD_ADMIN_TOKEN` in the dashboard unblock panel.
- Enter remote IP and click `unblock`.
- Agent pulls the command and executes firewall unblock on endpoint.

### Relay/dashboard host

Use dashboard page:
- `http://<relay-ip>:8600/`
- enter unique ID -> `/dashboard/<agent_id>`

## 5) Global install on any VM

Use `pipx` to install one global command without managing virtualenv manually:

```powershell
pip install pipx
pipx ensurepath
pipx install anomalyx
```

Then run from any folder:

```powershell
anomalyx dashboard --host 0.0.0.0 --port 8600
anomalyx agent --agent-id win-vm-001 --relay-url http://<relay-ip>:8600
```

Ubuntu VM example:

```bash
sudo anomalyx agent --agent-id ubuntu-vm-001 --relay-url http://<relay-ip>:8600 --interface eth0
```

## 6) Build executable (optional)

Install pyinstaller, then:

```powershell
cd edge-suite
pyinstaller --onefile --name EdgeAgentStandalone agent_runner.py
pyinstaller --onefile --name EdgeDashboardRelay dashboard_server.py
```

Outputs in `edge-suite/dist/`.

## 7) Quick security checklist

1. Use long random token and keep it secret.
2. Keep `DASHBOARD_STRICT_AUTH=1`.
3. Restrict dashboard host firewall to allowed clients.
4. Use TLS reverse proxy in front of dashboard for internet access.
5. Run agent as root on Ubuntu or admin on Windows only on trusted defender VM.

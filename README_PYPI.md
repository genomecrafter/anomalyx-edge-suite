# AnomalyX

AnomalyX provides a standalone IDS/IPS agent and a relay dashboard for Ubuntu and Windows VMs.

It captures host traffic, runs hybrid detection (signature + ML + zero-day),
uses a fusion policy for risk/action, and applies prevention via host firewall rules
(`iptables`/`ip6tables` on Ubuntu, `netsh advfirewall` on Windows).

## What it includes

- `anomalyx setup`: installs Python capture dependencies and attempts Npcap setup on Windows.
- `anomalyx agent`: runs the endpoint capture/detection/enforcement agent.
- `anomalyx dashboard`: runs the relay + monitoring dashboard.
- `anomalyx search-events`: query local event logs by action/risk.
- `anomalyx search-enforcement`: query enforcement actions by status/action/ip.
- `anomalyx unblock-ip`: remove host firewall blocks for a remote IP.

## Quick start

```powershell
pip install anomalyx
anomalyx setup
```

Start dashboard:

```powershell
anomalyx dashboard --host 0.0.0.0 --port 8600
```

`relay-ip` means the IP address of the machine where you started
`anomalyx dashboard`.

Start agent on Ubuntu VM (recommended):

```bash
sudo anomalyx agent --agent-id ubuntu-vm-001 --relay-url http://<relay-ip>:8600 --interface eth0
```

Start agent on Windows VM (Administrator terminal):

```powershell
anomalyx agent --agent-id win-vm-001 --relay-url http://<relay-ip>:8600
```

Open dashboard:

- `http://<relay-ip>:8600/`

## What to expect

- Live events with action labels: `allow`, `alert`, `temp_block_ip`, `block_ip`.
- Risk score and reason generated from fusion policy.
- Enforcement status in event data (applied/skipped/failed) with diagnostics.
- Staged escalation and repeat-safe enforcement to reduce false positives.
- Allowlist support with controlled blocking rate limits.
- Dashboard UI supports action/enforcement filters and critical traffic strip.
- Landing page shows fleet-level alerts/temp-blocks/blocks per agent.
- Dashboard supports admin-token protected unblock requests.

## Baseline mode (recommended first days)

- Default policy is tuned to prefer `alert` + `temp_block_ip`.
- `block_ip` now requires stronger repeat evidence and higher risk.
- Review enforcement log daily before expanding allowlist.

Daily review command:

```powershell
anomalyx review-enforcement --log-path anomalyx-logs/enforcement_actions.log --top 20 --min-count 5
```
- Local logs on agent host (default):
	- `anomalyx-logs/agent_runtime.log`
	- `anomalyx-logs/agent_events.jsonl`
	- `anomalyx-logs/enforcement_actions.log`

## Notes

- `anomalyx setup` uses `winget`/`choco` for automatic Npcap install on Windows when available.
- If automatic Npcap installation is unavailable, install Npcap manually: `https://npcap.com/#download`.

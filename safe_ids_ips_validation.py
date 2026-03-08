import json
import socket
import time
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# Controlled IDS/IPS validation traffic (safe, low-volume)
AGENT_ID = "win-vm-001"
DASHBOARD_BASE = "http://127.0.0.1:8600"
ENFORCEMENT_LOG = Path("anomalyx-logs/enforcement_actions.log")
TARGET_IP = "198.51.100.10"  # Reserved TEST-NET-2

TCP_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389, 5432]
UDP_PORTS = [53, 123, 1900]
CYCLES = 5
SLEEP_BETWEEN_PACKETS = 0.05
SLEEP_BETWEEN_CYCLES = 1.5
MONITOR_SECONDS = 40


def fetch_snapshot():
    url = f"{DASHBOARD_BASE}/api/agent/{AGENT_ID}/snapshot"
    req = Request(url, headers={"User-Agent": "anomalyx-safe-validator"})
    with urlopen(req, timeout=3) as r:
        return json.loads(r.read().decode("utf-8", errors="ignore"))


def tcp_scan_wave():
    for port in TCP_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.25)
        try:
            s.connect_ex((TARGET_IP, port))
        except Exception:
            pass
        finally:
            s.close()
        time.sleep(SLEEP_BETWEEN_PACKETS)


def udp_wave():
    for port in UDP_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.sendto(b"safe-test", (TARGET_IP, port))
        except Exception:
            pass
        finally:
            s.close()
        time.sleep(SLEEP_BETWEEN_PACKETS)


def tail_new_log_entries(last_size):
    if not ENFORCEMENT_LOG.exists():
        return [], last_size

    size = ENFORCEMENT_LOG.stat().st_size
    if size <= last_size:
        return [], size

    with ENFORCEMENT_LOG.open("r", encoding="utf-8", errors="ignore") as f:
        f.seek(last_size)
        raw = f.read().splitlines()

    parsed = []
    for line in raw:
        line = line.strip()
        if not line:
            continue
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    return parsed, size


def summarize_event_enforcement(events):
    summary = {"applied": 0, "skipped": 0, "failed": 0, "other": 0}
    lines = []
    for ev in events:
        enf = ev.get("enforcement", {})
        decision = ev.get("decision", {})
        packet = ev.get("packet", {})
        status = str(enf.get("status", "other") or "other").lower()
        if status in summary:
            summary[status] += 1
        else:
            summary["other"] += 1

        if status in {"applied", "failed"}:
            lines.append(
                f"[EVENT_ENF] status={status} action={enf.get('action')} "
                f"policy_action={decision.get('action')} risk={decision.get('risk')} "
                f"src={packet.get('src_ip')} dst={packet.get('dst_ip')} details={enf.get('details')}"
            )

    return summary, lines


def print_status(prefix="[STATUS]"):
    try:
        snap = fetch_snapshot()
        status = snap.get("status", {})
        actions = status.get("actions", {})
        enforcement = status.get("enforcement", {})

        print(
            f"{prefix} running={status.get('running')} processed={status.get('processed_packets', 0)} "
            f"allow={actions.get('allow', 0)} alert={actions.get('alert', 0)} "
            f"temp_block={actions.get('temp_block_ip', 0)} block={actions.get('block_ip', 0)} "
            f"enf_ok={enforcement.get('runtime_ok')} enf_msg={enforcement.get('runtime_message')}"
        )

        capture_error = status.get("capture_error")
        if capture_error:
            print(f"[CAPTURE_ERROR] {capture_error}")

    except (URLError, HTTPError, TimeoutError, OSError) as exc:
        print(f"[SNAPSHOT_ERROR] {exc}")


def main():
    print("=== AnomalyX Safe Validation Start ===")
    print(f"Agent={AGENT_ID} Dashboard={DASHBOARD_BASE} Target={TARGET_IP}")
    print_status("[BEFORE]")
    baseline_snap = fetch_snapshot()
    baseline_status = baseline_snap.get("status", {})
    baseline_actions = baseline_status.get("actions", {})
    baseline_processed = int(baseline_status.get("processed_packets", 0) or 0)
    baseline_alert = int(baseline_actions.get("alert", 0) or 0)
    baseline_temp = int(baseline_actions.get("temp_block_ip", 0) or 0)
    baseline_block = int(baseline_actions.get("block_ip", 0) or 0)

    # Prefer runtime-provided log path to avoid cwd mismatches.
    status_enf = baseline_status.get("enforcement", {})
    runtime_log_path = status_enf.get("log_path")
    if runtime_log_path:
        global ENFORCEMENT_LOG
        ENFORCEMENT_LOG = Path(runtime_log_path)
    print(f"[INFO] enforcement_log_path={ENFORCEMENT_LOG}")

    print("\n[TRAFFIC] Sending controlled suspicious traffic...")
    for i in range(CYCLES):
        tcp_scan_wave()
        udp_wave()
        print(f"[TRAFFIC] cycle {i + 1}/{CYCLES} done")
        time.sleep(SLEEP_BETWEEN_CYCLES)

    print("\n[MONITOR] Watching status + enforcement log...")
    start = time.time()
    last_size = ENFORCEMENT_LOG.stat().st_size if ENFORCEMENT_LOG.exists() else 0
    seen = 0
    event_enf_seen = {"applied": 0, "skipped": 0, "failed": 0, "other": 0}
    printed_event_lines = set()

    while time.time() - start < MONITOR_SECONDS:
        snap = fetch_snapshot()
        status = snap.get("status", {})
        actions = status.get("actions", {})
        print(
            f"[STATUS] running={status.get('running')} processed={status.get('processed_packets', 0)} "
            f"allow={actions.get('allow', 0)} alert={actions.get('alert', 0)} "
            f"temp_block={actions.get('temp_block_ip', 0)} block={actions.get('block_ip', 0)} "
            f"enf_ok={(status.get('enforcement') or {}).get('runtime_ok')} "
            f"enf_msg={(status.get('enforcement') or {}).get('runtime_message')}"
        )

        ev_summary, ev_lines = summarize_event_enforcement(snap.get("events", []))
        for key in event_enf_seen:
            event_enf_seen[key] = max(event_enf_seen[key], ev_summary.get(key, 0))
        for line in ev_lines:
            if line not in printed_event_lines:
                printed_event_lines.add(line)
                print(line)

        rows, last_size = tail_new_log_entries(last_size)
        for row in rows:
            action = row.get("action")
            state = row.get("status")
            if action in {"temp_block_ip", "block_ip"} or state in {"applied", "failed", "skipped"}:
                seen += 1
                print(
                    f"[ENFORCEMENT] status={state} action={action} "
                    f"ip={row.get('remote_ip')} rule={row.get('rule_name')} details={row.get('details')}"
                )
        time.sleep(2.0)

    final_snap = fetch_snapshot()
    final_status = final_snap.get("status", {})
    final_actions = final_status.get("actions", {})
    delta_processed = int(final_status.get("processed_packets", 0) or 0) - baseline_processed
    delta_alert = int(final_actions.get("alert", 0) or 0) - baseline_alert
    delta_temp = int(final_actions.get("temp_block_ip", 0) or 0) - baseline_temp
    delta_block = int(final_actions.get("block_ip", 0) or 0) - baseline_block

    print(f"\n=== Done. Observed {seen} new enforcement log entries ===")
    print(
        "[SUMMARY] "
        f"delta_processed={delta_processed} delta_alert={delta_alert} "
        f"delta_temp_block={delta_temp} delta_block={delta_block}"
    )
    print(
        "[SUMMARY] event_enforcement "
        f"applied={event_enf_seen['applied']} skipped={event_enf_seen['skipped']} "
        f"failed={event_enf_seen['failed']} other={event_enf_seen['other']}"
    )
    if delta_temp > 0 or delta_block > 0:
        print("[RESULT] Prevention logic triggered (policy issued temp_block/block actions).")
    if event_enf_seen["applied"] > 0:
        print("[RESULT] Enforcement applied successfully (confirmed in live events).")
    elif seen == 0:
        print("[NOTE] No new local log rows seen. If RESULT shows prevention, this is likely a log-path/cwd mismatch.")


if __name__ == "__main__":
    main()

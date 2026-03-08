import json
import socket
import subprocess
import time
from urllib.request import Request, urlopen

# Simple Windows demo: baseline connectivity -> trigger IPS -> confirm block
AGENT_ID = "win-vm-001"
DASHBOARD_BASE = "http://127.0.0.1:8600"
TARGET_IP = "1.1.1.1"  # Change if needed
TARGET_PORT = 443
MONITOR_SECONDS = 35
BURST_ROUNDS = 8
AGGRESSIVE_BURST_ROUNDS = 14

# Same style as safe validation script + signature-sensitive ports.
SENSITIVE_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3389, 5432, 8080]
UDP_PORTS = [53, 123, 1900]


def fetch_snapshot():
    url = f"{DASHBOARD_BASE}/api/agent/{AGENT_ID}/snapshot"
    req = Request(url, headers={"User-Agent": "anomalyx-simple-demo"})
    with urlopen(req, timeout=3) as r:
        return json.loads(r.read().decode("utf-8", errors="ignore"))


def socket_check(ip, port, timeout=2.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        code = s.connect_ex((ip, port))
        return code == 0, code
    except Exception:
        return False, -1
    finally:
        s.close()


def ping_check(ip):
    # Windows ping: success has return code 0
    result = subprocess.run(
        ["ping", "-n", "1", "-w", "1200", ip],
        capture_output=True,
        text=True,
    )
    ok = result.returncode == 0
    return ok, (result.stdout or "").strip().splitlines()[-1] if result.stdout else ""


def get_temp_block_count(snapshot):
    status = snapshot.get("status", {})
    actions = status.get("actions", {})
    return int(actions.get("temp_block_ip", 0) or 0)


def recent_applied_for_target(snapshot, target_ip):
    for ev in snapshot.get("events", []):
        enf = ev.get("enforcement", {})
        if enf.get("status") == "applied" and str(enf.get("remote_ip") or "") == target_ip:
            return True, ev
    return False, None


def trigger_scan_like_traffic(target_ip, rounds):
    # Validation-file style: dense TCP connect probes + UDP sends.
    for _ in range(rounds):
        for p in SENSITIVE_PORTS:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.18)
            try:
                s.connect_ex((target_ip, p))
            except Exception:
                pass
            finally:
                s.close()

        for p in UDP_PORTS:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                u.sendto(b"safe-demo", (target_ip, p))
            except Exception:
                pass
            finally:
                u.close()

        time.sleep(0.08)


def main():
    print("=== Simple IPS Block Demo ===")
    print(f"Agent={AGENT_ID} Dashboard={DASHBOARD_BASE} Target={TARGET_IP}:{TARGET_PORT}")
    print("TrafficMode=validation_style_tcp_udp")

    before_snap = fetch_snapshot()
    before_temp = get_temp_block_count(before_snap)

    before_sock_ok, before_sock_code = socket_check(TARGET_IP, TARGET_PORT)
    before_ping_ok, before_ping_tail = ping_check(TARGET_IP)

    print(f"[BEFORE] temp_block={before_temp} socket_ok={before_sock_ok} code={before_sock_code} ping_ok={before_ping_ok}")
    if before_ping_tail:
        print(f"[BEFORE] ping_tail={before_ping_tail}")

    print("[STEP] Generating safe scan-like traffic...")
    trigger_scan_like_traffic(TARGET_IP, BURST_ROUNDS)

    print("[STEP] Waiting for IPS decision/enforcement...")
    applied_seen = False
    applied_event = None
    after_temp = before_temp
    start = time.time()

    while time.time() - start < MONITOR_SECONDS:
        snap = fetch_snapshot()
        temp_now = get_temp_block_count(snap)
        applied_for_target, ev = recent_applied_for_target(snap, TARGET_IP)
        if applied_for_target:
            applied_seen = True
            applied_event = ev
            break
        if temp_now > before_temp:
            # temp block increased even if event list rolled over different IPs
            applied_seen = True
            after_temp = temp_now
            break
        time.sleep(1.5)

    if not (after_temp > before_temp or applied_seen):
        print("[STEP] No trigger yet, running aggressive retry phase...")
        trigger_scan_like_traffic(TARGET_IP, AGGRESSIVE_BURST_ROUNDS)
        retry_start = time.time()
        while time.time() - retry_start < 20:
            snap = fetch_snapshot()
            temp_now = get_temp_block_count(snap)
            applied_for_target, ev = recent_applied_for_target(snap, TARGET_IP)
            if applied_for_target:
                applied_seen = True
                applied_event = ev
                after_temp = temp_now
                break
            if temp_now > before_temp:
                applied_seen = True
                after_temp = temp_now
                break
            time.sleep(1.2)

    after_snap = fetch_snapshot()
    after_temp = get_temp_block_count(after_snap)

    after_sock_ok, after_sock_code = socket_check(TARGET_IP, TARGET_PORT)
    after_ping_ok, after_ping_tail = ping_check(TARGET_IP)

    print(f"[AFTER] temp_block={after_temp} socket_ok={after_sock_ok} code={after_sock_code} ping_ok={after_ping_ok}")
    if after_ping_tail:
        print(f"[AFTER] ping_tail={after_ping_tail}")

    print("\n=== Demo Result ===")
    if applied_event:
        enf = applied_event.get("enforcement", {})
        dec = applied_event.get("decision", {})
        print(
            f"Enforcement event: status={enf.get('status')} action={enf.get('action')} "
            f"remote_ip={enf.get('remote_ip')} risk={dec.get('risk')}"
        )

    blocked_after = (before_sock_ok and not after_sock_ok) or (before_ping_ok and not after_ping_ok)
    print(f"Connectivity now blocked: {blocked_after}")

    if blocked_after:
        print("RESULT: BLOCK CONFIRMED (connectivity dropped from before to after).")
    else:
        print("RESULT: NO BLOCK TRANSITION OBSERVED (connectivity did not drop during this run).")


if __name__ == "__main__":
    main()

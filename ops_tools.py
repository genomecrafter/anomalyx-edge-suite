import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)


def _read_jsonl(path):
    rows = []
    if not path.exists():
        return rows
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def parse_args():
    argv = list(sys.argv[1:])
    if argv and argv[0].startswith("-"):
        argv = ["review-enforcement", *argv]

    parser = argparse.ArgumentParser(description="AnomalyX operations tooling")
    sub = parser.add_subparsers(dest="command")

    review = sub.add_parser("review-enforcement", help="Summarize enforcement logs and print allowlist candidates")
    review.add_argument("--log-path", default="anomalyx-logs/enforcement_actions.log")
    review.add_argument("--top", type=int, default=15)
    review.add_argument("--min-count", type=int, default=5)

    search_enf = sub.add_parser("search-enforcement", help="Search enforcement log by action/status/ip")
    search_enf.add_argument("--log-path", default="anomalyx-logs/enforcement_actions.log")
    search_enf.add_argument("--status", default="")
    search_enf.add_argument("--action", default="")
    search_enf.add_argument("--ip", default="")
    search_enf.add_argument("--limit", type=int, default=30)

    search_events = sub.add_parser("search-events", help="Search local agent events by action/risk")
    search_events.add_argument("--events-path", default="anomalyx-logs/agent_events.jsonl")
    search_events.add_argument("--action", default="")
    search_events.add_argument("--min-risk", type=float, default=0)
    search_events.add_argument("--limit", type=int, default=30)

    unblock = sub.add_parser("unblock-ip", help="Unblock a remote IP on this host firewall")
    unblock.add_argument("--ip", required=True)

    # Backward compatibility: no subcommand means review mode.
    args = parser.parse_args(argv)
    if not args.command:
        args.command = "review-enforcement"
        if not hasattr(args, "log_path"):
            args.log_path = "anomalyx-logs/enforcement_actions.log"
        if not hasattr(args, "top"):
            args.top = 15
        if not hasattr(args, "min_count"):
            args.min_count = 5
    return args


def _review_enforcement(args):
    path = Path(args.log_path)
    rows = _read_jsonl(path)

    if not rows:
        print(f"[review] No log records found at: {path}")
        return 1

    status_counts = Counter((r.get("status") or "unknown") for r in rows)
    applied_actions = Counter((r.get("action") or "unknown") for r in rows if r.get("status") == "applied")

    block_targets = Counter()
    for r in rows:
        if r.get("status") != "applied":
            continue
        if r.get("action") not in {"temp_block_ip", "block_ip"}:
            continue
        ip = str(r.get("remote_ip") or "").strip()
        if ip:
            block_targets[ip] += 1

    print("[review] Enforcement status summary:")
    for k, v in status_counts.most_common():
        print(f"  - {k}: {v}")

    print("\n[review] Applied action summary:")
    for k, v in applied_actions.most_common():
        print(f"  - {k}: {v}")

    top_n = max(1, args.top)
    print(f"\n[review] Top {top_n} blocked targets (applied):")
    for ip, cnt in block_targets.most_common(top_n):
        print(f"  - {ip}: {cnt}")

    candidates = [ip for ip, cnt in block_targets.most_common() if cnt >= max(1, args.min_count)]
    if candidates:
        print("\n[review] Candidate allowlist entries (manual review required):")
        print("  IPS_ALLOWLIST_IPS=" + ",".join(candidates))
    else:
        print("\n[review] No allowlist candidates met min-count threshold.")

    return 0


def _search_enforcement(args):
    rows = _read_jsonl(Path(args.log_path))
    status_filter = str(args.status or "").lower().strip()
    action_filter = str(args.action or "").lower().strip()
    ip_filter = str(args.ip or "").strip()

    out = []
    for row in reversed(rows):
        status = str(row.get("status") or "").lower()
        action = str(row.get("action") or "").lower()
        ip = str(row.get("remote_ip") or "")
        if status_filter and status != status_filter:
            continue
        if action_filter and action != action_filter:
            continue
        if ip_filter and ip != ip_filter:
            continue
        out.append(row)
        if len(out) >= max(1, int(args.limit)):
            break

    if not out:
        print("[search-enforcement] No matching rows.")
        return 1

    print(f"[search-enforcement] matched={len(out)}")
    for row in out:
        print(
            f"- ts={row.get('timestamp')} status={row.get('status')} action={row.get('action')} "
            f"ip={row.get('remote_ip')} details={row.get('details')}"
        )
    return 0


def _search_events(args):
    rows = _read_jsonl(Path(args.events_path))
    action_filter = str(args.action or "").lower().strip()
    min_risk = float(args.min_risk or 0)

    out = []
    for row in reversed(rows):
        decision = row.get("decision") or {}
        action = str(decision.get("action") or "").lower()
        risk = _safe_float(decision.get("risk"), 0)
        if action_filter and action != action_filter:
            continue
        if risk < min_risk:
            continue
        out.append(row)
        if len(out) >= max(1, int(args.limit)):
            break

    if not out:
        print("[search-events] No matching rows.")
        return 1

    print(f"[search-events] matched={len(out)}")
    for row in out:
        p = row.get("packet") or {}
        d = row.get("decision") or {}
        e = row.get("enforcement") or {}
        print(
            f"- ts={row.get('timestamp')} action={d.get('action')} risk={d.get('risk')} "
            f"src={p.get('src_ip')} dst={p.get('dst_ip')} enf={e.get('status')}"
        )
    return 0


def _unblock_ip(args):
    from anomalyx_core.ips.enforcer import IPSEnforcer

    enforcer = IPSEnforcer()
    result = enforcer.unblock_ip(args.ip, reason="cli_unblock")
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "applied" else 1


def main():
    args = parse_args()
    if args.command == "review-enforcement":
        return _review_enforcement(args)
    if args.command == "search-enforcement":
        return _search_enforcement(args)
    if args.command == "search-events":
        return _search_events(args)
    if args.command == "unblock-ip":
        return _unblock_ip(args)

    print(f"[ops] Unsupported command: {args.command}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

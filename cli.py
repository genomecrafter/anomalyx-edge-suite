import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="anomalyx",
        description="AnomalyX standalone IDS/IPS toolkit",
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("agent", help="Run endpoint agent")

    sub.add_parser("dashboard", help="Run relay/dashboard server")

    sub.add_parser("setup", help="Install/verify packet capture prerequisites")

    sub.add_parser("review-enforcement", help="Summarize enforcement logs and print allowlist candidates")

    sub.add_parser("search-events", help="Search local event logs by action/risk")

    sub.add_parser("search-enforcement", help="Search enforcement logs by action/status/ip")

    sub.add_parser("unblock-ip", help="Unblock a remote IP on this host firewall")

    # Parse known args at the top level, and forward all remaining args to
    # the selected subcommand entrypoint.
    args, passthrough = parser.parse_known_args()

    if args.command == "agent":
        from agent_runner import main as agent_main

        sys.argv = ["anomalyx-agent", *passthrough]
        raise SystemExit(agent_main())

    if args.command == "dashboard":
        from dashboard_server import main as dashboard_main

        sys.argv = ["anomalyx-dashboard", *passthrough]
        raise SystemExit(dashboard_main())

    if args.command == "setup":
        from bootstrap import main as setup_main

        sys.argv = ["anomalyx-setup", *passthrough]
        raise SystemExit(setup_main())

    if args.command == "review-enforcement":
        from ops_tools import main as review_main

        sys.argv = ["anomalyx-review-enforcement", *passthrough]
        raise SystemExit(review_main())

    if args.command == "search-events":
        from ops_tools import main as review_main

        sys.argv = ["anomalyx-review-enforcement", "search-events", *passthrough]
        raise SystemExit(review_main())

    if args.command == "search-enforcement":
        from ops_tools import main as review_main

        sys.argv = ["anomalyx-review-enforcement", "search-enforcement", *passthrough]
        raise SystemExit(review_main())

    if args.command == "unblock-ip":
        from ops_tools import main as review_main

        sys.argv = ["anomalyx-review-enforcement", "unblock-ip", *passthrough]
        raise SystemExit(review_main())

    if passthrough:
        parser.error(f"unrecognized arguments: {' '.join(passthrough)}")

    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

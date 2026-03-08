import argparse
import json
import os
import signal
import time
from collections import deque
from datetime import datetime
from hashlib import sha1, sha256
from pathlib import Path
import hmac

import requests
import importlib

ROOT = Path(__file__).resolve().parent


def _load_backend_hooks():
    env_loader = importlib.import_module("anomalyx_core.env_loader")
    orchestrator_mod = importlib.import_module("anomalyx_core.ips.orchestrator")
    return env_loader.load_env_file, orchestrator_mod.get_ips_orchestrator


def event_key(event):
    packet = event.get("packet", {})
    decision = event.get("decision", {})
    base = {
        "ts": event.get("timestamp"),
        "src": packet.get("src_ip"),
        "dst": packet.get("dst_ip"),
        "sp": packet.get("src_port"),
        "dp": packet.get("dst_port"),
        "proto": packet.get("protocol"),
        "action": decision.get("action"),
        "risk": decision.get("risk"),
    }
    return sha1(json.dumps(base, sort_keys=True).encode("utf-8")).hexdigest()


class AgentRunner:
    def __init__(self, agent_id, agent_token, relay_url, interface=None, log_dir="anomalyx-logs"):
        self.agent_id = agent_id
        self.agent_token = agent_token
        self.relay_url = relay_url.rstrip("/")
        self.interface = interface
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        self.local_events = self.log_dir / "agent_events.jsonl"
        self.local_runtime = self.log_dir / "agent_runtime.log"

        _, get_ips_orchestrator = _load_backend_hooks()
        self.orchestrator = get_ips_orchestrator()
        self.running = True
        self.seen_keys = set()
        self.seen_fifo = deque(maxlen=8000)
        self.last_heartbeat = 0.0
        self.request_timeout = float(os.getenv("AGENT_REQUEST_TIMEOUT_SEC", "6"))
        self.max_retries = int(os.getenv("AGENT_MAX_RETRIES", "3"))
        self.max_events_per_cycle = int(os.getenv("AGENT_MAX_EVENTS_PER_CYCLE", "8"))
        self.min_risk_to_relay = float(os.getenv("AGENT_MIN_RISK_TO_RELAY", "0"))

    def _log(self, msg):
        line = f"[{datetime.utcnow().isoformat()}] {msg}"
        print(line)
        with open(self.local_runtime, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def _jsonl(self, path, payload):
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, separators=(",", ":")) + "\n")

    def _remember(self, key):
        if key in self.seen_keys:
            return
        if len(self.seen_fifo) == self.seen_fifo.maxlen:
            old = self.seen_fifo.popleft()
            self.seen_keys.discard(old)
        self.seen_fifo.append(key)
        self.seen_keys.add(key)

    def _post(self, route, payload, timeout=6, max_response_chars=200):
        url = f"{self.relay_url}{route}"
        ts = str(int(time.time()))
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True)
        sign_blob = f"{self.agent_id}.{ts}.{body}".encode("utf-8")
        signature = hmac.new(self.agent_token.encode("utf-8"), sign_blob, sha256).hexdigest()

        headers = {
            "Content-Type": "application/json",
            "X-Agent-Token": self.agent_token,
            "X-Agent-Id": self.agent_id,
            "X-Agent-Timestamp": ts,
            "X-Agent-Signature": signature,
        }

        last_err = ""
        for attempt in range(1, self.max_retries + 1):
            try:
                res = requests.post(url, headers=headers, data=body, timeout=max(1.0, timeout))
                response_text = res.text or ""
                if max_response_chars and max_response_chars > 0:
                    response_text = response_text[:max_response_chars]
                return res.status_code, response_text
            except requests.RequestException as exc:
                last_err = str(exc)
                if attempt < self.max_retries:
                    time.sleep(0.15 * attempt)

        return 0, last_err

    def _push_event(self, event):
        payload = {
            "agent_id": self.agent_id,
            "event": event,
        }
        code, txt = self._post(f"/api/agent/{self.agent_id}/event", payload, timeout=self.request_timeout)
        if code != 200:
            self._log(f"relay_event_failed code={code} msg={txt}")

    def _push_status(self):
        status = self.orchestrator.status()
        payload = {
            "agent_id": self.agent_id,
            "timestamp": datetime.utcnow().isoformat(),
            "status": status,
        }
        code, txt = self._post(f"/api/agent/{self.agent_id}/status", payload, timeout=self.request_timeout)
        if code != 200:
            self._log(f"relay_status_failed code={code} msg={txt}")

    def _pull_commands(self):
        payload = {
            "agent_id": self.agent_id,
            "timestamp": datetime.utcnow().isoformat(),
        }
        code, txt = self._post(
            f"/api/agent/{self.agent_id}/commands/pull",
            payload,
            timeout=self.request_timeout,
            max_response_chars=5000,
        )
        if code != 200:
            if code not in {404, 401}:
                self._log(f"relay_command_pull_failed code={code} msg={txt}")
            return []
        try:
            data = json.loads(txt or "{}")
        except json.JSONDecodeError:
            return []
        return list(data.get("commands") or [])

    def _execute_command(self, command):
        result = self.orchestrator.execute_command(command)
        self._log(
            f"command action={command.get('action')} remote_ip={command.get('remote_ip')} "
            f"ok={result.get('ok')} details={result.get('details', result.get('result', {}).get('details'))}"
        )

    def _consume_events(self):
        sent_in_cycle = 0
        for event in reversed(self.orchestrator.get_events(limit=400)):
            key = event_key(event)
            if key in self.seen_keys:
                continue

            if sent_in_cycle >= max(1, self.max_events_per_cycle):
                break

            decision = event.get("decision", {})
            risk = float(decision.get("risk", 0) or 0)
            if risk < self.min_risk_to_relay:
                self._remember(key)
                continue

            self._remember(key)
            self._jsonl(self.local_events, event)
            self._push_event(event)
            sent_in_cycle += 1

            packet = event.get("packet", {})
            enforcement = event.get("enforcement", {})
            self._log(
                f"event action={decision.get('action')} risk={decision.get('risk')} "
                f"src={packet.get('src_ip')} dst={packet.get('dst_ip')} enf={enforcement.get('status')}"
            )

    def stop(self, *_):
        self.running = False

    def run(self):
        self._log(
            f"agent_start id={self.agent_id} interface={self.interface or 'auto'} relay={self.relay_url}"
        )

        started = self.orchestrator.start(interface=self.interface)
        if not started:
            self._log("capture_start_failed")
            return 1

        while self.running:
            self._consume_events()
            now = time.time()
            if now - self.last_heartbeat > 3.0:
                self._push_status()
                for cmd in self._pull_commands():
                    self._execute_command(cmd)
                self.last_heartbeat = now
            time.sleep(0.7)

        self._log("agent_stop")
        self.orchestrator.stop()
        self._push_status()
        return 0


def parse_args():
    parser = argparse.ArgumentParser(description="Standalone IPS agent with relay sync")
    parser.add_argument("--agent-id", default=os.getenv("AGENT_ID", "vm-001"))
    parser.add_argument("--agent-token", default=os.getenv("AGENT_TOKEN", "change-me"))
    parser.add_argument("--relay-url", default=os.getenv("RELAY_URL", "http://localhost:8600"))
    parser.add_argument("--interface", default=os.getenv("AGENT_INTERFACE", "") or None)
    parser.add_argument("--log-dir", default=os.getenv("AGENT_LOG_DIR", "anomalyx-logs"))
    return parser.parse_args()


def main():
    load_env_file, _ = _load_backend_hooks()
    load_env_file(str(Path(__file__).resolve().with_name(".env")))

    args = parse_args()
    app = AgentRunner(
        agent_id=args.agent_id,
        agent_token=args.agent_token,
        relay_url=args.relay_url,
        interface=args.interface,
        log_dir=args.log_dir,
    )

    signal.signal(signal.SIGINT, app.stop)
    signal.signal(signal.SIGTERM, app.stop)

    return app.run()


if __name__ == "__main__":
    raise SystemExit(main())

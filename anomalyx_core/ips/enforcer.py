import ctypes
import json
import os
import platform
import subprocess
import threading
import time
from datetime import datetime
import ipaddress
from collections import deque
import shutil


class IPSEnforcer:
    """Applies IPS decisions to host firewall and logs enforcement actions."""

    def __init__(self):
        self.platform = platform.system().lower()
        self.enabled = os.getenv("IPS_ENFORCEMENT_ENABLED", "1") == "1"
        self.drop_ttl_sec = int(os.getenv("IPS_DROP_TTL_SEC", "120"))
        self.block_ttl_sec = int(os.getenv("IPS_BLOCK_TTL_SEC", "3600"))

        self._lock = threading.Lock()
        self._ephemeral_rules = {}
        self._recent_enforcement = {}
        self._block_attempts = deque(maxlen=5000)
        self._total_enforced = 0
        self._failed_enforcements = 0
        self._skipped_enforcements = 0
        self._repeat_suppressed_count = 0
        self._controlled_skips = 0
        self._actions_applied = {"temp_block_ip": 0, "block_ip": 0}

        self.max_new_blocks_per_min = int(os.getenv("IPS_MAX_NEW_BLOCKS_PER_MIN", "120"))
        self.temp_repeat_suppress_sec = int(os.getenv("IPS_TEMP_BLOCK_REPEAT_SUPPRESS_SEC", "20"))
        self.block_repeat_suppress_sec = int(os.getenv("IPS_BLOCK_REPEAT_SUPPRESS_SEC", "180"))

        self.allowlist_ips = set()
        self.allowlist_cidrs = []
        self._load_allowlist()

        default_log_path = os.path.join("anomalyx-logs", "enforcement_actions.log")
        self.log_path = os.getenv("IPS_ENFORCEMENT_LOG_PATH", default_log_path)
        log_dir = os.path.dirname(self.log_path)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        self.last_result = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": "init",
            "status": "ready",
            "details": "enforcer_initialized",
        }

    def _is_rule_exists_error(self, payload):
        blob = f"{payload.get('stdout', '')} {payload.get('stderr', '')}".lower()
        return (
            "already exists" in blob
            or "cannot create a file when that file already exists" in blob
            or "exists with this name" in blob
        )

    def _parse_csv(self, raw):
        return [item.strip() for item in str(raw or "").split(",") if item.strip()]

    def _load_allowlist(self):
        for raw_ip in self._parse_csv(os.getenv("IPS_ALLOWLIST_IPS", "")):
            normalized = raw_ip.split("%", 1)[0]
            try:
                ipaddress.ip_address(normalized)
                self.allowlist_ips.add(normalized)
            except ValueError:
                continue

        for raw_cidr in self._parse_csv(os.getenv("IPS_ALLOWLIST_CIDRS", "")):
            try:
                self.allowlist_cidrs.append(ipaddress.ip_network(raw_cidr, strict=False))
            except ValueError:
                continue

    def _is_allowlisted(self, remote_ip):
        if not remote_ip:
            return False
        candidate = str(remote_ip).split("%", 1)[0]
        if candidate in self.allowlist_ips:
            return True
        try:
            addr = ipaddress.ip_address(candidate)
        except ValueError:
            return False
        return any(addr in network for network in self.allowlist_cidrs)

    def _repeat_suppress_window(self, action):
        return self.block_repeat_suppress_sec if action == "block_ip" else self.temp_repeat_suppress_sec

    def _is_repeat_suppressed(self, action, remote_ip):
        key = f"{action}:{str(remote_ip).split('%', 1)[0]}"
        now = time.time()
        win = max(0, self._repeat_suppress_window(action))
        if win <= 0:
            self._recent_enforcement[key] = now
            return False
        prev = self._recent_enforcement.get(key)
        self._recent_enforcement[key] = now
        return prev is not None and (now - prev) < win

    def _controlled_block_allowed(self):
        now = time.time()
        while self._block_attempts and (now - self._block_attempts[0]) > 60:
            self._block_attempts.popleft()
        if len(self._block_attempts) >= max(1, self.max_new_blocks_per_min):
            return False
        self._block_attempts.append(now)
        return True

    def _is_windows_admin(self):
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _append_log(self, payload):
        line = json.dumps(payload, separators=(",", ":"))
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def _run(self, args, timeout=10):
        completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return {
            "ok": completed.returncode == 0,
            "returncode": completed.returncode,
            "stdout": (completed.stdout or "").strip()[:500],
            "stderr": (completed.stderr or "").strip()[:500],
            "command": " ".join(args),
        }

    def _has_command(self, name):
        return shutil.which(name) is not None

    def _rule_name(self, action, remote_ip):
        safe_ip = str(remote_ip).replace(":", "_").replace(".", "_")
        return f"IPS_{action.upper()}_{safe_ip}"

    def _add_windows_block_rule(self, rule_name, remote_ip):
        # Apply both ingress and egress blocks for consistent host protection.
        directions = ["in", "out"]
        applied_rules = []
        errors = []

        for direction in directions:
            dir_rule_name = f"{rule_name}_{direction.upper()}"
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={dir_rule_name}",
                f"dir={direction}",
                "action=block",
                f"remoteip={remote_ip}",
                "profile=any",
                "enable=yes",
            ]
            res = self._run(cmd)
            if res["ok"] or self._is_rule_exists_error(res):
                applied_rules.append(dir_rule_name)
            else:
                errors.append(res)

        return {
            "ok": len(errors) == 0,
            "applied_rules": applied_rules,
            "errors": errors,
            "command": f"netsh add block rules for {remote_ip}",
        }

    def _delete_windows_rule(self, rule_name):
        results = []
        for suffix in ("_IN", "_OUT", ""):
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}{suffix}",
            ]
            results.append(self._run(cmd))

        return {
            "ok": any(r.get("ok") for r in results),
            "results": results,
            "command": f"netsh delete block rules for {rule_name}",
        }

    def _linux_tool_for_ip(self, remote_ip):
        try:
            addr = ipaddress.ip_address(str(remote_ip).split("%", 1)[0])
        except ValueError:
            return None
        return "iptables" if addr.version == 4 else "ip6tables"

    def _linux_rule_specs(self, remote_ip):
        tool = self._linux_tool_for_ip(remote_ip)
        if not tool:
            return None, []

        # Block traffic both entering from and leaving to the remote IP.
        specs = [
            ("INPUT", ["-s", str(remote_ip), "-j", "DROP"]),
            ("OUTPUT", ["-d", str(remote_ip), "-j", "DROP"]),
        ]
        return tool, specs

    def _add_linux_block_rule(self, remote_ip):
        tool, specs = self._linux_rule_specs(remote_ip)
        if not tool:
            return {
                "ok": False,
                "applied_rules": [],
                "errors": [{"stderr": "invalid_remote_ip"}],
                "command": f"linux firewall add for {remote_ip}",
            }

        applied_rules = []
        errors = []

        for chain, rule_args in specs:
            check_cmd = [tool, "-C", chain, *rule_args]
            check = self._run(check_cmd)
            if check["ok"]:
                applied_rules.append(f"{tool}:{chain}")
                continue

            add_cmd = [tool, "-I", chain, *rule_args]
            add_res = self._run(add_cmd)
            if add_res["ok"]:
                applied_rules.append(f"{tool}:{chain}")
            else:
                errors.append(add_res)

        return {
            "ok": len(errors) == 0,
            "applied_rules": applied_rules,
            "errors": errors,
            "command": f"{tool} add block rules for {remote_ip}",
        }

    def _delete_linux_rule(self, remote_ip):
        tool, specs = self._linux_rule_specs(remote_ip)
        if not tool:
            return {
                "ok": False,
                "results": [],
                "command": f"linux firewall delete for {remote_ip}",
            }

        results = []
        for chain, rule_args in specs:
            cmd = [tool, "-D", chain, *rule_args]
            results.append(self._run(cmd))

        return {
            "ok": any(r.get("ok") for r in results),
            "results": results,
            "command": f"{tool} delete block rules for {remote_ip}",
        }

    def _delete_rules_for_ip(self, remote_ip):
        normalized = str(remote_ip or "").split("%", 1)[0]
        if not normalized:
            return {
                "ok": False,
                "results": [],
                "details": "missing_remote_ip",
            }

        if self.platform == "windows":
            candidates = [
                self._rule_name("temp_block_ip", normalized),
                self._rule_name("block_ip", normalized),
            ]
            results = [self._delete_windows_rule(rule_name) for rule_name in candidates]
            return {
                "ok": any(r.get("ok") for r in results),
                "results": results,
                "details": "windows_rule_delete_attempted",
            }

        if self.platform == "linux":
            result = self._delete_linux_rule(normalized)
            return {
                "ok": bool(result.get("ok")),
                "results": [result],
                "details": "linux_rule_delete_attempted",
            }

        return {
            "ok": False,
            "results": [],
            "details": "unsupported_platform",
        }

    def _cleanup_expired_rules(self):
        now = time.time()
        expired = []
        with self._lock:
            for rule_name, meta in list(self._ephemeral_rules.items()):
                if now >= float(meta.get("expires_at", 0)):
                    expired.append((rule_name, meta))
            for rule_name, _ in expired:
                self._ephemeral_rules.pop(rule_name, None)

        for rule_name, meta in expired:
            platform_hint = meta.get("platform", "")
            remote_ip = meta.get("remote_ip")
            if platform_hint == "linux":
                self._delete_linux_rule(remote_ip)
            else:
                self._delete_windows_rule(rule_name)

    def _is_linux_root(self):
        geteuid = getattr(os, "geteuid", None)
        if callable(geteuid):
            try:
                return int(geteuid()) == 0
            except Exception:
                return False
        return False

    def _validate_runtime(self):
        if not self.enabled:
            return False, "enforcement_disabled"

        if self.platform == "windows":
            if not self._is_windows_admin():
                return False, "administrator_required"

            probe = self._run(["netsh", "advfirewall", "show", "allprofiles"])
            if not probe["ok"]:
                return False, "netsh_unavailable"

            return True, "ok"

        if self.platform == "linux":
            if not self._is_linux_root():
                return False, "root_required"

            has_ipv4 = self._has_command("iptables")
            has_ipv6 = self._has_command("ip6tables")
            if not has_ipv4 and not has_ipv6:
                return False, "iptables_unavailable"

            return True, "ok"

        return False, "unsupported_platform"

    def _is_enforceable_ip(self, remote_ip):
        if not remote_ip:
            return False, "missing_remote_ip"

        candidate = str(remote_ip).split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(candidate)
        except ValueError:
            return False, "invalid_remote_ip"

        if addr.is_unspecified:
            return False, "non_routable_unspecified"
        if addr.is_loopback:
            return False, "non_routable_loopback"
        if addr.is_multicast:
            return False, "non_routable_multicast"
        if getattr(addr, "is_link_local", False):
            return False, "non_routable_link_local"

        if addr.version == 4 and str(addr).endswith(".255"):
            return False, "non_routable_broadcast"

        return True, "ok"

    def enforce(self, decision, packet):
        self._cleanup_expired_rules()

        action = str(decision.get("action", "allow") or "allow").lower()
        if action in {"drop", "drop_packet"}:
            action = "temp_block_ip"
        remote_ip = packet.get("traffic_source", {}).get("remote_ip") or packet.get("dst_ip") or packet.get("src_ip")
        if remote_ip:
            remote_ip = str(remote_ip).split("%", 1)[0]

        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "remote_ip": remote_ip,
            "status": "no_action",
            "details": "not_required",
            "rule_name": None,
            "applied": False,
        }

        if action in {"allow", "alert"}:
            self.last_result = result
            self._append_log(result)
            return result

        if self._is_allowlisted(remote_ip):
            result.update({"status": "skipped", "details": "allowlisted_remote_ip"})
            self._skipped_enforcements += 1
            self.last_result = result
            self._append_log(result)
            return result

        runtime_ok, runtime_msg = self._validate_runtime()
        if not runtime_ok:
            result.update({"status": "failed", "details": runtime_msg})
            self._failed_enforcements += 1
            self.last_result = result
            self._append_log(result)
            return result

        enforceable, enforce_msg = self._is_enforceable_ip(remote_ip)
        if not enforceable:
            result.update({"status": "skipped", "details": enforce_msg})
            self._skipped_enforcements += 1
            self.last_result = result
            self._append_log(result)
            return result

        if not remote_ip:
            result.update({"status": "failed", "details": "missing_remote_ip"})
            self._failed_enforcements += 1
            self.last_result = result
            self._append_log(result)
            return result

        if action not in {"temp_block_ip", "block_ip"}:
            result.update({"status": "failed", "details": f"unsupported_action:{action}"})
            self._failed_enforcements += 1
            self.last_result = result
            self._append_log(result)
            return result

        if self._is_repeat_suppressed(action, remote_ip):
            result.update({"status": "skipped", "details": "repeat_suppressed"})
            self._repeat_suppressed_count += 1
            self._skipped_enforcements += 1
            self.last_result = result
            self._append_log(result)
            return result

        if not self._controlled_block_allowed():
            result.update({"status": "skipped", "details": "controlled_block_rate_limited"})
            self._controlled_skips += 1
            self._skipped_enforcements += 1
            self.last_result = result
            self._append_log(result)
            return result

        ttl = self.drop_ttl_sec if action == "temp_block_ip" else self.block_ttl_sec
        rule_name = self._rule_name(action, remote_ip)
        if self.platform == "windows":
            apply_result = self._add_windows_block_rule(rule_name, remote_ip)
        elif self.platform == "linux":
            apply_result = self._add_linux_block_rule(remote_ip)
        else:
            apply_result = {
                "ok": False,
                "applied_rules": [],
                "errors": [{"stderr": "unsupported_platform"}],
                "command": "unsupported_platform",
            }

        if apply_result["ok"]:
            if action == "temp_block_ip":
                with self._lock:
                    self._ephemeral_rules[rule_name] = {
                        "expires_at": time.time() + max(5, ttl),
                        "remote_ip": remote_ip,
                        "platform": self.platform,
                    }
            result.update(
                {
                    "status": "applied",
                    "details": "firewall_rule_added",
                    "rule_name": rule_name,
                    "applied": True,
                    "applied_rules": apply_result.get("applied_rules", []),
                    "ttl_sec": ttl,
                    "command": apply_result["command"],
                }
            )
            self._total_enforced += 1
            self._actions_applied[action] = self._actions_applied.get(action, 0) + 1
        else:
            error_blob = " | ".join(
                [
                    f"{e.get('stderr') or e.get('stdout') or 'unknown_error'}"
                    for e in apply_result.get("errors", [])
                ]
            )[:800]
            result.update(
                {
                    "status": "failed",
                    "details": "firewall_rule_add_failed",
                    "rule_name": rule_name,
                    "applied": False,
                    "command": apply_result["command"],
                    "stderr": error_blob,
                }
            )
            self._failed_enforcements += 1

        self.last_result = result
        self._append_log(result)
        return result

    def unblock_ip(self, remote_ip, reason="manual_unblock"):
        normalized = str(remote_ip or "").split("%", 1)[0]
        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": "unblock_ip",
            "remote_ip": normalized,
            "status": "failed",
            "details": "not_attempted",
            "applied": False,
            "reason": reason,
        }

        runtime_ok, runtime_msg = self._validate_runtime()
        if not runtime_ok:
            result.update({"details": runtime_msg})
            self.last_result = result
            self._append_log(result)
            return result

        enforceable, enforce_msg = self._is_enforceable_ip(normalized)
        if not enforceable:
            result.update({"status": "skipped", "details": enforce_msg})
            self.last_result = result
            self._append_log(result)
            return result

        deletion = self._delete_rules_for_ip(normalized)
        if deletion.get("ok"):
            result.update(
                {
                    "status": "applied",
                    "details": "firewall_rule_deleted",
                    "applied": True,
                    "results": deletion.get("results", []),
                }
            )
        else:
            result.update(
                {
                    "status": "failed",
                    "details": deletion.get("details", "firewall_rule_delete_failed"),
                    "results": deletion.get("results", []),
                }
            )

        # Clear local caches so future decisions are not muted by stale suppression keys.
        for key in [f"temp_block_ip:{normalized}", f"block_ip:{normalized}"]:
            self._recent_enforcement.pop(key, None)

        with self._lock:
            for rule_name, meta in list(self._ephemeral_rules.items()):
                if str(meta.get("remote_ip") or "") == normalized:
                    self._ephemeral_rules.pop(rule_name, None)

        self.last_result = result
        self._append_log(result)
        return result

    def status(self):
        runtime_ok, runtime_msg = self._validate_runtime()
        with self._lock:
            active_ephemeral = len(self._ephemeral_rules)

        return {
            "enabled": self.enabled,
            "platform": self.platform,
            "runtime_ok": runtime_ok,
            "runtime_message": runtime_msg,
            "total_enforced": self._total_enforced,
            "failed_enforcements": self._failed_enforcements,
            "skipped_enforcements": self._skipped_enforcements,
            "repeat_suppressed": self._repeat_suppressed_count,
            "controlled_skips": self._controlled_skips,
            "actions_applied": dict(self._actions_applied),
            "max_new_blocks_per_min": self.max_new_blocks_per_min,
            "allowlist": {
                "ips": sorted(self.allowlist_ips),
                "cidr_count": len(self.allowlist_cidrs),
            },
            "active_ephemeral_rules": active_ephemeral,
            "last_result": self.last_result,
            "log_path": self.log_path,
        }

    def tail_logs(self, limit=50):
        if not os.path.exists(self.log_path):
            return []

        with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[-max(1, int(limit)):]

        parsed = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                parsed.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return parsed

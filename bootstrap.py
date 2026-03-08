import argparse
import importlib
import os
import platform
import shutil
import subprocess
import sys


def _run(cmd):
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
            shell=False,
        )
        out = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
        return completed.returncode == 0, out.strip()
    except Exception as exc:
        return False, str(exc)


def _print_step(message):
    print(f"[setup] {message}")


def _has_command(name):
    return shutil.which(name) is not None


def _install_python_dependencies():
    _print_step("Installing Python dependencies (including scapy)...")
    ok, out = _run([
        sys.executable,
        "-m",
        "pip",
        "install",
        "--upgrade",
        "scapy",
        "requests",
        "flask",
        "waitress",
        "joblib",
        "numpy",
        "pandas",
    ])
    if not ok:
        print(out)
        return False

    try:
        importlib.import_module("scapy.all")
    except Exception as exc:
        _print_step(f"Scapy import check failed: {exc}")
        return False

    _print_step("Python dependency setup complete.")
    return True


def _npcap_installed():
    if platform.system().lower() != "windows":
        return True

    ok, _ = _run(["sc.exe", "query", "npcap"])
    if ok:
        return True

    # Fallback check via common install directory.
    return os.path.exists(r"C:\Windows\System32\Npcap")


def _install_npcap_windows():
    if _npcap_installed():
        _print_step("Npcap already installed.")
        return True

    _print_step("Npcap not detected. Attempting auto-install...")

    if _has_command("winget"):
        _print_step("Trying winget install for Npcap...")
        ok, out = _run([
            "winget",
            "install",
            "--id",
            "Npcap.Npcap",
            "-e",
            "--silent",
            "--accept-package-agreements",
            "--accept-source-agreements",
        ])
        if ok:
            _print_step("Npcap installed via winget.")
            return True
        _print_step("winget install failed; trying Chocolatey if available.")
        if out:
            print(out)

    if _has_command("choco"):
        _print_step("Trying choco install for Npcap...")
        ok, out = _run(["choco", "install", "npcap", "-y"])
        if ok:
            _print_step("Npcap installed via Chocolatey.")
            return True
        if out:
            print(out)

    _print_step("Automatic Npcap install failed.")
    print("[setup] Please install Npcap manually from: https://npcap.com/#download")
    return False


def _check_capture_runtime():
    if platform.system().lower() == "windows" and not _npcap_installed():
        _print_step("Capture runtime check: Npcap missing.")
        return False

    try:
        importlib.import_module("scapy.all")
    except Exception as exc:
        _print_step(f"Capture runtime check: Scapy missing/broken: {exc}")
        return False

    if platform.system().lower() == "linux":
        geteuid = getattr(os, "geteuid", None)
        if callable(geteuid) and int(geteuid()) != 0:
            _print_step("Linux note: run `sudo anomalyx agent ...` for packet capture and enforcement.")

        has_iptables = shutil.which("iptables") is not None
        has_ip6tables = shutil.which("ip6tables") is not None
        if not has_iptables and not has_ip6tables:
            _print_step("Linux warning: iptables/ip6tables not found. Enforcement will fail until installed.")

    _print_step("Capture runtime check passed.")
    return True


def parse_args():
    parser = argparse.ArgumentParser(description="AnomalyX bootstrap for packet capture dependencies")
    parser.add_argument("--check-only", action="store_true", help="Only verify setup state")
    parser.add_argument("--python-deps-only", action="store_true", help="Install Python dependencies only")
    parser.add_argument("--skip-npcap", action="store_true", help="Skip Npcap installation on Windows")
    return parser.parse_args()


def main():
    args = parse_args()

    if args.check_only:
        return 0 if _check_capture_runtime() else 1

    py_ok = _install_python_dependencies()
    if not py_ok:
        _print_step("Python dependency installation failed.")
        return 1

    if platform.system().lower() == "windows" and not args.python_deps_only and not args.skip_npcap:
        if not _install_npcap_windows():
            _print_step("Setup completed with warnings: Npcap not installed.")
            return 2

    if _check_capture_runtime():
        _print_step("Setup complete. You can now run `anomalyx agent ...`.")
        return 0

    _print_step("Setup incomplete. See messages above.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

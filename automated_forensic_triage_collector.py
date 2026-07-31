#!/usr/bin/env python3
"""Lightweight, cross-platform endpoint triage collector.

Run only with appropriate authorization. The collector writes artifacts to a
temporary directory, packages them into a ZIP archive, and removes that
temporary directory when packaging succeeds.
"""

from __future__ import annotations

import csv
import datetime as dt
import getpass
import json
import os
import platform
import shutil
import socket
import sys
import tempfile
import traceback
import zipfile
from pathlib import Path
from typing import Any, Callable, Iterable

import psutil


SCRIPT_VERSION = "1.0"
IS_WINDOWS = platform.system().lower() == "windows"


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def iso_time(value: dt.datetime | None = None) -> str:
    return (value or utc_now()).isoformat(timespec="seconds")


def status(message: str) -> None:
    print(f"[+] {message}", flush=True)


def warn(message: str) -> None:
    print(f"[!] {message}", file=sys.stderr, flush=True)


def error_text(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"


def safe_hostname() -> str:
    hostname = socket.gethostname() or "unknown-host"
    return "".join(char if char.isalnum() or char in "-_." else "_" for char in hostname)


def write_json(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False, default=str)
        handle.write("\n")


def write_text(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", errors="replace")


def address_parts(address: Any) -> tuple[str, str]:
    """Return address and port without assuming an IPv4 tuple."""
    if not address:
        return "", ""
    try:
        return str(address.ip), str(address.port)
    except AttributeError:
        try:
            return str(address[0]), str(address[1])
        except (IndexError, TypeError):
            return str(address), ""


def collect_system_info(output_dir: Path) -> None:
    boot_time = dt.datetime.fromtimestamp(psutil.boot_time(), tz=dt.timezone.utc)
    now = utc_now()
    content = {
        "collector_version": SCRIPT_VERSION,
        "collection_timestamp_utc": iso_time(now),
        "hostname": socket.gethostname(),
        "fqdn": socket.getfqdn(),
        "operating_system": platform.platform(),
        "os_family": platform.system(),
        "os_release": platform.release(),
        "os_version": platform.version(),
        "architecture": platform.machine(),
        "python_version": platform.python_version(),
        "boot_time_utc": iso_time(boot_time),
        "uptime_seconds": round((now - boot_time).total_seconds(), 2),
    }
    lines = [f"{key}: {value}" for key, value in content.items()]
    write_text(output_dir / "system_info.txt", "\n".join(lines) + "\n")


def collect_network_connections(output_dir: Path) -> None:
    fields = ["protocol", "pid", "local_address", "local_port", "remote_address", "remote_port", "status"]
    with (output_dir / "network_connections.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            warn(f"Could not enumerate network connections: {error_text(exc)}")
            return
        for conn in connections:
            local_ip, local_port = address_parts(conn.laddr)
            remote_ip, remote_port = address_parts(conn.raddr)
            writer.writerow({
                "protocol": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                "pid": "" if conn.pid is None else conn.pid,
                "local_address": local_ip,
                "local_port": local_port,
                "remote_address": remote_ip,
                "remote_port": remote_port,
                "status": conn.status or "NONE",
            })


def collect_processes(output_dir: Path) -> None:
    records: list[dict[str, Any]] = []
    for process in psutil.process_iter(attrs=["pid", "name", "exe", "cmdline"]):
        try:
            info = process.info
            records.append({
                "pid": info.get("pid"),
                "name": info.get("name") or "",
                "executable_path": info.get("exe") or "",
                "command_line": info.get("cmdline") or [],
                "access_error": "",
            })
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess) as exc:
            records.append({
                "pid": process.pid,
                "name": "",
                "executable_path": "",
                "command_line": [],
                "access_error": error_text(exc),
            })
    write_json(output_dir / "processes.json", records)


def collect_user_activity(output_dir: Path) -> None:
    users: list[dict[str, Any]] = []
    try:
        sessions = psutil.users()
    except (psutil.AccessDenied, OSError) as exc:
        sessions = []
        warn(f"Could not enumerate logged-in users: {error_text(exc)}")
    for session in sessions:
        started = ""
        if session.started:
            started = iso_time(dt.datetime.fromtimestamp(session.started, tz=dt.timezone.utc))
        users.append({
            "username": session.name,
            "terminal": session.terminal or "",
            "host": session.host or "",
            "started_utc": started,
            "pid": session.pid,
        })
    write_json(output_dir / "user_activity.json", {
        "collector_user": getpass.getuser(),
        "logged_in_sessions": users,
    })


def copy_text_artifact(source: Path, destination: Path, notes: list[str]) -> None:
    try:
        write_text(destination, source.read_text(encoding="utf-8", errors="replace"))
        notes.append(f"Collected: {source}")
    except (OSError, PermissionError) as exc:
        notes.append(f"Unable to read {source}: {error_text(exc)}")


def collect_linux_persistence(output_dir: Path, notes: list[str]) -> None:
    home = Path.home()
    copy_text_artifact(home / ".bash_history", output_dir / "bash_history.txt", notes)
    copy_text_artifact(Path("/etc/crontab"), output_dir / "etc_crontab.txt", notes)


def iter_powershell_history_paths() -> Iterable[Path]:
    # History is normally per user, but include the current process's profile
    # explicitly for environments where HOME and USERPROFILE differ.
    homes = {Path.home()}
    for variable in ("USERPROFILE", "HOME"):
        value = os.environ.get(variable)
        if value:
            homes.add(Path(value))
    for home in homes:
        yield home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"


def read_registry_run_keys() -> list[dict[str, str]]:
    import winreg  # Available only on Windows.

    results: list[dict[str, str]] = []
    locations = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
    ]
    for root, subkey, hive_name in locations:
        key_path = f"{hive_name}\\{subkey}"
        try:
            with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        name, value, value_type = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    results.append({
                        "registry_key": key_path,
                        "value_name": name,
                        "value_data": str(value),
                        "value_type": str(value_type),
                    })
                    index += 1
        except OSError as exc:
            results.append({
                "registry_key": key_path,
                "value_name": "",
                "value_data": "",
                "value_type": f"ERROR: {error_text(exc)}",
            })
    return results


def collect_windows_persistence(output_dir: Path, notes: list[str]) -> None:
    histories = list(iter_powershell_history_paths())
    found_history = False
    for index, history in enumerate(histories, start=1):
        if history.is_file():
            copy_text_artifact(history, output_dir / f"powershell_history_{index}.txt", notes)
            found_history = True
    if not found_history:
        notes.append("PowerShell ConsoleHost_history.txt was not found in the current user's profile paths.")

    startup = Path(os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    startup_entries: list[dict[str, str]] = []
    try:
        if startup.is_dir():
            for entry in startup.iterdir():
                try:
                    startup_entries.append({"name": entry.name, "path": str(entry), "type": "directory" if entry.is_dir() else "file"})
                except OSError as exc:
                    startup_entries.append({"name": entry.name, "path": str(entry), "type": f"ERROR: {error_text(exc)}"})
        else:
            notes.append(f"Startup folder not found: {startup}")
    except OSError as exc:
        notes.append(f"Unable to inspect Startup folder {startup}: {error_text(exc)}")
    write_json(output_dir / "startup_folder.json", startup_entries)
    write_json(output_dir / "registry_run_keys.json", read_registry_run_keys())


def collect_commands_and_persistence(output_dir: Path) -> None:
    notes: list[str] = [f"Operating system: {platform.system()}"]
    if IS_WINDOWS:
        collect_windows_persistence(output_dir, notes)
    elif platform.system().lower() == "linux":
        collect_linux_persistence(output_dir, notes)
    else:
        notes.append("Command-history and persistence collection is currently implemented for Windows and Linux only.")
    write_text(output_dir / "persistence_collection_notes.txt", "\n".join(notes) + "\n")


def run_module(label: str, callback: Callable[[Path], None], output_dir: Path, failures: list[str]) -> None:
    status(f"Collecting {label}...")
    try:
        callback(output_dir)
    except Exception as exc:  # Keep acquisition moving after unexpected module failures.
        message = f"{label}: {error_text(exc)}"
        failures.append(message)
        warn(message)
        traceback.print_exc()
    else:
        print("    Done.", flush=True)


def create_archive(source_dir: Path, archive_path: Path) -> None:
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for file_path in source_dir.rglob("*"):
            if file_path.is_file():
                archive.write(file_path, file_path.relative_to(source_dir))


def main() -> int:
    timestamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    hostname = safe_hostname()
    output_parent = Path.cwd()
    archive_path = output_parent / f"triage_collection_{hostname}_{timestamp}.zip"
    temp_dir = Path(tempfile.mkdtemp(prefix=f"triage_{hostname}_{timestamp}_", dir=output_parent))
    failures: list[str] = []

    status(f"Writing collection artifacts to: {temp_dir}")
    run_module("system information", collect_system_info, temp_dir, failures)
    run_module("network connections", collect_network_connections, temp_dir, failures)
    run_module("running processes", collect_processes, temp_dir, failures)
    run_module("user activity", collect_user_activity, temp_dir, failures)
    run_module("recent commands and persistence", collect_commands_and_persistence, temp_dir, failures)
    write_json(temp_dir / "collection_metadata.json", {
        "collector_version": SCRIPT_VERSION,
        "collection_timestamp_utc": iso_time(),
        "archive_name": archive_path.name,
        "module_failures": failures,
    })

    status("Creating ZIP archive...")
    try:
        create_archive(temp_dir, archive_path)
    except Exception as exc:
        warn(f"Archiving failed; uncompressed data retained at {temp_dir}: {error_text(exc)}")
        return 1

    try:
        shutil.rmtree(temp_dir)
    except OSError as exc:
        warn(f"Archive created, but could not remove temporary folder {temp_dir}: {error_text(exc)}")
        return 1

    status(f"Collection complete: {archive_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        warn("Collection interrupted by user.")
        raise SystemExit(130)

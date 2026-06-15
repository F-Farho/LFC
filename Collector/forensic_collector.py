#!/usr/bin/env python3
"""Linux forensic collector.

The collector uses Python's standard library and tools already present on the
examined host. It never installs or removes packages. Missing capabilities are
recorded in metadata and collection continues with the available evidence.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import logging
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

VERSION = "3.0.0"
DEFAULT_COMMAND_TIMEOUT = 60
LOGGER = logging.getLogger("forensic_collector")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ForensicCollector:
    """Collect a practical set of volatile and persistent Linux artifacts."""

    CAPABILITY_COMMANDS = (
        "ps", "ss", "netstat", "lsof", "who", "w", "last", "lastb",
        "journalctl", "dmesg", "systemctl", "crontab", "lsmod", "ip",
        "findmnt", "lsblk", "iptables", "ip6tables", "nft", "ufw",
        "firewall-cmd", "dpkg-query", "rpm", "pacman", "openssl", "find",
    )

    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.started_at = utc_now()
        self.timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%SZ")
        self.base_dir = Path(args.output_dir or os.getcwd()).expanduser().resolve()
        self.output_dir = self.base_dir / f"forensic_data_{self.timestamp}"
        self.temp_dir = self.output_dir / "artifacts"
        self.archive_path = self.output_dir / (
            "forensic_data.zip" if args.format == "zip" else "forensic_data.tar.gz"
        )
        self.capabilities = {
            command: bool(shutil.which(command)) for command in self.CAPABILITY_COMMANDS
        }
        self.metadata: dict = {
            "schema_version": "1.0",
            "collector_version": VERSION,
            "collection_started_utc": self.started_at,
            "collection_finished_utc": None,
            "hostname": platform.node(),
            "platform": platform.platform(),
            "effective_uid": os.geteuid(),
            "is_root": os.geteuid() == 0,
            "command_line": sys.argv,
            "capabilities": self.capabilities,
            "artifacts": [],
            "errors": [],
        }
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        self._configure_logging()

    def _configure_logging(self) -> None:
        for handler in LOGGER.handlers:
            handler.close()
        LOGGER.handlers.clear()
        LOGGER.setLevel(logging.DEBUG if self.args.verbose else logging.INFO)
        formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        file_handler = logging.FileHandler(self.output_dir / "forensic_collector.log")
        file_handler.setFormatter(formatter)
        LOGGER.addHandler(file_handler)
        if not self.args.silent:
            console = logging.StreamHandler()
            console.setFormatter(formatter)
            LOGGER.addHandler(console)

    def _record(self, path: str, source: str, success: bool, **details: object) -> None:
        item = {"path": path, "source": source, "success": success, **details}
        self.metadata["artifacts"].append(item)
        if not success:
            self.metadata["errors"].append(item)

    def _destination(self, relative_path: str) -> Path:
        destination = self.temp_dir / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        return destination

    def _command_exists(self, command: str) -> bool:
        return self.capabilities.get(command, bool(shutil.which(command)))

    def save_command(self, command: list[str], relative_path: str, timeout: int | None = None) -> bool:
        """Save stdout/stderr and command status without invoking a shell."""
        destination = self._destination(relative_path)
        started = time.monotonic()
        timeout = timeout or self.args.command_timeout
        if not self._command_exists(command[0]):
            message = f"Command not available: {command[0]}"
            destination.write_text(message + "\n", encoding="utf-8")
            self._record(relative_path, "command", False, command=command, error=message)
            return False
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=timeout,
                check=False,
            )
            destination.write_text(result.stdout, encoding="utf-8", errors="replace")
            if result.stderr:
                destination.with_suffix(destination.suffix + ".stderr").write_text(
                    result.stderr, encoding="utf-8", errors="replace"
                )
            self._record(
                relative_path,
                "command",
                result.returncode == 0,
                command=command,
                return_code=result.returncode,
                duration_seconds=round(time.monotonic() - started, 3),
                stderr_file=(relative_path + ".stderr") if result.stderr else None,
            )
            return result.returncode == 0
        except subprocess.TimeoutExpired as exc:
            destination.write_text(exc.stdout or "", encoding="utf-8", errors="replace")
            self._record(relative_path, "command", False, command=command, error="timeout")
            return False
        except Exception as exc:
            destination.write_text(f"Collection error: {exc}\n", encoding="utf-8")
            self._record(relative_path, "command", False, command=command, error=str(exc))
            return False

    def copy_file(self, source: str | Path, relative_path: str) -> bool:
        source_path = Path(source)
        destination = self._destination(relative_path)
        try:
            if not source_path.is_file() and not source_path.is_symlink():
                raise FileNotFoundError(f"Not a file: {source_path}")
            if source_path.is_symlink():
                destination.write_text(os.readlink(source_path), encoding="utf-8", errors="replace")
            else:
                shutil.copy2(source_path, destination)
            source_stat = source_path.lstat()
            self._record(
                relative_path,
                "file",
                True,
                original_path=str(source_path),
                size=source_stat.st_size,
                mode=stat.filemode(source_stat.st_mode),
                uid=source_stat.st_uid,
                gid=source_stat.st_gid,
                mtime_ns=source_stat.st_mtime_ns,
            )
            return True
        except Exception as exc:
            self._record(relative_path, "file", False, original_path=str(source_path), error=str(exc))
            return False

    def copy_directory(self, source: str | Path, relative_path: str) -> int:
        source_path = Path(source)
        copied = 0
        if not source_path.is_dir():
            self._record(relative_path, "directory", False, original_path=str(source_path), error="not found")
            return copied
        for root, directories, files in os.walk(source_path, followlinks=False):
            directories[:] = [name for name in directories if not (Path(root) / name).is_symlink()]
            for filename in files:
                path = Path(root) / filename
                destination = Path(relative_path) / path.relative_to(source_path)
                copied += int(self.copy_file(path, str(destination)))
        return copied

    def copy_existing(self, sources: Iterable[str], relative_directory: str) -> None:
        for source in sources:
            path = Path(source)
            destination = str(Path(relative_directory) / path.name)
            if path.is_dir():
                self.copy_directory(path, destination)
            elif path.exists() or path.is_symlink():
                self.copy_file(path, destination)

    def save_text(self, relative_path: str, content: str, source: str = "python") -> None:
        self._destination(relative_path).write_text(content, encoding="utf-8", errors="replace")
        self._record(relative_path, source, True)

    def collect_volatile_state(self) -> None:
        LOGGER.info("Collecting volatile process, session, and network state")
        process_commands = [
            (["ps", "-eo", "pid,ppid,uid,gid,lstart,etime,stat,comm,args"], "volatile/processes.txt"),
            (["ps", "auxf"], "volatile/process_tree.txt"),
            (["who", "-a"], "volatile/who.txt"),
            (["w"], "volatile/w.txt"),
        ]
        for command, path in process_commands:
            self.save_command(command, path)

        if self._command_exists("ss"):
            self.save_command(["ss", "-tulpan"], "volatile/network_sockets.txt")
        elif self._command_exists("netstat"):
            self.save_command(["netstat", "-tulpan"], "volatile/network_sockets.txt")

        if self._command_exists("lsof"):
            self.save_command(["lsof", "-nP"], "volatile/open_files.txt", timeout=120)

        self.copy_existing(
            ["/proc/meminfo", "/proc/loadavg", "/proc/uptime", "/proc/stat", "/proc/modules"],
            "volatile/proc",
        )
        self.copy_existing(
            ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6", "/proc/net/unix", "/proc/net/arp", "/proc/net/route", "/proc/net/ipv6_route"],
            "volatile/proc_net",
        )
        self.collect_proc_snapshot()

    def collect_proc_snapshot(self) -> None:
        """Collect a bounded /proc fallback for processes and open descriptors."""
        process_data = []
        descriptor_data = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            record = {"pid": int(entry.name)}
            for name in ("status", "cmdline", "comm", "cgroup"):
                try:
                    value = (entry / name).read_text(encoding="utf-8", errors="replace")
                    record[name] = value.replace("\x00", " ").strip()
                except OSError:
                    pass
            for name in ("exe", "cwd"):
                try:
                    record[name] = os.readlink(entry / name)
                except OSError:
                    pass
            process_data.append(record)
            try:
                for descriptor in (entry / "fd").iterdir():
                    try:
                        descriptor_data.append({"pid": int(entry.name), "fd": descriptor.name, "target": os.readlink(descriptor)})
                    except OSError:
                        pass
            except OSError:
                pass
        self.save_text("volatile/proc_processes.json", json.dumps(process_data, indent=2))
        self.save_text("volatile/proc_open_files.json", json.dumps(descriptor_data, indent=2))

    def collect_system_identity(self) -> None:
        LOGGER.info("Collecting system identity, storage, and kernel information")
        self.copy_existing(
            ["/etc/os-release", "/etc/hostname", "/etc/machine-id", "/proc/version", "/proc/cmdline", "/proc/cpuinfo", "/proc/mounts", "/proc/self/mountinfo", "/etc/fstab"],
            "system",
        )
        for command, path in [
            (["dmesg", "--ctime"], "system/dmesg.txt"),
            (["lsmod"], "system/loaded_modules.txt"),
            (["findmnt", "--all"], "system/mounts.txt"),
            (["lsblk", "-a", "-o", "NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINT,UUID,MODEL,SERIAL"], "system/block_devices.txt"),
        ]:
            self.save_command(command, path)

    def collect_logs(self) -> None:
        LOGGER.info("Collecting logs")
        log_files = [
            "/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages",
            "/var/log/kern.log", "/var/log/dmesg", "/var/log/wtmp", "/var/log/btmp",
            "/var/log/lastlog", "/var/log/faillog", "/var/log/dpkg.log", "/var/log/yum.log",
        ]
        self.copy_existing(log_files, "logs")
        if Path("/var/log/audit").exists():
            self.copy_directory("/var/log/audit", "logs/audit_log")
        if Path("/etc/audit").exists():
            self.copy_directory("/etc/audit", "logs/audit_configuration")
        if self._command_exists("journalctl"):
            self.save_command(["journalctl", "--no-pager", "-o", "short-iso", "-b"], "logs/journal_current_boot.log", timeout=180)
            self.save_command(["journalctl", "--no-pager", "-o", "short-iso", "-b", "-1"], "logs/journal_previous_boot.log", timeout=180)
        self.save_command(["last", "-n", "200"], "logs/last_logins.txt")
        self.save_command(["lastb", "-n", "200"], "logs/failed_logins.txt")

    def collect_accounts_and_access(self) -> None:
        LOGGER.info("Collecting accounts, privileges, SSH access, and shell history")
        self.copy_existing(
            ["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/login.defs", "/etc/security", "/etc/sudoers.d", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d", "/etc/ssh/ssh_config", "/etc/ssh/ssh_config.d"],
            "accounts",
        )
        for home_root in (Path("/home"), Path("/root")):
            homes = list(home_root.iterdir()) if home_root == Path("/home") and home_root.exists() else [home_root]
            for home in homes:
                if not home.exists() or not home.is_dir():
                    continue
                user = "root" if home == Path("/root") else home.name
                for filename in (".bash_history", ".zsh_history", ".python_history", ".lesshst", ".viminfo"):
                    path = home / filename
                    if path.exists():
                        self.copy_file(path, f"accounts/history/{user}_{filename.lstrip('.')}")
                ssh_directory = home / ".ssh"
                for filename in ("authorized_keys", "authorized_keys2", "known_hosts", "config"):
                    path = ssh_directory / filename
                    if path.exists():
                        self.copy_file(path, f"accounts/users/{user}/ssh/{filename}")
                autostart = home / ".config/autostart"
                if autostart.exists():
                    self.copy_directory(autostart, f"accounts/users/{user}/autostart")

    def collect_persistence(self) -> None:
        LOGGER.info("Collecting scheduled tasks, services, and startup configuration")
        self.copy_existing(
            ["/etc/crontab", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly", "/etc/anacrontab", "/var/spool/cron", "/var/spool/cron/crontabs", "/etc/init.d", "/etc/rc.local", "/etc/profile", "/etc/profile.d"],
            "persistence",
        )
        for source, destination in (
            ("/etc/systemd/system", "persistence/systemd_etc"),
            ("/usr/lib/systemd/system", "persistence/systemd_usr_lib"),
            ("/lib/systemd/system", "persistence/systemd_lib"),
        ):
            if Path(source).exists():
                self.copy_directory(source, destination)
        if self._command_exists("systemctl"):
            self.save_command(["systemctl", "list-units", "--all", "--no-pager"], "persistence/systemd_units.txt")
            self.save_command(["systemctl", "list-unit-files", "--no-pager"], "persistence/systemd_unit_files.txt")
            self.save_command(["systemctl", "list-timers", "--all", "--no-pager"], "persistence/systemd_timers.txt")

    def collect_network_configuration(self) -> None:
        LOGGER.info("Collecting network and firewall configuration")
        self.copy_existing(
            ["/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/hostname", "/etc/network", "/etc/NetworkManager", "/etc/systemd/network", "/etc/netplan", "/etc/ufw", "/etc/firewalld"],
            "network",
        )
        commands = [
            (["ip", "address", "show"], "network/ip_addresses.txt"),
            (["ip", "route", "show", "table", "all"], "network/routes.txt"),
            (["ip", "neighbor", "show"], "network/neighbors.txt"),
            (["iptables", "-S"], "network/iptables_rules.txt"),
            (["ip6tables", "-S"], "network/ip6tables_rules.txt"),
            (["nft", "list", "ruleset"], "network/nftables_rules.txt"),
            (["ufw", "status", "verbose"], "network/ufw_status.txt"),
            (["firewall-cmd", "--list-all-zones"], "network/firewalld_zones.txt"),
        ]
        for command, path in commands:
            self.save_command(command, path)

    def collect_package_inventory(self) -> None:
        LOGGER.info("Collecting installed package inventory")
        if self._command_exists("dpkg-query"):
            self.save_command(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${Architecture}\n"], "packages/installed.txt")
        elif self._command_exists("rpm"):
            self.save_command(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"], "packages/installed.txt")
        elif self._command_exists("pacman"):
            self.save_command(["pacman", "-Q"], "packages/installed.txt")
        self.copy_existing(["/etc/apt/sources.list", "/etc/apt/sources.list.d", "/etc/yum.repos.d", "/etc/pacman.conf"], "packages/configuration")

    def collect_file_indicators(self) -> None:
        """Run optional, bounded file metadata searches; no content is classified."""
        if not self.args.scan_files:
            return
        LOGGER.info("Collecting optional file indicators")
        if not self._command_exists("find"):
            self._record("file_indicators", "command", False, error="find is unavailable")
            return
        commands = [
            (["find", "/", "-xdev", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-ls"], "file_indicators/suid_sgid.txt"),
            (["find", "/", "-xdev", "(", "-nouser", "-o", "-nogroup", ")", "-ls"], "file_indicators/unowned.txt"),
            (["find", "/tmp", "/var/tmp", "/dev/shm", "-xdev", "-type", "f", "-ls"], "file_indicators/temporary_files.txt"),
        ]
        for command, path in commands:
            self.save_command(command, path, timeout=self.args.scan_timeout)

    def hash_artifacts(self) -> None:
        LOGGER.info("Hashing collected artifacts")
        hashes = {}
        for path in self.temp_dir.rglob("*"):
            if not path.is_file():
                continue
            digest = hashlib.sha256()
            try:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                hashes[str(path.relative_to(self.temp_dir))] = digest.hexdigest()
            except OSError as exc:
                self.metadata["errors"].append({"path": str(path), "source": "hash", "success": False, "error": str(exc)})
        self.metadata["sha256"] = hashes

    def write_metadata(self) -> None:
        self.metadata["collection_finished_utc"] = utc_now()
        self.metadata["summary"] = {
            "successful_artifacts": sum(1 for item in self.metadata["artifacts"] if item["success"]),
            "failed_artifacts": sum(1 for item in self.metadata["artifacts"] if not item["success"]),
        }
        self._destination("metadata.json").write_text(json.dumps(self.metadata, indent=2), encoding="utf-8")

    def create_archive(self) -> None:
        LOGGER.info("Creating %s archive", self.args.format)
        if self.args.format == "zip":
            with zipfile.ZipFile(self.archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
                for path in self.temp_dir.rglob("*"):
                    if path.is_file():
                        archive.write(path, path.relative_to(self.temp_dir))
        else:
            with tarfile.open(self.archive_path, "w:gz") as archive:
                archive.add(self.temp_dir, arcname="")
        digest = self._sha256_file(self.archive_path)
        self.archive_path.with_suffix(self.archive_path.suffix + ".sha256").write_text(
            f"{digest}  {self.archive_path.name}\n", encoding="utf-8"
        )

    def encrypt_archive(self) -> None:
        if not self.args.encrypt:
            return
        if not self._command_exists("openssl"):
            raise RuntimeError("OpenSSL is not available; archive was left unencrypted")
        if self.args.non_interactive:
            raise RuntimeError("Encryption requires an interactive password prompt")
        password = getpass.getpass("Encryption password: ")
        if not password or password != getpass.getpass("Confirm encryption password: "):
            raise RuntimeError("Encryption passwords did not match or were empty")
        encrypted = Path(str(self.archive_path) + ".enc")
        result = subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-salt", "-pbkdf2", "-in", str(self.archive_path), "-out", str(encrypted), "-pass", "stdin"],
            input=password + "\n",
            text=True,
            capture_output=True,
            timeout=self.args.command_timeout,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"OpenSSL encryption failed: {result.stderr.strip()}")
        unencrypted_checksum = self.archive_path.with_suffix(self.archive_path.suffix + ".sha256")
        self.archive_path.unlink()
        unencrypted_checksum.unlink(missing_ok=True)
        self.archive_path = encrypted
        digest = self._sha256_file(self.archive_path)
        Path(str(self.archive_path) + ".sha256").write_text(f"{digest}  {self.archive_path.name}\n", encoding="utf-8")

    @staticmethod
    def _sha256_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def collect_all(self) -> Path:
        LOGGER.info("Starting Linux forensic collection version %s", VERSION)
        if not self.metadata["is_root"]:
            LOGGER.warning("Not running as root; some artifacts will be unavailable")
        try:
            self.collect_volatile_state()
            self.collect_system_identity()
            self.collect_logs()
            self.collect_accounts_and_access()
            self.collect_persistence()
            self.collect_network_configuration()
            self.collect_package_inventory()
            self.collect_file_indicators()
            self.hash_artifacts()
            self.write_metadata()
            self.create_archive()
            self.encrypt_archive()
            if not self.args.keep_staging:
                shutil.rmtree(self.temp_dir)
            LOGGER.info("Collection complete: %s", self.archive_path)
            return self.archive_path
        except Exception:
            LOGGER.exception("Collection failed")
            raise


def parse_arguments(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Dependency-free Linux live-response forensic artifact collector")
    parser.add_argument("--output-dir", help="Directory for the collection output")
    parser.add_argument("--format", choices=("zip", "tar.gz"), default="zip", help="Archive format")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt the archive with locally available OpenSSL")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--silent", action="store_true", help="Suppress console output")
    parser.add_argument("--non-interactive", action="store_true", help="Never prompt for input")
    parser.add_argument("--scan-files", action="store_true", help="Run optional bounded filesystem indicator searches")
    parser.add_argument("--command-timeout", type=int, default=DEFAULT_COMMAND_TIMEOUT, help="Command timeout in seconds")
    parser.add_argument("--scan-timeout", type=int, default=300, help="Filesystem scan timeout in seconds")
    parser.add_argument("--keep-staging", action="store_true", help="Keep unarchived staging artifacts")
    return parser.parse_args(argv)


def main() -> int:
    args = parse_arguments()
    if args.encrypt and (args.non_interactive or args.silent):
        print("Error: --encrypt cannot be combined with --non-interactive or --silent", file=sys.stderr)
        return 2
    collector = ForensicCollector(args)
    try:
        archive = collector.collect_all()
    except Exception as exc:
        if not args.silent:
            print(f"Collection failed: {exc}", file=sys.stderr)
        return 1
    if not args.silent:
        print(f"Collection completed: {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

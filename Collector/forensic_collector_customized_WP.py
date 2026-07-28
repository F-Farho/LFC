#!/usr/bin/env python3
"""Linux forensic collector with WordPress, web server, scheduler, and temp-file coverage.

The collector captures volatile state, persistence, logs, WordPress/web artifacts,
active cron tables, systemd timers, other common scheduler sources, and a bounded
inventory of /tmp, /var/tmp, and /dev/shm. Suspicious or scheduler-referenced temp
files are copied by default; complete temp collection is available explicitly.
"""

from __future__ import annotations

import argparse
import fnmatch
import getpass
import hashlib
import json
import logging
import os
import platform
import pwd
import re
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

VERSION = "3.2.0"

DEFAULT_COMMAND_TIMEOUT = 60
DEFAULT_TEMP_MAX_FILE_SIZE_MB = 25
DEFAULT_TEMP_MAX_TOTAL_SIZE_MB = 250
DEFAULT_TEMP_MAX_FILES = 500
DEFAULT_TEMP_RECENT_HOURS = 72

LOGGER = logging.getLogger("forensic_collector")

WEBROOT_SEARCH_BASES = [
    "/var/www",
    "/srv/www",
    "/srv/http",
    "/usr/share/nginx/html",
    "/var/html",
    "/opt/bitnami/wordpress",
    "/home",
]

WEBROOT_MAX_DEPTH = 6

MALWARE_FILENAME_PATTERNS = [
    re.compile(r"class-walker_[0-9a-f]{8}\.php$"),
    re.compile(r"class-wp-compat_[0-9a-f]{8}\.php$"),
    re.compile(r"[a-z0-9\-]+_[0-9a-f]{8}\.php$"),
]

SUSPICIOUS_TEMP_EXTENSIONS = {
    ".bash", ".bin", ".cgi", ".elf", ".exe", ".js", ".lua", ".out",
    ".php", ".php3", ".php4", ".php5", ".php7", ".php8", ".phtml",
    ".pl", ".pm", ".ps1", ".py", ".rb", ".sh", ".so", ".war",
}

WEB_SERVICE_USERS = {"apache", "caddy", "httpd", "lighttpd", "nginx", "nobody", "www-data"}
TEMP_ROOTS = (Path("/tmp"), Path("/var/tmp"), Path("/dev/shm"))

# Captures absolute temporary paths and simple glob expressions in scheduler definitions.
TEMP_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_])(/(?:tmp|var/tmp|dev/shm)/(?:\\.|[^\s\"'`;|&<>])+)",
    re.MULTILINE,
)

KNOWN_ACCESS_LOG_PATHS = [
    "/var/log/apache2/access.log",
    "/var/log/apache2/other_vhosts_access.log",
    "/var/log/httpd/access_log",
    "/var/log/httpd/access.log",
    "/var/log/nginx/access.log",
    "/var/log/lighttpd/access.log",
    "/var/log/caddy/access.log",
    "/var/log/openlitespeed/access.log",
]

KNOWN_ERROR_LOG_PATHS = [
    "/var/log/apache2/error.log",
    "/var/log/httpd/error_log",
    "/var/log/nginx/error.log",
    "/var/log/lighttpd/error.log",
]

APACHE_CONF_DIRS = [
    "/etc/apache2/sites-enabled",
    "/etc/apache2/conf-enabled",
    "/etc/httpd/conf.d",
    "/etc/httpd/conf/httpd.conf",
]

NGINX_CONF_DIRS = [
    "/etc/nginx/sites-enabled",
    "/etc/nginx/conf.d",
    "/etc/nginx/nginx.conf",
]

LITESPEED_CONF_DIRS = [
    "/usr/local/lsws/conf/vhosts",
    "/etc/litespeed",
]

CRON_AND_SCHEDULER_SOURCES = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.monthly",
    "/etc/cron.weekly",
    "/etc/periodic",
    "/etc/anacrontab",
    "/etc/fcron.conf",
    "/etc/fcron.d",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
    "/var/spool/fcron",
    "/var/spool/fcron3",
    "/var/spool/at",
    "/var/spool/atjobs",
    "/var/spool/cron/atjobs",
    "/var/spool/batch",
]

SYSTEMD_SYSTEM_SOURCES = [
    "/etc/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
    "/run/systemd/system",
    "/run/systemd/transient",
    "/run/systemd/generator",
    "/run/systemd/generator.early",
    "/run/systemd/generator.late",
]

SYSTEMD_USER_SOURCES = [
    "/etc/systemd/user",
    "/usr/lib/systemd/user",
    "/lib/systemd/user",
    "/var/lib/systemd/linger",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ForensicCollector:
    """Collect practical volatile and persistent Linux forensic artifacts."""

    CAPABILITY_COMMANDS = (
        "ps", "ss", "netstat", "lsof", "who", "w", "last", "lastb",
        "journalctl", "dmesg", "systemctl", "crontab", "atq", "lsmod", "ip",
        "findmnt", "lsblk", "iptables", "ip6tables", "nft", "ufw",
        "firewall-cmd", "dpkg-query", "rpm", "pacman", "openssl", "find", "wp",
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
        self.scheduled_temp_references: set[str] = set()
        self.metadata: dict = {
            "schema_version": "1.1",
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
            "scheduler_artifacts": {
                "active_crontabs_queried": [],
                "temp_references": [],
                "wordpress_cron_queries": [],
            },
            "temporary_artifacts": {
                "roots": [str(path) for path in TEMP_ROOTS],
                "inventory_entries": 0,
                "files_collected": 0,
                "bytes_collected": 0,
                "skipped_by_size": 0,
                "skipped_by_limit": 0,
                "errors": 0,
            },
            "web_artifacts": {
                "wordpress_installs": [],
                "malware_files_found": [],
                "access_logs_collected": [],
                "error_logs_collected": [],
            },
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

    def save_command(
        self,
        command: list[str],
        relative_path: str,
        timeout: int | None = None,
        acceptable_codes: tuple[int, ...] = (0,),
    ) -> bool:
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
            success = result.returncode in acceptable_codes
            self._record(
                relative_path,
                "command",
                success,
                command=command,
                return_code=result.returncode,
                duration_seconds=round(time.monotonic() - started, 3),
                stderr_file=(relative_path + ".stderr") if result.stderr else None,
            )
            return success
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            destination.write_text(stdout, encoding="utf-8", errors="replace")
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
        try:
            for root, directories, files in os.walk(source_path, followlinks=False):
                directories[:] = [name for name in directories if not (Path(root) / name).is_symlink()]
                for filename in files:
                    path = Path(root) / filename
                    destination = Path(relative_path) / path.relative_to(source_path)
                    copied += int(self.copy_file(path, str(destination)))
        except OSError as exc:
            self._record(relative_path, "directory", False, original_path=str(source_path), error=str(exc))
        return copied

    def copy_existing(self, sources: Iterable[str], relative_directory: str) -> None:
        for source in sources:
            path = Path(source)
            destination = str(Path(relative_directory) / self._safe_dir_label(path))
            if path.is_dir():
                self.copy_directory(path, destination)
            elif path.exists() or path.is_symlink():
                self.copy_file(path, destination)

    def save_text(self, relative_path: str, content: str, source: str = "python") -> None:
        self._destination(relative_path).write_text(content, encoding="utf-8", errors="replace")
        self._record(relative_path, source, True)

    @staticmethod
    def _safe_dir_label(path: Path) -> str:
        label = str(path).lstrip("/").replace("/", "_")
        return label or "root"

    @staticmethod
    def _is_within(path: Path, parent: Path) -> bool:
        try:
            path.resolve(strict=False).relative_to(parent.resolve(strict=False))
            return True
        except ValueError:
            return False

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
        process_data = []
        descriptor_data = []
        scheduler_processes = []
        try:
            proc_entries = list(Path("/proc").iterdir())
        except OSError as exc:
            self._record("volatile/proc_processes.json", "proc", False, error=str(exc))
            return

        for entry in proc_entries:
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

            process_text = f"{record.get('comm', '')} {record.get('cmdline', '')}".lower()
            if any(name in process_text for name in ("cron", "crond", "anacron", "fcron", "atd")):
                scheduler_processes.append(record)
                scheduler_cmdline = record.get("cmdline", "")
                self._extract_temp_references(scheduler_cmdline, f"/proc/{entry.name}/cmdline")
                # crond commonly accepts a cron directory with -c. If that directory is
                # itself a temp root, prioritize all files below it within collection limits.
                for temp_root in ("/tmp", "/var/tmp", "/dev/shm"):
                    if re.search(rf"(?:^|\s)-c(?:=|\s+){re.escape(temp_root)}(?:\s|$)", scheduler_cmdline):
                        self.scheduled_temp_references.add(temp_root + "/*")

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
        self.save_text("persistence/scheduler_processes.json", json.dumps(scheduler_processes, indent=2))

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
            "/var/log/cron", "/var/log/cron.log",
        ]
        self.copy_existing(log_files, "logs")
        if Path("/var/log/audit").exists():
            self.copy_directory("/var/log/audit", "logs/audit_log")
        if Path("/etc/audit").exists():
            self.copy_directory("/etc/audit", "logs/audit_configuration")
        if self._command_exists("journalctl"):
            self.save_command(["journalctl", "--no-pager", "-o", "short-iso", "-b"], "logs/journal_current_boot.log", timeout=180)
            self.save_command(["journalctl", "--no-pager", "-o", "short-iso", "-b", "-1"], "logs/journal_previous_boot.log", timeout=180, acceptable_codes=(0, 1))
            self.save_command(["journalctl", "--no-pager", "-o", "short-iso", "-u", "cron", "-u", "crond", "-u", "anacron", "-u", "fcron", "-u", "atd"], "logs/schedulers_journal.log", timeout=180, acceptable_codes=(0, 1))
        self.save_command(["last", "-n", "200"], "logs/last_logins.txt")
        self.save_command(["lastb", "-n", "200"], "logs/failed_logins.txt", acceptable_codes=(0, 1))

    def collect_accounts_and_access(self) -> None:
        LOGGER.info("Collecting accounts, privileges, SSH access, and shell history")
        self.copy_existing(
            ["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/login.defs", "/etc/security", "/etc/sudoers.d", "/etc/ssh/sshd_config", "/etc/ssh/sshd_config.d", "/etc/ssh/ssh_config", "/etc/ssh/ssh_config.d"],
            "accounts",
        )
        for user_name, home in self._iter_user_homes():
            if not home.exists() or not home.is_dir():
                continue
            for filename in (".bash_history", ".zsh_history", ".python_history", ".lesshst", ".viminfo"):
                path = home / filename
                if path.exists():
                    self.copy_file(path, f"accounts/history/{user_name}_{filename.lstrip('.')}")
            ssh_directory = home / ".ssh"
            for filename in ("authorized_keys", "authorized_keys2", "known_hosts", "config"):
                path = ssh_directory / filename
                if path.exists():
                    self.copy_file(path, f"accounts/users/{user_name}/ssh/{filename}")
            autostart = home / ".config/autostart"
            if autostart.exists():
                self.copy_directory(autostart, f"accounts/users/{user_name}/autostart")

    @staticmethod
    def _iter_user_homes() -> list[tuple[str, Path]]:
        users: list[tuple[str, Path]] = []
        seen: set[tuple[str, str]] = set()
        try:
            for account in pwd.getpwall():
                if not account.pw_dir or account.pw_dir == "/":
                    continue
                item = (account.pw_name, account.pw_dir)
                if item not in seen:
                    seen.add(item)
                    users.append((account.pw_name, Path(account.pw_dir)))
        except Exception:
            pass
        return users

    def _extract_temp_references(self, content: str, source: str) -> None:
        for match in TEMP_PATH_RE.finditer(content):
            candidate = match.group(1).replace("\\ ", " ").rstrip(")]}:,.")
            if candidate:
                self.scheduled_temp_references.add(candidate)
                LOGGER.debug("Scheduled temp reference from %s: %s", source, candidate)

    def _scan_scheduler_source(self, source: Path) -> None:
        if source.is_symlink():
            try:
                self._extract_temp_references(os.readlink(source), str(source))
            except OSError:
                return
            return
        if not source.is_file():
            return
        try:
            if source.stat().st_size > 10 * 1024 * 1024:
                return
            content = source.read_text(encoding="utf-8", errors="replace")
            self._extract_temp_references(content, str(source))
        except OSError:
            pass

    def _scan_scheduler_tree(self, source: Path) -> None:
        if source.is_file() or source.is_symlink():
            self._scan_scheduler_source(source)
            return
        if not source.is_dir():
            return
        try:
            for root, directories, files in os.walk(source, followlinks=False):
                directories[:] = [name for name in directories if not (Path(root) / name).is_symlink()]
                for filename in files:
                    self._scan_scheduler_source(Path(root) / filename)
        except OSError:
            pass

    def _collect_active_crontabs(self) -> None:
        if not self._command_exists("crontab"):
            return

        users: list[str]
        if os.geteuid() == 0:
            users = sorted({account.pw_name for account in pwd.getpwall()})
        else:
            users = [pwd.getpwuid(os.geteuid()).pw_name]

        for user in users:
            safe_user = re.sub(r"[^A-Za-z0-9_.-]", "_", user)
            relative_path = f"persistence/cron/active_crontabs/{safe_user}.txt"
            command = ["crontab", "-l", "-u", user] if os.geteuid() == 0 else ["crontab", "-l"]
            success = self.save_command(command, relative_path, acceptable_codes=(0, 1))
            artifact_path = self.temp_dir / relative_path
            content = ""
            try:
                content = artifact_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
            self._extract_temp_references(content, f"crontab:{user}")
            self.metadata["scheduler_artifacts"]["active_crontabs_queried"].append(
                {"user": user, "collected": success, "has_entries": bool(content.strip())}
            )

    def _collect_user_systemd_sources(self) -> None:
        for user_name, home in self._iter_user_homes():
            for relative in (Path(".config/systemd/user"), Path(".local/share/systemd/user")):
                source = home / relative
                if source.exists():
                    destination = f"persistence/systemd_users/{user_name}/{str(relative).replace('/', '_').lstrip('.')}"
                    self.copy_directory(source, destination)
                    self._scan_scheduler_tree(source)

    def collect_persistence(self) -> None:
        LOGGER.info("Collecting cron jobs, timers, services, and startup configuration")

        for source_text in CRON_AND_SCHEDULER_SOURCES:
            source = Path(source_text)
            if not source.exists() and not source.is_symlink():
                continue
            destination = f"persistence/schedulers/{self._safe_dir_label(source)}"
            if source.is_dir():
                self.copy_directory(source, destination)
            else:
                self.copy_file(source, destination)
            self._scan_scheduler_tree(source)

        self._collect_active_crontabs()

        for source_text in SYSTEMD_SYSTEM_SOURCES:
            source = Path(source_text)
            if source.exists():
                self.copy_directory(source, f"persistence/systemd_system/{self._safe_dir_label(source)}")
                self._scan_scheduler_tree(source)

        for source_text in SYSTEMD_USER_SOURCES:
            source = Path(source_text)
            if source.exists():
                if source.is_dir():
                    self.copy_directory(source, f"persistence/systemd_user_global/{self._safe_dir_label(source)}")
                else:
                    self.copy_file(source, f"persistence/systemd_user_global/{self._safe_dir_label(source)}")
                self._scan_scheduler_tree(source)

        self._collect_user_systemd_sources()

        self.copy_existing(
            ["/etc/init.d", "/etc/rc.local", "/etc/profile", "/etc/profile.d", "/etc/rc.d", "/etc/inittab"],
            "persistence/startup",
        )

        if self._command_exists("systemctl"):
            self.save_command(["systemctl", "list-units", "--all", "--no-pager"], "persistence/systemd_units.txt")
            self.save_command(["systemctl", "list-unit-files", "--no-pager"], "persistence/systemd_unit_files.txt")
            self.save_command(["systemctl", "list-timers", "--all", "--no-pager"], "persistence/systemd_timers.txt")

        if self._command_exists("atq"):
            self.save_command(["atq"], "persistence/at_queue.txt", acceptable_codes=(0, 1))

        self.metadata["scheduler_artifacts"]["temp_references"] = sorted(self.scheduled_temp_references)
        self.save_text(
            "persistence/scheduled_temp_references.json",
            json.dumps(sorted(self.scheduled_temp_references), indent=2),
        )

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

    @staticmethod
    def _file_sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    def _read_file_signature(path: Path) -> tuple[str | None, bool]:
        try:
            with path.open("rb") as handle:
                data = handle.read(4096)
        except OSError:
            return None, False

        if data.startswith(b"\x7fELF"):
            return "ELF", True
        if data.startswith(b"#!"):
            first_line = data.splitlines()[0].decode("utf-8", errors="replace")
            return first_line, True
        lowered = data.lower()
        if b"<?php" in lowered:
            return "PHP", True
        if b"powershell" in lowered or b"frombase64string" in lowered:
            return "script-content", True
        return None, False

    def _path_matches_scheduled_reference(self, path: Path) -> bool:
        path_text = str(path)
        for reference in self.scheduled_temp_references:
            if any(character in reference for character in "*?["):
                if fnmatch.fnmatch(path_text, reference):
                    return True
            elif path_text == reference:
                return True
        return False

    def _temp_collection_reasons(self, path: Path, file_stat: os.stat_result) -> tuple[list[str], str | None]:
        reasons: list[str] = []
        if self.args.collect_all_temp:
            reasons.append("collect-all-temp")
        if self._path_matches_scheduled_reference(path):
            reasons.append("scheduled-reference")
        if file_stat.st_mode & 0o111:
            reasons.append("executable")
        if path.suffix.lower() in SUSPICIOUS_TEMP_EXTENSIONS:
            reasons.append("script-or-binary-extension")

        signature, signature_suspicious = self._read_file_signature(path)
        if signature_suspicious:
            reasons.append("executable-or-script-signature")

        age_seconds = max(0.0, time.time() - file_stat.st_mtime)
        recent = age_seconds <= self.args.temp_recent_hours * 3600
        if path.name.startswith(".") and recent:
            reasons.append("recent-hidden-file")

        try:
            owner = pwd.getpwuid(file_stat.st_uid).pw_name
        except KeyError:
            owner = str(file_stat.st_uid)
        if owner in WEB_SERVICE_USERS and recent:
            reasons.append("recent-web-service-owned")

        return sorted(set(reasons)), signature

    def _temp_destination(self, source: Path) -> str:
        root_label = "unknown"
        relative = Path(source.name)
        for root in TEMP_ROOTS:
            try:
                relative = source.relative_to(root)
                root_label = self._safe_dir_label(root)
                break
            except ValueError:
                continue
        return str(Path("temporary/content") / root_label / relative)

    def collect_temporary_artifacts(self) -> None:
        LOGGER.info("Inventorying temporary directories and collecting bounded suspicious content")
        inventory: list[dict] = []
        collected_files = 0
        collected_bytes = 0
        max_file_bytes = self.args.temp_max_file_size_mb * 1024 * 1024
        max_total_bytes = self.args.temp_max_total_size_mb * 1024 * 1024

        for temp_root in TEMP_ROOTS:
            if not temp_root.exists() or not temp_root.is_dir():
                continue
            try:
                for root, directories, files in os.walk(temp_root, followlinks=False):
                    root_path = Path(root)
                    directories[:] = [
                        name for name in directories
                        if not (root_path / name).is_symlink()
                        and not self._is_within(root_path / name, self.output_dir)
                    ]
                    for filename in files:
                        path = root_path / filename
                        if self._is_within(path, self.output_dir):
                            continue
                        entry: dict = {"path": str(path), "root": str(temp_root)}
                        try:
                            file_stat = path.lstat()
                            entry.update(
                                {
                                    "type": "symlink" if path.is_symlink() else "regular" if stat.S_ISREG(file_stat.st_mode) else "special",
                                    "size": file_stat.st_size,
                                    "mode": stat.filemode(file_stat.st_mode),
                                    "uid": file_stat.st_uid,
                                    "gid": file_stat.st_gid,
                                    "atime_ns": file_stat.st_atime_ns,
                                    "mtime_ns": file_stat.st_mtime_ns,
                                    "ctime_ns": file_stat.st_ctime_ns,
                                }
                            )
                            try:
                                entry["owner"] = pwd.getpwuid(file_stat.st_uid).pw_name
                            except KeyError:
                                entry["owner"] = None

                            if path.is_symlink():
                                entry["symlink_target"] = os.readlink(path)
                                entry["scheduled_reference"] = self._path_matches_scheduled_reference(path)
                                inventory.append(entry)
                                continue
                            if not stat.S_ISREG(file_stat.st_mode):
                                inventory.append(entry)
                                continue

                            reasons, signature = self._temp_collection_reasons(path, file_stat)
                            entry["signature"] = signature
                            entry["collection_reasons"] = reasons
                            entry["scheduled_reference"] = "scheduled-reference" in reasons

                            if file_stat.st_size <= max_file_bytes:
                                try:
                                    entry["sha256"] = self._file_sha256(path)
                                except OSError as exc:
                                    entry["hash_error"] = str(exc)

                            should_collect = bool(reasons) and not self.args.no_temp_content
                            if should_collect and file_stat.st_size > max_file_bytes:
                                entry["collection_status"] = "skipped-file-size-limit"
                                self.metadata["temporary_artifacts"]["skipped_by_size"] += 1
                            elif should_collect and (
                                collected_files >= self.args.temp_max_files
                                or collected_bytes + file_stat.st_size > max_total_bytes
                            ):
                                entry["collection_status"] = "skipped-total-limit"
                                self.metadata["temporary_artifacts"]["skipped_by_limit"] += 1
                            elif should_collect:
                                destination = self._temp_destination(path)
                                if self.copy_file(path, destination):
                                    entry["collection_status"] = "collected"
                                    entry["collected_path"] = destination
                                    collected_files += 1
                                    collected_bytes += file_stat.st_size
                                else:
                                    entry["collection_status"] = "collection-failed"
                            else:
                                entry["collection_status"] = "inventory-only"
                        except OSError as exc:
                            entry["error"] = str(exc)
                            self.metadata["temporary_artifacts"]["errors"] += 1
                        inventory.append(entry)
            except OSError as exc:
                inventory.append({"path": str(temp_root), "error": str(exc)})
                self.metadata["temporary_artifacts"]["errors"] += 1

        self.metadata["temporary_artifacts"].update(
            {
                "inventory_entries": len(inventory),
                "files_collected": collected_files,
                "bytes_collected": collected_bytes,
                "content_mode": "disabled" if self.args.no_temp_content else "all" if self.args.collect_all_temp else "selective",
                "max_file_size_mb": self.args.temp_max_file_size_mb,
                "max_total_size_mb": self.args.temp_max_total_size_mb,
                "max_files": self.args.temp_max_files,
                "recent_hours": self.args.temp_recent_hours,
            }
        )
        self.save_text("temporary/inventory.json", json.dumps(inventory, indent=2))
        self.save_text("temporary/summary.json", json.dumps(self.metadata["temporary_artifacts"], indent=2))

    def collect_file_indicators(self) -> None:
        if not self.args.scan_files:
            return
        LOGGER.info("Collecting optional filesystem indicators")
        if not self._command_exists("find"):
            self._record("file_indicators", "command", False, error="find is unavailable")
            return
        commands = [
            (["find", "/", "-xdev", "-type", "f", "(", "-perm", "-4000", "-o", "-perm", "-2000", ")", "-ls"], "file_indicators/suid_sgid.txt"),
            (["find", "/", "-xdev", "(", "-nouser", "-o", "-nogroup", ")", "-ls"], "file_indicators/unowned.txt"),
        ]
        for command, path in commands:
            self.save_command(command, path, timeout=self.args.scan_timeout)

    def _discover_wordpress_installs(self) -> list[Path]:
        """Walk known webroot bases to find WordPress installations."""
        found_roots: list[Path] = []
        seen: set[Path] = set()

        for base_text in WEBROOT_SEARCH_BASES:
            base = Path(base_text)
            if not base.exists() or not base.is_dir():
                continue
            try:
                for root, directories, _files in os.walk(base, followlinks=False):
                    root_path = Path(root)
                    depth = len(root_path.relative_to(base).parts)
                    if depth > WEBROOT_MAX_DEPTH:
                        directories.clear()
                        continue
                    directories[:] = [name for name in directories if not (root_path / name).is_symlink()]
                    if (root_path / "wp-includes" / "assets").is_dir():
                        resolved = root_path.resolve()
                        if resolved not in seen:
                            seen.add(resolved)
                            found_roots.append(root_path)
                            LOGGER.info("WordPress install found: %s", root_path)
                        directories.clear()
            except (OSError, PermissionError):
                continue

        return found_roots

    def _is_malware_filename(self, filename: str) -> bool:
        return any(pattern.match(filename) for pattern in MALWARE_FILENAME_PATTERNS)

    def _scan_for_malware_files(self, wp_root: Path) -> list[Path]:
        matched: list[Path] = []
        try:
            for root, directories, files in os.walk(wp_root, followlinks=False):
                directories[:] = [name for name in directories if not (Path(root) / name).is_symlink()]
                for filename in files:
                    if self._is_malware_filename(filename):
                        matched.append(Path(root) / filename)
        except (OSError, PermissionError):
            pass
        return matched

    def _discover_web_logs(self) -> list[Path]:
        candidates: list[Path] = [Path(path) for path in KNOWN_ACCESS_LOG_PATHS + KNOWN_ERROR_LOG_PATHS]
        log_path_re = re.compile(
            r"(?:access_?log|error_?log|CustomLog|ErrorLog)\s+[\"']?([/][^\s\"']+)",
            re.IGNORECASE,
        )

        for source_text in APACHE_CONF_DIRS + NGINX_CONF_DIRS + LITESPEED_CONF_DIRS:
            source = Path(source_text)
            if not source.exists():
                continue
            files_to_read: list[Path] = []
            if source.is_file():
                files_to_read.append(source)
            elif source.is_dir():
                try:
                    files_to_read.extend(
                        path for path in source.rglob("*")
                        if path.is_file() and path.suffix in (".conf", ".cfg", "")
                    )
                except (OSError, PermissionError):
                    continue
            for config_file in files_to_read:
                try:
                    content = config_file.read_text(encoding="utf-8", errors="replace")
                    for match in log_path_re.finditer(content):
                        candidates.append(Path(match.group(1)))
                except (OSError, PermissionError):
                    continue

        seen: set[Path] = set()
        result: list[Path] = []
        for candidate in candidates:
            if candidate.is_file() and candidate not in seen:
                seen.add(candidate)
                result.append(candidate)
        return result

    def _collect_wordpress_cron(self, wp_root: Path, label: str) -> dict:
        record = {"path": str(wp_root), "attempted": False, "collected": False}
        if not self._command_exists("wp"):
            record["reason"] = "wp-cli-unavailable"
            return record

        relative_path = f"web/wordpress/{label}/wp_cron_events.json"
        command = [
            "wp", "cron", "event", "list",
            "--fields=hook,next_run_gmt,next_run_relative,recurrence",
            "--format=json",
            f"--path={wp_root}",
        ]
        if os.geteuid() == 0:
            command.append("--allow-root")
        record["attempted"] = True
        record["collected"] = self.save_command(command, relative_path, timeout=120)
        try:
            content = (self.temp_dir / relative_path).read_text(encoding="utf-8", errors="replace")
            self._extract_temp_references(content, f"wordpress-cron:{wp_root}")
        except OSError:
            pass
        return record

    def collect_web_artifacts(self) -> None:
        LOGGER.info("Collecting WordPress and web server artifacts")
        wp_installs = self._discover_wordpress_installs()

        if not wp_installs:
            self.save_text(
                "web/wordpress_discovery.txt",
                "No WordPress installs found in search bases:\n" + "\n".join(WEBROOT_SEARCH_BASES) + "\n",
            )
        else:
            for wp_root in wp_installs:
                label = self._safe_dir_label(wp_root)
                install_record = {
                    "path": str(wp_root),
                    "assets_dir": str(wp_root / "wp-includes" / "assets"),
                    "malware_files": [],
                }

                assets_dir = wp_root / "wp-includes" / "assets"
                if assets_dir.is_dir():
                    copied = self.copy_directory(assets_dir, f"web/wordpress/{label}/wp-includes/assets")
                    LOGGER.info("Copied %d files from %s", copied, assets_dir)

                malware_files = self._scan_for_malware_files(wp_root)
                for malware_path in malware_files:
                    LOGGER.warning("Malware filename pattern matched: %s", malware_path)
                    try:
                        relative_to_wp = malware_path.relative_to(wp_root)
                    except ValueError:
                        relative_to_wp = Path(malware_path.name)
                    destination = str(Path(f"web/wordpress/{label}/malware_files") / relative_to_wp)
                    self.copy_file(malware_path, destination)
                    install_record["malware_files"].append(str(malware_path))
                    self.metadata["web_artifacts"]["malware_files_found"].append(str(malware_path))

                wp_cron_record = self._collect_wordpress_cron(wp_root, label)
                install_record["wp_cron"] = wp_cron_record
                self.metadata["scheduler_artifacts"]["wordpress_cron_queries"].append(wp_cron_record)
                self.metadata["web_artifacts"]["wordpress_installs"].append(install_record)

            self.save_text(
                "web/wordpress_discovery.json",
                json.dumps([{"path": str(path), "assets": str(path / "wp-includes" / "assets")} for path in wp_installs], indent=2),
            )

        malware_summary_lines = ["Malware filename scan summary", "=" * 40]
        if self.metadata["web_artifacts"]["malware_files_found"]:
            malware_summary_lines.append(f"FOUND {len(self.metadata['web_artifacts']['malware_files_found'])} file(s):")
            malware_summary_lines.extend(self.metadata["web_artifacts"]["malware_files_found"])
        else:
            malware_summary_lines.append("No malware-pattern files found.")
        self.save_text("web/malware_files_summary.txt", "\n".join(malware_summary_lines) + "\n")

        log_paths = self._discover_web_logs()
        if not log_paths:
            self.save_text("web/logs/no_logs_found.txt", "No web server access or error logs found.\n")
        else:
            for log_path in log_paths:
                label = self._safe_dir_label(log_path)
                destination = f"web/logs/{label}"
                success = self.copy_file(log_path, destination)
                entry = {"path": str(log_path), "collected": success}
                if "error" in log_path.name.lower() or "error" in str(log_path).lower():
                    self.metadata["web_artifacts"]["error_logs_collected"].append(entry)
                else:
                    self.metadata["web_artifacts"]["access_logs_collected"].append(entry)

        self.metadata["scheduler_artifacts"]["temp_references"] = sorted(self.scheduled_temp_references)
        self.save_text("web/web_artifacts_summary.json", json.dumps(self.metadata["web_artifacts"], indent=2))

    def hash_artifacts(self) -> None:
        LOGGER.info("Hashing collected artifacts")
        hashes = {}
        for path in self.temp_dir.rglob("*"):
            if not path.is_file():
                continue
            try:
                hashes[str(path.relative_to(self.temp_dir))] = self._file_sha256(path)
            except OSError as exc:
                self.metadata["errors"].append({"path": str(path), "source": "hash", "success": False, "error": str(exc)})
        self.metadata["sha256"] = hashes

    def write_metadata(self) -> None:
        self.metadata["collection_finished_utc"] = utc_now()
        self.metadata["scheduler_artifacts"]["temp_references"] = sorted(self.scheduled_temp_references)
        self.metadata["summary"] = {
            "successful_artifacts": sum(1 for item in self.metadata["artifacts"] if item["success"]),
            "failed_artifacts": sum(1 for item in self.metadata["artifacts"] if not item["success"]),
            "wordpress_installs_found": len(self.metadata["web_artifacts"]["wordpress_installs"]),
            "malware_files_found": len(self.metadata["web_artifacts"]["malware_files_found"]),
            "access_logs_collected": len(self.metadata["web_artifacts"]["access_logs_collected"]),
            "scheduled_temp_references": len(self.scheduled_temp_references),
            "temporary_files_collected": self.metadata["temporary_artifacts"]["files_collected"],
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
            f"{digest} {self.archive_path.name}\n", encoding="utf-8"
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
        Path(str(self.archive_path) + ".sha256").write_text(f"{digest} {self.archive_path.name}\n", encoding="utf-8")

    @staticmethod
    def _sha256_file(path: Path) -> str:
        return ForensicCollector._file_sha256(path)

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
            self.collect_web_artifacts()
            # Run after persistence and WordPress cron discovery so referenced temp files are prioritized.
            self.collect_temporary_artifacts()
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
    parser = argparse.ArgumentParser(
        description="Dependency-free Linux live-response forensic collector with WordPress, scheduler, and bounded temp-file support"
    )
    parser.add_argument("--output-dir", help="Directory for collection output")
    parser.add_argument("--format", choices=("zip", "tar.gz"), default="zip", help="Archive format")
    parser.add_argument("--encrypt", action="store_true", help="Encrypt the archive with locally available OpenSSL")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--silent", action="store_true", help="Suppress console output")
    parser.add_argument("--non-interactive", action="store_true", help="Never prompt for input")
    parser.add_argument("--scan-files", action="store_true", help="Run optional filesystem-wide SUID/SGID and ownership searches")
    parser.add_argument("--command-timeout", type=int, default=DEFAULT_COMMAND_TIMEOUT, help="Command timeout in seconds")
    parser.add_argument("--scan-timeout", type=int, default=300, help="Filesystem scan timeout in seconds")
    parser.add_argument("--keep-staging", action="store_true", help="Keep unarchived staging artifacts")

    temp_group = parser.add_argument_group("temporary-file collection")
    temp_group.add_argument("--no-temp-content", action="store_true", help="Inventory temporary directories without copying file contents")
    temp_group.add_argument("--collect-all-temp", action="store_true", help="Copy all regular temp files within configured limits instead of suspicious files only")
    temp_group.add_argument("--temp-max-file-size-mb", type=int, default=DEFAULT_TEMP_MAX_FILE_SIZE_MB, help="Maximum size of one copied temp file")
    temp_group.add_argument("--temp-max-total-size-mb", type=int, default=DEFAULT_TEMP_MAX_TOTAL_SIZE_MB, help="Maximum total copied temp content")
    temp_group.add_argument("--temp-max-files", type=int, default=DEFAULT_TEMP_MAX_FILES, help="Maximum number of copied temp files")
    temp_group.add_argument("--temp-recent-hours", type=int, default=DEFAULT_TEMP_RECENT_HOURS, help="Recent-file window used for hidden and web-service-owned temp files")

    args = parser.parse_args(argv)
    for field in ("temp_max_file_size_mb", "temp_max_total_size_mb", "temp_max_files", "temp_recent_hours"):
        if getattr(args, field) < 0:
            parser.error(f"--{field.replace('_', '-')} must be zero or greater")
    if args.collect_all_temp and args.no_temp_content:
        parser.error("--collect-all-temp cannot be combined with --no-temp-content")
    return args


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

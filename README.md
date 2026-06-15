# Linux Forensic Collector

A lightweight Linux live-response collector that gathers volatile state, logs, account and persistence configuration, network configuration, and package inventory for later analysis.

The collector is intentionally neutral: it collects raw artifacts and does not decide whether activity is malicious. for the Analysis, there is a special tool which remains (for now) a separate, private tool.

## Design principles

- Uses Python's standard library and commands already installed on the host.
- Never downloads, installs, or removes system packages.
- Collects volatile process and network state first.
- Records unavailable commands and failed artifacts in `metadata.json`.
- Adds SHA-256 hashes for collected files and the final archive.
- Makes expensive filesystem indicator searches optional.

## Requirements

- Linux
- Python 3.9 or newer
- Root privileges are recommended for the most complete collection

## Collected artifacts :

- Collects Linux live-response forensic artifacts without installing extra packages.
- Captures volatile system state, including running processes, sessions, open files, and network sockets.
- Collects system identity and configuration data such as OS details, hostname, kernel info, mounts, disks, and boot parameters.
- Collects authentication and system logs, including journal logs, login history, failed logins, audit logs, and common /var/log files.
- Collects user and access-related artifacts such as local accounts, groups, sudo configuration, SSH configuration, authorized keys, known hosts, and shell history.
- Collects persistence artifacts, including cron jobs, systemd services, timers, startup scripts, init scripts, and user autostart entries.
- Collects network configuration, routes, neighbors, DNS settings, hosts file, firewall rules, UFW, firewalld, iptables, ip6tables, and nftables data.
- Collects installed package inventory from supported package managers such as dpkg, rpm, or pacman.
- Optionally collects bounded filesystem indicators, including SUID/SGID files, unowned files, and files from temporary directories.
- Records collection metadata, errors, command availability, artifact status, and SHA256 hashes.
- Packages the results into a ZIP or TAR.GZ archive, with optional OpenSSL encryption.

## Usage

```bash
sudo python3 collector/forensic_collector.py --output-dir /path/to/output
```

Common options:

```text
--format {zip,tar.gz}   Select archive format (default: zip)
--silent                Suppress console output
--non-interactive       Never prompt for input
--scan-files            Run optional bounded filesystem metadata searches
--command-timeout N     Set ordinary command timeout in seconds
--scan-timeout N        Set filesystem scan timeout in seconds
--keep-staging          Keep unarchived staging artifacts
--encrypt               Encrypt using an already-installed OpenSSL command
```

`--encrypt` is intentionally interactive and cannot be combined with silent or non-interactive mode. Encryption passwords are passed to OpenSSL through standard input rather than command-line arguments.

## Output

Each run creates a timestamped directory containing:

- `forensic_data.zip` or `forensic_data.tar.gz`
- A SHA-256 file for the final archive
- `forensic_collector.log`
- Optional staging artifacts when `--keep-staging` is used

The archive includes `metadata.json`, which records the collector version, host details, capabilities, collection methods, failures, and artifact hashes.

## Important limitation

This is a live-response artifact collector, not a bit-for-bit disk imaging tool. Running any live-response tool changes some system state. Test it in your environment before operational use.

## Historical approach

See [CHANGELOG.md](https://github.com/F-Farho/LFC/blob/main/ChangeLog.md)  for the previous collector approach and the changes made in the current version.

# Changelog

## 3.0.0 - Collector-focused redesign

- Established `collector/forensic_collector.py` as the single canonical collector.
- Removed automatic package installation and package removal from evidence collection.
- Added a startup capability map and graceful handling of unavailable commands.
- Changed collection order so volatile process, session, socket, and `/proc` evidence is captured first.
- Added standard-library `/proc` fallbacks for process details, open descriptors, sockets, modules, routes, memory, mounts, and system state.
- Replaced collector-side suspicious-process and suspicious-connection classification with complete raw evidence collection.
- Added safe recursive directory collection, command timeouts, clearer error records, schema/version metadata, and SHA-256 artifact hashes.
- Made bounded filesystem indicator searches optional with `--scan-files`.
- Removed automatic privilege relaunch; operators explicitly choose whether to run with `sudo`.
- Improved optional OpenSSL encryption so passwords are not placed in command-line arguments or saved beside the archive.
- Removed obsolete collector copies, historical placeholders, broken installation scripts, and unsafe test/simulation scripts from the active tree.

## Previous collector approach

### 2.1

- Added silent and non-interactive modes.
- Automatically detected and installed missing packages during collection.
- Tracked packages installed during collection and attempted to remove them afterward.
- Automatically attempted to relaunch through `sudo`.

This approach improved convenience but modified the examined system through package-manager activity. Version 3.0 removes that behavior and records missing capabilities instead.

### 2.0

- Added a root-permission check and automatic `sudo` relaunch.

### 1.5

- Expanded cross-distribution collection, error handling, archive formats, encryption, and artifact coverage.
- Identified problems with interactive execution, missing dependencies, graceful degradation, and command-line behavior.

### 1.0

- Initial proof-of-concept scripts collected basic process, network, file, and system information.

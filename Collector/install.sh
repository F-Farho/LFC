#!/bin/sh
set -eu

PREFIX="${PREFIX:-/usr/local}"
DESTINATION="$PREFIX/bin/forensic-collector"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

install -m 0755 "$SCRIPT_DIR/forensic_collector.py" "$DESTINATION"
printf 'Installed forensic-collector to %s\n' "$DESTINATION"

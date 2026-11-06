#!/bin/sh
# Cargo runner for Apple Silicon. Hypervisor.framework refuses unsigned binaries, so this
# applies an ad hoc signature with the hypervisor entitlement and then runs the binary.
binary="$1"
codesign --force --sign - --entitlements "$(dirname "$0")/hypervisor.entitlements" "$binary" >/dev/null 2>&1 || true
exec "$@"

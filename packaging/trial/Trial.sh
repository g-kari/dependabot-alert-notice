#!/bin/bash
# Trial only: no installer, service registration, stable updater, or user config.
set -euo pipefail
umask 077
if [ "$#" -gt 1 ]; then
  printf 'Use: bash Trial.sh [--version|--web-url|--start]\n' >&2
  exit 2
fi
mode="${1:---version}"
case "$mode" in
  --version|--web-url|--start) ;;
  *) printf 'Unsupported trial mode. No app was started.\n' >&2; exit 2 ;;
esac
package_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
binary="$package_dir/dependabot-alert-notice"
test -f "$binary"
trial_dir="$(mktemp -d "${TMPDIR:-/tmp}/devsecops-trial.XXXXXXXX")"
mkdir -p "$trial_dir/home/bin" "$trial_dir/home/config" "$trial_dir/home/gh" "$trial_dir/home/codex" "$trial_dir/tmp"
cp "$package_dir/trial-config.yaml" "$trial_dir/config.yaml"
cd -- "$trial_dir"
args=(--config "$trial_dir/config.yaml" --auto-update=false)
if [ "$mode" = --start ]; then
  printf 'Trial data: %s\nOffline/empty trial UI: http://127.0.0.1:18999/settings\nDo not enter credentials or enable external integrations. Stop with Ctrl+C.\n' "$trial_dir" >&2
else
  args+=("$mode")
fi
/usr/bin/env -i \
  HOME="$trial_dir/home" USERPROFILE="$trial_dir/home" \
  XDG_CONFIG_HOME="$trial_dir/home/config" GH_CONFIG_DIR="$trial_dir/home/gh" \
  CODEX_HOME="$trial_dir/home/codex" PATH="$trial_dir/home/bin" \
  TMPDIR="$trial_dir/tmp" TMP="$trial_dir/tmp" TEMP="$trial_dir/tmp" \
  SECURITY_NOTICE_AUTO_UPDATE=0 SECURITY_NOTICE_NO_BROWSER=1 \
  "$binary" "${args[@]}"
if [ "$mode" != --start ]; then
  test ! -e "$trial_dir/store.db"
fi

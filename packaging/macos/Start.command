#!/bin/bash
set -euo pipefail
umask 077

# Finder does not inherit the usual terminal PATH.
export PATH="/opt/homebrew/bin:/usr/local/bin:${HOME}/.local/bin:${PATH}"
package_dir="$(cd -- "$(dirname "$0")" && pwd)"
binary="${package_dir}/dependabot-alert-notice"
data_dir="${SECURITY_NOTICE_DATA_DIR:-${HOME}/Library/Application Support/security-notice}"
mkdir -p -- "$data_dir"
config_path="${data_dir}/config.yaml"
if [ ! -f "$config_path" ]; then
  cp -n -- "${package_dir}/config.yaml.example" "$config_path"
fi
cd -- "$data_dir"
if [ "${SECURITY_NOTICE_AUTO_UPDATE:-1}" != 0 ]; then
  printf '公開済みReleaseの更新を確認します。\n'
  if ! "$binary" --config "$config_path" --update; then
    printf '更新できなかったため、現在の版で起動します。\n'
  fi
fi
url="$("$binary" --config "$config_path" --web-url)"
printf 'Security Notice を起動します。\n設定・DB: %s\nWeb UI: %s/settings\n終了するには Ctrl+C を押してください。\n' "$data_dir" "$url"

"$binary" --config "$config_path" "$@" &
app_pid=$!
cleanup() {
  if kill -0 "$app_pid" 2>/dev/null; then
    kill -TERM "$app_pid" 2>/dev/null || true
  fi
  wait "$app_pid" 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
ready=false
for ((attempt=0; attempt<30; attempt++)); do
  if ! kill -0 "$app_pid" 2>/dev/null; then
    wait "$app_pid"
    exit 0
  fi
  if /usr/bin/curl --silent --fail --max-time 1 "${url}/settings" >/dev/null; then
    ready=true
    break
  fi
  sleep 1
done
if [ "$ready" = true ]; then
  # GUI applications require the local Aqua launchd domain. SSH sessions and
  # background services must not ask LaunchServices to open a browser.
  open_browser=false
  if [ "${SECURITY_NOTICE_NO_BROWSER:-0}" != 1 ] &&
     [ -z "${SSH_CONNECTION:-}" ] && [ -z "${SSH_CLIENT:-}" ] && [ -z "${SSH_TTY:-}" ]; then
    if launch_domain="$(/bin/launchctl managername 2>/dev/null)" && [ "$launch_domain" = Aqua ]; then
      open_browser=true
    fi
  fi
  if [ "$open_browser" = true ]; then
    /usr/bin/open "${url}/settings" || printf 'ブラウザで %s/settings を開いてください。\n' "$url"
  else
    printf 'ブラウザの自動起動を省略します。Web UI: %s/settings\n' "$url"
  fi
elif [ "$ready" != true ]; then
  printf '起動が完了していません。上のログを確認してください。URL: %s/settings\n' "$url"
fi
wait "$app_pid"

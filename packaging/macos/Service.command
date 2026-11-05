#!/bin/bash
# Executed as the chosen user, never as root. No Terminal/browser is launched.
set -euo pipefail
umask 077
if [ "$(id -u)" -eq 0 ]; then
  printf 'アプリ本体は一般ユーザー権限で起動してください。\n' >&2
  exit 1
fi
export PATH="/opt/homebrew/bin:/usr/local/bin:${HOME}/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
package_dir="$(cd -- "$(dirname "$0")" && pwd)"
data_dir="${SECURITY_NOTICE_DATA_DIR:-${HOME}/Library/Application Support/security-notice}"
mkdir -p -- "$data_dir"
chmod 700 "$data_dir"
env_file="${data_dir}/service.env.sh"
if [ -e "$env_file" ] || [ -L "$env_file" ]; then
  if [ ! -f "$env_file" ] || [ -L "$env_file" ] || [ "$(stat -f %u "$env_file")" != "$(id -u)" ] || [ "$(stat -f %Lp "$env_file")" != 600 ]; then
    printf 'service.env.sh は本人所有・権限600の通常ファイルが必要です。\n' >&2
    exit 1
  fi
  . "$env_file"
fi
if [ ! -f "${data_dir}/config.yaml" ]; then
  cp -n -- "${package_dir}/config.yaml.example" "${data_dir}/config.yaml"
fi
cd -- "$data_dir"
if [ "$(uname -m)" = arm64 ] && command -v container >/dev/null 2>&1; then
  if ! container system start --enable-kernel-install; then
    printf 'Apple containerを起動できませんでした。AI隔離評価は失敗として扱います。\n' >&2
  fi
fi
if [ "${SECURITY_NOTICE_AUTO_UPDATE:-1}" != 0 ]; then
  if ! "${package_dir}/dependabot-alert-notice" --update; then
    printf '起動前の更新に失敗したため、現在の版で起動します。\n' >&2
  fi
else
  set -- --auto-update=false "$@"
fi
exec "${package_dir}/dependabot-alert-notice" --config "${data_dir}/config.yaml" "$@"

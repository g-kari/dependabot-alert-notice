#!/bin/bash
# Update the complete package, stopping/restarting the registered daemon if present.
set -euo pipefail
umask 077
if [ "$(uname -s)" != Darwin ]; then printf 'macOS専用です。\n' >&2; exit 1; fi
package_dir="$(cd -- "$(dirname "$0")" && pwd)"
install_dir="${SECURITY_NOTICE_INSTALL_DIR:-${HOME}/Applications/security-notice}"
export SECURITY_NOTICE_INSTALL_DIR="$install_dir"
service="${package_dir}/service-macos.sh"
job=system/xyz.0g0.security-notice
restart_service=false
# Always restore the previous working service after a failed download/verification.
restore() {
  local result=$?
  trap - EXIT
  if [ "$restart_service" = true ]; then
    if ! bash "$service" start; then printf '常駐再起動に失敗しました。service-macos.sh startで確認してください。\n' >&2; result=1; fi
  fi
  exit "$result"
}
trap restore EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [ -f /Library/LaunchDaemons/xyz.0g0.security-notice.plist ]; then
  if sudo /bin/launchctl print "$job" >/dev/null 2>&1; then
    restart_service=true
    bash "$service" stop
  fi
fi
printf '手動起動中の本体はCtrl+Cで終了してから更新してください。\n'
bash "${package_dir}/Setup.command"
printf '一式更新が完了しました。\nTUI: %q --tui\n' "${install_dir}/current/dependabot-alert-notice"

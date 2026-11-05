#!/bin/bash
# Administrative commands install a system daemon; application code runs as user.
set -euo pipefail
umask 077
if [ "$(uname -s)" != Darwin ]; then
  printf 'このスクリプトはmacOS専用です。\n' >&2; exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
  printf 'sudoを付けず、利用するユーザーで実行してください。必要な操作だけsudoします。\n' >&2; exit 1
fi
export PATH="/opt/homebrew/bin:/usr/local/bin:${HOME}/.local/bin:${PATH}"
label=xyz.0g0.security-notice
plist="/Library/LaunchDaemons/${label}.plist"
job="system/${label}"
package_dir="$(cd -- "$(dirname "$0")" && pwd)"
install_dir="${SECURITY_NOTICE_INSTALL_DIR:-${HOME}/Applications/security-notice}"
# A stable current link allows whole-package updates without rewriting the daemon.
runner="${install_dir}/current/Service.command"
data_dir="${SECURITY_NOTICE_DATA_DIR:-${HOME}/Library/Application Support/security-notice}"
account="$(id -un)"
user_id="$(id -u)"
xml() { local v="$1"; v="${v//&/\&amp;}"; v="${v//</\&lt;}"; v="${v//>/\&gt;}"; v="${v//\"/\&quot;}"; printf '%s' "$v"; }
loaded() { sudo /bin/launchctl print "$job" >/dev/null 2>&1; }
case "${1:-status}" in
  install)
    if [ ! -f "$runner" ] || [ -L "$runner" ]; then
      printf '先にSetup.commandで %s/current に配布物を配置してください。\n' "$install_dir" >&2; exit 1
    fi
    mkdir -p -- "$data_dir"; chmod 700 "$data_dir"
    env_file="${data_dir}/service.env.sh"
    if [ ! -e "$env_file" ] && [ ! -L "$env_file" ]; then
      printf '# 本体の環境変数。設定後はservice-macos.sh restartで反映します。\n' > "$env_file"
      for key in GH_TOKEN GITHUB_TOKEN SECURITY_NOTICE_AUTO_UPDATE SLACK_BOT_TOKEN SLACK_APP_TOKEN DISCORD_WEBHOOK_URL ANTHROPIC_API_KEY OPENAI_API_KEY CODEX_HOME; do
        value="${!key:-}"
        if [ -n "$value" ]; then printf 'export %s=%q\n' "$key" "$value" >> "$env_file"; fi
      done
      chmod 600 "$env_file"
    fi
    if [ ! -f "$env_file" ] || [ -L "$env_file" ] || [ "$(stat -f %u "$env_file")" != "$user_id" ] || [ "$(stat -f %Lp "$env_file")" != 600 ]; then
      printf 'service.env.sh は本人所有・権限600の通常ファイルが必要です。\n' >&2; exit 1
    fi
    work="$(mktemp -d)"; trap 'rm -rf -- "$work"' EXIT
    cat > "${work}/service.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>${label}</string>
<key>ProgramArguments</key><array>
<string>/bin/launchctl</string><string>asuser</string><string>${user_id}</string>
<string>/usr/bin/sudo</string><string>-H</string><string>-u</string><string>$(xml "$account")</string>
<string>/usr/bin/env</string><string>$(xml "SECURITY_NOTICE_DATA_DIR=$data_dir")</string>
<string>/bin/bash</string><string>$(xml "$runner")</string>
</array>
<key>EnvironmentVariables</key><dict><key>SECURITY_NOTICE_DATA_DIR</key><string>$(xml "$data_dir")</string></dict>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>30</integer>
<key>ExitTimeOut</key><integer>180</integer>
<key>StandardOutPath</key><string>$(xml "${data_dir}/service.log")</string>
<key>StandardErrorPath</key><string>$(xml "${data_dir}/service.log")</string>
</dict></plist>
PLIST
    /usr/bin/plutil -lint "${work}/service.plist"
    touch "${data_dir}/service.log"; chmod 600 "${data_dir}/service.log"
    if loaded; then sudo /bin/launchctl bootout "$job"; fi
    sudo /usr/bin/install -o root -g wheel -m 644 "${work}/service.plist" "$plist"
    sudo /bin/launchctl bootstrap system "$plist"
    printf '常駐登録・起動しました。ログ: %s/service.log\n' "$data_dir"
    ;;
  start)
    if ! loaded; then sudo /bin/launchctl bootstrap system "$plist"; fi
    ;;
  stop)
    if loaded; then sudo /bin/launchctl bootout "$job"; fi
    ;;
  restart)
    if loaded; then sudo /bin/launchctl bootout "$job"; fi
    sudo /bin/launchctl bootstrap system "$plist"
    ;;
  status) sudo /bin/launchctl print "$job" ;;
  uninstall)
    if loaded; then sudo /bin/launchctl bootout "$job"; fi
    sudo /bin/rm -f -- "$plist"
    printf '常駐登録を解除しました。設定・DBは保持しました。\n'
    ;;
  *) printf '使い方: bash %q install|start|stop|restart|status|uninstall\n' "$0" >&2; exit 1 ;;
esac

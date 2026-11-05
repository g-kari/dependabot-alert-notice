#!/bin/bash
# Install a verified Mac release without compiling or replacing user data.
set -euo pipefail
umask 077

if [ "$(uname -s)" != Darwin ]; then
  printf 'このスクリプトはmacOS専用です。\n' >&2
  exit 1
fi

export PATH="/opt/homebrew/bin:/usr/local/bin:${HOME}/.local/bin:${PATH}"
if ! command -v gh >/dev/null 2>&1; then
  if ! command -v brew >/dev/null 2>&1; then
    printf 'HomebrewまたはGitHub CLIを先に導入してください。\nhttps://brew.sh/\nhttps://cli.github.com/\n' >&2
    exit 1
  fi
  brew install gh
fi
if ! gh auth status --hostname github.com >/dev/null 2>&1; then
  printf '表示されたURLとコードを別の端末で開くか、GH_TOKENで認証してください。\n'
  BROWSER=/usr/bin/true gh auth login --hostname github.com --git-protocol https --web
fi

case "$(uname -m)" in
  arm64) arch=arm64 ;;
  x86_64) arch=amd64 ;;
  *) printf '未対応のCPUです。\n' >&2; exit 1 ;;
esac

repository=g-kari/dependabot-alert-notice
tag="$(gh api "repos/${repository}/releases/latest" --jq '.tag_name')"
if ! [[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  printf '最新Releaseのタグが安定版SemVerではありません: %s\n' "$tag" >&2
  exit 1
fi
folder="security-notice_${tag}_macos_${arch}"
asset="${folder}.zip"
install_dir="${SECURITY_NOTICE_INSTALL_DIR:-${HOME}/Applications/security-notice}"
mkdir -p -- "$install_dir"
install_dir="$(cd -- "$install_dir" && pwd)"

if [ -e "${install_dir}/current" ] && [ ! -L "${install_dir}/current" ]; then
  printf '%s/current が既存のファイルまたはフォルダです。保存先を変更してください。\n' "$install_dir" >&2
  exit 1
fi

# Stage on the installation filesystem so the completed directory can be moved.
if ! mkdir "${install_dir}/.install-lock" 2>/dev/null; then
  printf '別の一式更新が実行中、または .install-lock が残っています。プロセスを確認してください。\n' >&2
  exit 1
fi
work=""
cleanup() { if [ -n "$work" ]; then rm -rf -- "$work"; fi; rmdir "${install_dir}/.install-lock"; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
work="$(mktemp -d "${install_dir}/.setup-XXXXXX")"

printf '%s (%s) を取得します。\n' "$tag" "$arch"
gh release download "$tag" --repo "$repository" --pattern "$asset" --pattern macos-checksums.txt --dir "$work"
expected="$(awk -v name="$asset" '$2 == name {print $1}' "${work}/macos-checksums.txt")"
if ! [[ "$expected" =~ ^[a-fA-F0-9]{64}$ ]]; then
  printf '配布ZIPのSHA-256チェックサムがないか、重複・不正です。\n' >&2
  exit 1
fi
actual="$(shasum -a 256 "${work}/${asset}" | awk '{print $1}')"
if [ "$actual" != "$(printf '%s' "$expected" | tr 'A-F' 'a-f')" ]; then
  printf '配布ZIPのSHA-256が一致しません。インストールを中止します。\n' >&2
  exit 1
fi

# Only extract the known distribution assets; do not follow arbitrary archive paths.
core_files=(dependabot-alert-notice Start.command config.yaml.example MAC-START.md)
known_files=("${core_files[@]}"
  Setup.command Update.command Service.command service-macos.sh Build.command
  Dockerfile.evaluator Dockerfile.codex-evaluator Dockerfile.apple-claude Dockerfile.apple-codex MAC-VERIFY.md LICENSE BUILD-INFO.txt)
extract_files=()
required_files=()
entries="$(unzip -Z -1 "${work}/${asset}")"
for required in "${known_files[@]}"; do
  case $'\n'"$entries"$'\n' in
    *$'\n'"${folder}/${required}"$'\n'*)
      extract_files+=("${folder}/${required}")
      required_files+=("$required")
      ;;
  esac
done
if [ "${#extract_files[@]}" -eq 0 ]; then printf '既知の配布ファイルがありません。\n' >&2; exit 1; fi
unzip -q "${work}/${asset}" "${extract_files[@]}" -d "${work}/extracted"
package="${work}/extracted/${folder}"
for required in "${core_files[@]}" "${required_files[@]}"; do
  if [ ! -f "${package}/${required}" ] || [ -L "${package}/${required}" ]; then
    printf '配布物に必要な通常ファイルがありません: %s\n' "$required" >&2
    exit 1
  fi
done
chmod u+x "${package}/dependabot-alert-notice" "${package}/"*.command
if [ -f "${package}/service-macos.sh" ]; then chmod u+x "${package}/service-macos.sh"; fi
if [ "$("${package}/dependabot-alert-notice" --version)" != "dependabot-alert-notice ${tag}" ]; then
  printf '配布バイナリのバージョンがReleaseタグと一致しません。\n' >&2
  exit 1
fi

target="${install_dir}/${folder}"
if [ -e "$target" ] || [ -L "$target" ]; then
  if [ ! -d "$target" ] || [ -L "$target" ] || [ ! -f "${target}/Start.command" ]; then
    printf '既存のインストール先が配布フォルダではありません: %s\n' "$target" >&2
    exit 1
  fi
  printf '既存の配布フォルダを保持します: %s\n' "$target"
else
  mv -- "$package" "$target"
fi
ln -sfn "$folder" "${install_dir}/current"
printf 'セットアップ完了: %s/current\n' "$install_dir"
printf '起動コマンド: bash %q\n' "${install_dir}/current/Start.command"
printf '確認間隔を1時間にする場合: bash %q --update-interval 1h\n' "${install_dir}/current/Start.command"
printf 'TUI: %q --tui\n' "${install_dir}/current/dependabot-alert-notice"
if [ -f "${install_dir}/current/service-macos.sh" ]; then
printf '常駐登録: bash %q install\n' "${install_dir}/current/service-macos.sh"
printf '一式更新: bash %q\n' "${install_dir}/current/Update.command"
fi
printf '設定・DB: ~/Library/Application Support/security-notice\n終了: 起動したターミナルでCtrl+C\n'

#!/bin/bash
# Build only the two application-owned images; never send a home/config as context.
set -euo pipefail
umask 077
export PATH="/opt/homebrew/bin:/usr/local/bin:${HOME}/.local/bin:${PATH}"
if [ "$(uname -s)" != Darwin ] || [ "$(uname -m)" != arm64 ] || [ "$(sw_vers -productVersion | cut -d. -f1)" -lt 26 ]; then
  printf 'Apple Silicon・macOS 26以降が必要です。\n' >&2
  exit 1
fi
if ! command -v container >/dev/null 2>&1; then
  printf 'Apple container 1.5.0以降を公式の署名済みインストーラから導入してください。\nhttps://github.com/apple/container/releases\n' >&2
  exit 1
fi
package_dir="$(cd -- "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cp -- "${package_dir}/Dockerfile.apple-claude" "${package_dir}/Dockerfile.apple-codex" "$work/"
container system start --enable-kernel-install
container build --cpus 2 --memory 2g --progress plain -f "${work}/Dockerfile.apple-claude" -t security-notice-apple-claude:latest "$work"
container build --cpus 2 --memory 2g --progress plain -f "${work}/Dockerfile.apple-codex" -t security-notice-apple-codex:latest "$work"
printf 'AI評価用のApple containerイメージを作成しました。\n'

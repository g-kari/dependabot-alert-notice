#!/usr/bin/env bash
# Install only the browser QA font from authenticated, isolated Ubuntu indexes.
set -euo pipefail
export LC_ALL=C
source /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 26.04 && "$VERSION_CODENAME" == resolute ]]
test -r /usr/share/keyrings/ubuntu-archive-keyring.gpg

font_dir=$(mktemp -d "$RUNNER_TEMP/devsecops-cjk-apt.XXXXXX")
trap 'sudo rm -rf -- "$font_dir"' EXIT
chmod 755 "$font_dir"

# Runner images differ across cloud hosts. Their ambient source/mirror settings
# are not inputs: only these HTTPS endpoints, suites, component and keyring are.
# Do not edit the host's APT configuration or widen browser QA network access.
cat > "$font_dir/ubuntu.sources" <<'SOURCES'
Types: deb
URIs: https://archive.ubuntu.com/ubuntu/
Suites: resolute resolute-updates resolute-backports
Components: main
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg

Types: deb
URIs: https://security.ubuntu.com/ubuntu/
Suites: resolute-security
Components: main
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
SOURCES

sudo install -d -o _apt -g root "$font_dir/lists/partial" "$font_dir/archives/partial"
apt_opts=(
  -o "Dir::Etc::sourcelist=$font_dir/ubuntu.sources"
  -o Dir::Etc::sourceparts=-
  -o "Dir::State::lists=$font_dir/lists"
  -o "Dir::Cache::archives=$font_dir/archives"
  -o Dir::Cache::pkgcache=
  -o Dir::Cache::srcpkgcache=
  -o APT::Update::Error-Mode=any
  -o Acquire::Retries=1
  -o Acquire::http::Timeout=30
  -o Acquire::https::Timeout=30
  -o Acquire::AllowInsecureRepositories=false
  -o Acquire::AllowDowngradeToInsecureRepositories=false
  -o APT::Get::AllowUnauthenticated=false
  -o Acquire::Check-Valid-Until=true
  -o Acquire::https::Verify-Peer=true
  -o Acquire::https::Verify-Host=true
  -o Acquire::https::AllowRedirect=false
)
# APT verifies Ubuntu signatures, authenticated index hashes and package hashes.
# No trust bypass or direct unverified .deb download is permitted.
sudo apt-get "${apt_opts[@]}" update
candidate=$(apt-cache "${apt_opts[@]}" policy fonts-noto-cjk | awk '$1 == "Candidate:" {print $2}')
[[ "$candidate" =~ ^[0-9A-Za-z.+:~_-]+$ ]]
apt-cache "${apt_opts[@]}" madison fonts-noto-cjk | awk -F '|' -v wanted="$candidate" '{gsub(/^[ \t]+|[ \t]+$/, "", $2); if ($2 == wanted) found=1} END {exit !found}'
sudo apt-get "${apt_opts[@]}" --simulate --no-install-recommends --reinstall install "fonts-noto-cjk=$candidate" > "$font_dir/transaction.txt"
awk '/^Remv / {bad=1} /^(Inst|Conf) / {split($2, package, ":"); if (package[1] != "fonts-noto-cjk") bad=1; if ($1 == "Inst" && package[1] == "fonts-noto-cjk") found=1} END {exit bad || !found}' "$font_dir/transaction.txt"
sudo env DEBIAN_FRONTEND=noninteractive apt-get "${apt_opts[@]}" --yes --no-install-recommends --reinstall install "fonts-noto-cjk=$candidate"
[[ $(dpkg-query -W -f='${Version}' fonts-noto-cjk) == "$candidate" ]]
dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' fonts-noto-cjk
fc-match -f '%{family}\n' 'Noto Sans CJK JP:lang=ja' | grep -Fx 'Noto Sans CJK JP'

# Mac mini実機での確認

対象：Apple M4 Pro・macOS 26.3・Apple container 1.5.0以降。

開発環境からこのMacへの接続がなく、Apple container実VM、認証を使った実AI評価、launchdの起動前・SSH切断後・再起動後の動作は未検証です。以下を実機で実施して結果を記録してください。CIのmacOSランナーでのテストはこの確認を代替しません。

## 1. 導入・認証・設定

READMEの導入手順をSSH上のBashで実施し、以下を確認します。トークン値や認証ファイルの中身を確認記録へ貼らないでください。

```bash
system_profiler SPHardwareDataType | grep -E 'Chip|Model Name'
sw_vers -productVersion
container --version
gh auth status --hostname github.com
app_dir="${SECURITY_NOTICE_INSTALL_DIR:-$HOME/Applications/security-notice}/current"
data_dir="${SECURITY_NOTICE_DATA_DIR:-$HOME/Library/Application Support/security-notice}"
"$app_dir/dependabot-alert-notice" --version
bash "$app_dir/Build.command"
```

`--setup` で設定を保存し、サービスを登録します。TUIで監視対象、除外、RSS、通知、プロバイダー・モデル・隔離方式を編集できることを確認します。設定の取消・入力途中の切断で保存されないこと、2つのTUIから同時編集した際に後からの保存が競合として拒否されること、監視間隔の変更で再起動の案内が出ることを確認します。TUIでSlack Bot/App TokenとDiscord Webhookを非表示入力し、確認取消・入力中のEsc/Ctrl+Cで保存されないこと、保存後は再起動案内が出ることを確認します。再起動後の通知疎通は本人の許可されたテスト先で確認し、無効化・環境変数に戻す操作も試します。認証ファイルが本人所有・0600で、認証情報の値が画面やログに出ないことも確認します。

## 2. 実VMの境界（実トークンを使わないプローブ）

Podmanを選ぶ場合は、同じユーザーで `podman machine start` 後、READMEのPodman用イメージを作成します。ダミー認証だけを使い、`--userns=keep-id:uid=1000,gid=1000 --user=1000:1000` でマウントを読めること、認証ディレクトリ・コンテナルートを書き換えられないこと、CPU/メモリ制限を確認してください。Podman未起動・認証読込失敗・タイムアウトでは評価が失敗し、Docker/ホストへ切り替わらないことも確認します。Podman実機は開発環境で未検証です。

通知の実送信・編集やAWS操作は開発テストで実施していません。通知を実機確認する場合は許可されたテスト先を使い、同一repoの新規・AI評価・解決で親が更新されること、再起動後も同じ親に入ること、承認無効化時に古いボタン操作も拒否されることを確認してください。AWS欄は構成未確認の条件付き評価として読み、不明な構成は本人が確認します。

アプリと同じ実行オプションで、ダミー認証ファイルだけを渡します。以下はBashで実行します。

```bash
work=$(mktemp -d)
chmod 700 "$work"
mkdir "$work/auth"
chmod 755 "$work/auth"
printf '{"fixture":"not-a-secret"}' > "$work/auth/auth.json"
chmod 444 "$work/auth/auth.json"
name="security-notice-probe-$$"
container run --name "$name" -i --read-only --cap-drop ALL --user 1000:1000 \
  --cpus 1 --memory 512m --network default \
  --tmpfs /tmp:rw,nosuid,nodev,size=64m,mode=1777 --workdir /tmp \
  --mount "type=bind,source=$work/auth,target=/run/security-notice-auth,readonly" \
  --entrypoint /usr/bin/setpriv security-notice-apple-claude:latest \
  --no-new-privs /bin/sh -eu -c '
    test "$(id -u)" = 1000
    grep -E "^(CapEff|NoNewPrivs):" /proc/self/status
    test "$(awk "/^NoNewPrivs:/ {print \$2}" /proc/self/status)" = 1
    test "$(awk "/^CapEff:/ {print \$2}" /proc/self/status)" = 0000000000000000
    test -r /run/security-notice-auth/auth.json
    if touch /usr/local/should-not-write; then exit 1; fi
    if touch /run/security-notice-auth/should-not-write; then exit 1; fi
    mkdir /tmp/home
    printf ok > /tmp/home/write-test
    test ! -e /host
    df -h /tmp
    node -e "fetch(\"https://api.anthropic.com/\",{signal:AbortSignal.timeout(10000)}).then(r=>console.log(\"HTTPS status\",r.status)).catch(()=>process.exit(1))"
  '
result=$?
container inspect "$name"
container delete --force "$name"
rm -rf "$work"
printf 'probe exit=%s（0なら成功）\n' "$result"
```

rootと認証マウントへの書き込みが失敗し、tmpfsだけに書けること、UID、capability、NoNewPrivs、メモリ・CPU・マウント・ネットワークが指定どおりであることを確認します。HTTPSプローブは認証なしの到達確認なので、401/404等のHTTP応答でも疎通成功です。NATは通信先制限ではなく、ホスト・LANとの通信を遮断する保証はありません。ネットワーク分離が追加で必要なら組織のファイアウォールで許可・拒否先を設計し、明示的に許可したテスト先だけで検証してください。

## 3. 実AI評価と失敗時の動作

TUIからテスト用アラートのAI評価を依頼し、結果が保存されること、評価後に `container list --all` に `security-notice-eval-*` が残らないことを確認します。Claude/Codexの利用するプロバイダーで確認してください。512MiBで不足する場合はTUIからメモリ上限を増やします。

AI設定を控えたうえで、存在しないAppleイメージ名、認証なしの状態、短いタイムアウトをそれぞれ試します。エラーで評価を中止し、ホストのClaude/CodexやDockerを起動しないこと、VMと `security-notice-apple-auth-*` の一時フォルダを残さないこと、前の評価を成功扱いに上書きしないことを確認します。VM削除に失敗した場合はログを確認し、自分の該当VMだけを削除します。確認後は設定を戻します。

## 4. SSH切断・再起動・FileVault

```bash
bash "$app_dir/service-macos.sh" status
curl --fail http://127.0.0.1:8999/settings >/dev/null
"$app_dir/dependabot-alert-notice" --tui --config "$data_dir/config.yaml"
```

TUI終了後も本体が継続すること、SSH切断後に再接続しても本体・定期取得が継続することを確認します。`stop` / `start` / `restart` と異常終了後の再起動も確認します。

Macを再起動し、必要ならFileVaultを解除したあと、GUIへログインせずSSHだけで接続し、同じ状態・疎通・AI評価の確認を行います。ログイン前のユーザーlaunchdドメインやホームの利用可否によってサービスが起動しない場合は、`status` と `service.log` の認証値を除いた内容を保存し、確認未完了として扱います。

## 5. 更新・バックアップ・復旧

サービスを停止してデータフォルダをバックアップし、再開します。`Update.command` を実行し、本体が再開すること、設定・DB・service.env.shが保持されることを確認します。新しいReleaseがなければ同じ版の再導入でも確認できます。

通信できない状態での一式更新は、失敗終了後に旧サービスが再開し、`current` とデータが保持されることを確認します。定期バイナリ更新は `--check-update` で確認し、新版があるときに更新後のバージョンと稼働を確認します。DBを伴う旧版への復旧はテスト用データコピーで実施し、対応するバックアップを復元してください。

## 確認記録

実施日時、Mac/OS/containerの版、アプリの版、上記各項目の成功・失敗・未実施、認証値を除いたエラーを記録します。全項目が完了するまでは「Mac実機で設定→常駐→AI評価→更新→再起動を検証済み」と表記しないでください。

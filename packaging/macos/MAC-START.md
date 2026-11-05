# Macでのセットアップ・運用

Apple Silicon・macOS 26以降でApple containerによるAI隔離、設定TUI、launchd常駐管理、一式更新を利用できます。Docker Desktop、Go、Mac上のブラウザは不要です。詳細な認証・導入手順は [README](https://github.com/g-kari/dependabot-alert-notice/blob/main/README.md#macでセットアップ常駐運用ビルド済み配布)、実機で残る確認は同梱の [MAC-VERIFY.md](MAC-VERIFY.md) を参照してください。

## 通知集約と確認方法

Slack/Discordを既定で1時間ごとにまとめ、リポジトリのまとめだけを更新します。定期通知は未解決件数・重要度別件数・AI評価状況に絞ります。普段の確認にはWeb UI/TUIを使い、アラート一覧・AI評価の全文・AWSで危険になる利用条件は画面で確認してください。更新後は本体を再起動してください。既存設定に項目がなければ `notification_interval: 1h` が適用されます。TUI/Web UIの「通知をまとめる間隔」で確認・変更できます。変更のない一覧は送らず、送信待ちは再起動後も保持します。期限の確認は毎分です。都度通知に戻す場合は `0s` にします。承認無効化は待たず反映します。

## 追加機能

Slack/Discord通知をリポジトリ単位に集約し、AWSで危険になる利用条件をAI評価に追加します。AWSの実構成は取得せず、条件付きの確認項目として表示します。古い結果を読むことはできますが、AWS欄を得るには再評価してください。TUIの「アラート詳細」でも `Evaluation.aws_risk` を確認できます。承認無効化の保存は再起動なしでSlackへ反映し、追跡可能な既存メッセージからのボタン除去も試みます。

## Podmanを明示的に選ぶ場合

`auto` はM4 Proでは引き続きApple containerです。Podmanを使う場合は以下を本人の端末で実施します。実機検証は未実施です。認証ファイルの値を表示・共有しないでください。

```bash
brew install podman
podman machine init    # 初回だけ
podman machine start
podman info
app_dir="${SECURITY_NOTICE_INSTALL_DIR:-$HOME/Applications/security-notice}/current"
cd "$app_dir"
podman build -f Dockerfile.evaluator -t dependabot-evaluator:latest .
podman build -f Dockerfile.codex-evaluator -t dependabot-codex-evaluator:latest .
data_dir="${SECURITY_NOTICE_DATA_DIR:-$HOME/Library/Application Support/security-notice}"
"$app_dir/dependabot-alert-notice" --tui --config "$data_dir/config.yaml"
```

TUIの「設定 > AI評価 > AI隔離 > runtime」で `podman` を選択し、`enabled: true` を維持して保存します。Web UIでも選べます。`Build.command` はApple container専用なのでPodman用イメージは上記で作成します。CLI認証ディレクトリがPodman machineから読み取り可能か確認してください。rootlessのUID/GID対応、読取専用マウント・ルート、tmpfs、権限削除、CPU/メモリ制限を使います。失敗時にDocker/ホスト実行へ切り替えません。tmux/launchdでは同じユーザーでPodman machineを起動し、PodmanのPATHを本体へ渡してください。

詳しくは [READMEのPodman手順](https://github.com/g-kari/dependabot-alert-notice#podmanでai評価する) と [公式導入ガイド](https://podman.io/docs/installation) を参照してください。

## 初回のmacOS警告

アプリのDeveloper ID署名・公証は未設定です。配布元のリポジトリの配布物とSHA-256を確認してください。管理ポリシーやGatekeeperで実行が拒否される場合は、[Apple公式手順](https://support.apple.com/ja-jp/102445) や管理者による許可が必要です。OSのセキュリティ機能を一括で無効にしないでください。CLI導入でも管理ポリシーによる実行制限は回避しません。

## SSHからの導入

既存のGitHub CLI認証、または非表示入力した `GH_TOKEN` を利用します。privateリポジトリとDependabotアラートを読める権限・SSO認可が必要です。Bashで実行します。

```bash
read -r -s -p 'GitHub Token: ' GH_TOKEN; printf '\n'
export GH_TOKEN
gh auth status --hostname github.com
bash Setup.command
app_dir="${SECURITY_NOTICE_INSTALL_DIR:-$HOME/Applications/security-notice}/current"
data_dir="${SECURITY_NOTICE_DATA_DIR:-$HOME/Library/Application Support/security-notice}"
mkdir -p "$data_dir"
cd "$data_dir"
"$app_dir/dependabot-alert-notice" --setup --config "$data_dir/config.yaml"
```

`Setup.command` は最新の安定版ZIPをCPUに合わせて取得し、SHA-256とバージョンを検証して `current` を切り替えます。設定・DBには触れません。初期状態はlocalhost待受、AI自動評価なし、承認操作無効です。6つのデフォルトRSSから開始できます。

## Apple containerとAI認証

[Apple containerの公式Release](https://github.com/apple/container/releases/tag/1.5.0) から署名済みpkgを導入します。Apple Silicon・macOS 26以降・container 1.5.0以降が必要です。READMEにブラウザを使わない取得・インストール手順があります。

```bash
container --version
bash "$app_dir/Build.command"
# Claudeを使う場合。Codexの場合はOPENAI_API_KEYを同様に設定
read -r -s -p 'Anthropic API Key: ' ANTHROPIC_API_KEY; printf '\n'
export ANTHROPIC_API_KEY
```

APIキー方式はホストへのAI CLI導入が不要です。ファイル認証ではCodexの `${CODEX_HOME:-$HOME/.codex}/auth.json`、Claudeの `~/.claude/.credentials.json` だけをコピーします。ClaudeのKeychain認証は自動で取り出しません。

評価VMには認証コピーだけを読み取り専用で渡します。ホストのホーム・リポジトリは渡しません。読み取り専用ルート、64MiB tmpfs、非root、capability削除、no-new-privileges、CPU・メモリ・時間制限を適用します。既定のNATは外向き通信を許可し、接続先・LANへのアクセスを許可リストで制限しません。失敗時は隔離なしで実行しません。

Intel Macや他環境では `runtime: docker` と既存Dockerfileを使います。

## 常駐管理・TUI

利用ユーザーで常駐登録します。通知の認証情報は環境変数を渡すか、起動後のTUIから登録できます。

```bash
bash "$app_dir/service-macos.sh" install
bash "$app_dir/service-macos.sh" status
"$app_dir/dependabot-alert-notice" --tui --config "$data_dir/config.yaml"
# 管理コマンド
bash "$app_dir/service-macos.sh" stop
bash "$app_dir/service-macos.sh" start
bash "$app_dir/service-macos.sh" restart
# 登録を解除（データは保持）
# bash "$app_dir/service-macos.sh" uninstall
```

必要な管理操作だけsudoします。アプリ本体は一般ユーザーで起動します。常駐登録は初回の環境変数を `$data_dir/service.env.sh`（本人所有・600）へ保存し、既存ファイルを上書きしません。認証情報を含むため共有しないでください。変更後はサービスを再起動します。

TUIは矢印キーとEnterで選択します。Escで戻り、番号入力も併用できます。プロバイダー・モデル・重要度・隔離方式・有効無効などには候補を表示し、モデルの直接入力も利用できます。端末以外では従来の番号操作を使います。設定、アラート・評価結果、ログ、手動取得、評価依頼に対応します。設定は `s` で確認して保存、`q` で破棄、`r` で再読込。認証情報は表示しません。保存失敗・競合時は既存設定を保持し、再起動が必要な変更を案内します。TUIを終了しても本体は継続します。

「認証・通知設定」からSlack Bot/App Token・Discord Webhookを非表示で入力・保存できます。保存先は `$data_dir/config.yaml.credentials.json`（本人所有・0600、平文）で、環境変数より優先します。無効化・環境変数へ戻す操作も選べます。保存後は本体を再起動してください。更新直後も本体を再起動して新しい認証APIを使用します。tmuxで手動起動している場合は、本体のペインでCtrl+C→同じ起動コマンドを再実行します。TUIの終了だけでは本体を再起動しません。

`stop` は次回起動時の開始を無効にしません。継続して止める場合は `uninstall` します。FileVaultで暗号化したMacは電源投入後のロック解除が必要です。ログは `$data_dir/service.log`。SSH切断・再起動・ログイン前の挙動は実機の確認手順を実施してください。

手動実行は `bash "$app_dir/Service.command"`（Ctrl+Cで終了）。常駐中には二重起動しないでください。GUI操作を使う環境では `Start.command` を開く方法も維持します。ヘッドレスでは `open Start.command` を使わずBashで実行します。

## 更新・データ保護

```bash
bash "$app_dir/Update.command"
"$app_dir/dependabot-alert-notice" --version
bash "$app_dir/service-macos.sh" status
```

稼働中の登録済みサービスを停止し、一式を検証・配置して再開します。取得・検証失敗時は旧版を再開します。手動起動中の本体は先に停止してください。バイナリは起動前と標準6時間ごとに更新確認します。スクリプトやDockerfileも更新するには `Update.command` を使います。イメージ更新は `Build.command` を再実行します。

設定・DB・認証環境ファイル・TUI認証ファイルは `$data_dir` に保持します。バックアップはサービスを停止してからフォルダ全体を権限600のアーカイブに保存してください。認証情報を含みます。復旧は停止→現データ退避→対応するバックアップ復元→所有者・権限確認→起動の順です。旧バイナリだけへのダウングレードでDB互換性は保証しません。

## 配布物の検証状態

`BUILD-INFO.txt` にCPU、バージョン、ソースcommit、未コミット変更の有無を記録します。ReleaseワークフローはLinuxとApple Silicon/IntelのmacOSランナーで全Goテスト・race検査、スクリプトのモック検証、ZIP・ネイティブバイナリの検査を行ってから公開します。

macOSランナーでの検査は、macOS 26.3のApple VM実行やM4 Proの起動前常駐テストを含みません。実機検証済みとは称しません。残る確認は [MAC-VERIFY.md](MAC-VERIFY.md) を参照してください。

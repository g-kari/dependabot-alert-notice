# DevSecOps Console: 全体仕様と実装ロードマップ

基準日: 2026-11-12。対象リポジトリ: [g-kari/devsecops-console](https://github.com/g-kari/devsecops-console)。コードの到達点は Overview/Assets の PR #53、更新保存層の PR #70–76、同一 controller 内の限定復旧の PR #77、品質 gate の PR #81、GoReleaser 契約修復の PR #83 を含む main `a6d5e18710bca70a842dc23aaf6904c512c06448` のスナップショット。マージ済みコード、個別の検証結果、正式リリースへの収録は別に確認する。

本書は [アーキテクチャ設計 v1.0 のロードマップ](https://devsecops-architecture-ggg.mail590137.chatgpt.site/#roadmap) を、実装済みの範囲と残る製品要件に分けた仕様である。画面統合と GitHub 接続認証は全体の一部であり、それだけで DevSecOps 対応の完了とはしない。以降の「必要」「合格条件」は未実装部分の要求を含む。予定の API 名や状態は、既存契約と区別して記す。

## 1. 目的、利用者、完了の定義

コード、依存関係、コンテナ、クラウド設定、脅威、Web 防御の検出を安全に取り込み、資産ごとの影響・根拠・不明点を確認し、優先付け、調査、修正、再検査まで追跡する。最初は Go のモジュラーモノリス、SQLite、既存 Job Queue を拡張する。PostgreSQL、分散ワーカー、特定の外部サービスは初期必須要件にしない。

- Viewer は対象範囲内の状況・証拠・履歴を確認する。
- Analyst はトリアージ、調査案件、修正案、例外申請を扱う。
- Admin は接続設定と運用を管理する。ロールを持つだけでは PR マージや本番変更を許可しない。

製品全体の合格条件は次のとおり。

1. 異なる検出元を一つの対応キューから調べられ、原観測と資産別の対応状態が失われない。
2. 未接続、未取得、部分取得、権限不足、取得失敗、正常なゼロ件、解消済みを区別できる。収集失敗による誤解消を起こさない。
3. 優先度の根拠、入力時刻、欠落、評価履歴、対応期限を説明できる。参考試算と保存済み判断を混同しない。
4. 調査の判断、担当、修正の承認、外部 Issue/PR、再検査結果をたどれる。変更操作は権限・対象単位の承認・監査を通る。
5. 既存 Dependabot の取得、評価、RSS、通知、承認・マージ制御を回帰させない。
6. 移行と復旧を隔離した合成データで再現でき、実環境への接続・移行・公開・デプロイは別の検証記録を持つ。

### 実装済みと運用確認を分ける

「実装済み」はマージされたコードとその検証範囲を指し、実 DB の移行、実データ接続、継続稼働、ブラウザー実表示、全 OS の実機確認を意味しない。オフライン取り込みは、外部サービスを継続収集できることの証明ではない。以下は上記基準日のスナップショットであり、後続 PR の完了は個別に更新する。

| 到達点 | 実装済みの範囲と根拠 | 未完了・検証境界 |
| --- | --- | --- |
| Phase 0 | [PR #17](https://github.com/g-kari/devsecops-console/pull/17): Asset/Finding/Observation/Event/IngestRun、非破壊 migration、Dependabot 投影。詳細は [Phase 0](security-phase0.md)。 | 合成 DB の保全・失敗復旧テストであり、運用 DB の移行・復旧演習ではない。 |
| Phase 1 入力と読み取り | [PR #20](https://github.com/g-kari/devsecops-console/pull/20): Trivy JSON オフライン取り込みと共通 GET-only Findings/Assets API。[PR #28](https://github.com/g-kari/devsecops-console/pull/28): Code Scanning オフライン取り込み。[PR #29](https://github.com/g-kari/devsecops-console/pull/29): secret-free Secret Scanning metadata 取り込み。 | ライブ収集、スキャナー実行、HTTP 取り込み口、共通トリアージの実装ではない。非空の secret は masked 値も拒否する。 |
| Phase 1 証拠と関連付け | [PR #30](https://github.com/g-kari/devsecops-console/pull/30): EPSS/KEV オフライン証拠と manifest・鮮度。[PR #31](https://github.com/g-kari/devsecops-console/pull/31): source/native ID 投影、literal 検索、厳密 CVE、same-CVE related API。 | 共通 Finding の継続 feed 更新や永続優先度再評価ではない。legacy risk は変更していない。 |
| 共通優先度の参考試算 | [PR #36](https://github.com/g-kari/devsecops-console/pull/36): 既存モデルへの pure adapter。[PR #37](https://github.com/g-kari/devsecops-console/pull/37): bounded base input。[PR #38](https://github.com/g-kari/devsecops-console/pull/38): 明示的 profile binding。[PR #39](https://github.com/g-kari/devsecops-console/pull/39): bounded CVE assessment input。[PR #41](https://github.com/g-kari/devsecops-console/pull/41): stdin-only offline CLI。 | profile/assessment の自動選択、共通スコアの保存、期限作成、通知は行わない。 |
| 共通優先度 API | [PR #42](https://github.com/g-kari/devsecops-console/pull/42): 明示的 `as_of` の GET-only priority-preview と CLI 再現用 snapshot。 | 現在の DB snapshot を指定時刻で評価する。過去 DB の再構成ではない。API では profile/assessment/CVSS を推定・選択しない。 |
| native UI の第 1 工程 | [PR #47](https://github.com/g-kari/devsecops-console/pull/47): `/findings` 一覧・詳細、既存 API と共通の検証、同一 CVE 関連、EPSS/KEV、参考試算への導線。詳細は [native Findings Console](native-findings-console.md)。 | 全画面の統一、Overview/Assets の完成、Web 認証、共通変更操作は含まない。ページ内件数は全体集計ではない。PR CI と当該 merge の事後 CI は成功。後続 PR #53 の画面統合と実ブラウザー検証は native 画面統合の行に分けて記録する。 |
| GitHub credential context | [PR #48](https://github.com/g-kari/devsecops-console/pull/48): 明示的な GitHub 認証 context と共有 command runner のコード統合。 | 最終 head の全体 CI とレビューを確認してマージ済み。[事後 CI](https://github.com/g-kari/devsecops-console/actions/runs/42664337692) も実 merge commit で format/vet/race/build/Mac helper が成功。実アカウントでの認証設定は有効化しておらず、ライブ接続や Web 利用者認証の確認ではない。legacy `inherited` mode は対話 CLI の認証依存を維持し、分離を保証しない。 |
| 記録済み収集状態/coverage | [PR #49](https://github.com/g-kari/devsecops-console/pull/49): 明示的 `as_of`、厳密な source/scope と bounded query/page による GET-only 読み取り。最新の記録済み試行と最後の成功 receipt を分離する。詳細は [connector status 契約](security-connector-status.md)。 | 最終 head の全体 CI と実 merge の [事後 CI](https://github.com/g-kari/devsecops-console/actions/runs/42677991408) で format/vet/race/build/Mac helper が成功。設定 scope/inventory、全試行履歴、生存監視は未実装で、asset 母数も unknown/null。変更操作、認証、新規 feed は追加しない。 |
| native 画面統合 | [PR #53](https://github.com/g-kari/devsecops-console/pull/53): Overview、Assets 一覧/詳細、記録済み Integrations と共通 shell、履歴移動後の SSE 復帰。 | 実 Chrome 32 ケース・10 フロー・29 画像を確認し、実 merge の [Check](https://github.com/g-kari/devsecops-console/actions/runs/43188786770) / [Trial](https://github.com/g-kari/devsecops-console/actions/runs/43188786584) が成功。captured viewport 外の全描画、ユーザー端末、実運用有効化は未確認。設定母数・生存監視は unknown のまま。 |
| 共通 enrichment の限定経路 | [PR #56](https://github.com/g-kari/devsecops-console/pull/56)〜[#69](https://github.com/g-kari/devsecops-console/pull/69): receipt・合成 refresh・明示的な手動操作、journal/checkpoint と保持 operation/reservation 証拠。詳細は [refresh](security-enrichment-refresh.md)、[journal adapter](security-enrichment-journal-adapter.md)、[reservation](security-enrichment-operation-reservation.md)。 | 個別 slice の opt-in・保持要求・上限を維持する。共通 Finding のライブ継続収集、再起動をまたぐ実行所有権、運用 DB への適用ではない。 |
| 世代付き書込みと旧入口 guard | [PR #70](https://github.com/g-kari/devsecops-console/pull/70)、[#71](https://github.com/g-kari/devsecops-console/pull/71)、[#72](https://github.com/g-kari/devsecops-console/pull/72): 明示的 fenced write と採用済み feed の旧 6 入口の防御。 | コード・合成回帰・統合まで完了。旧 binary 混在やあらゆる SQL 書込みの防御を保証しない。controller 接続は残る。 |
| 証拠付き予約解除と次世代受付 | [PR #73](https://github.com/g-kari/devsecops-console/pull/73)、[#74](https://github.com/g-kari/devsecops-console/pull/74)、[#76](https://github.com/g-kari/devsecops-console/pull/76): 同一 transaction の certificate/CAS と保持履歴・業務証拠の再検証。詳細は [atomic release](security-enrichment-atomic-release.md)。 | #74 の [事後 CI](https://github.com/g-kari/devsecops-console/actions/runs/43007002373)、#76 の [Check](https://github.com/g-kari/devsecops-console/actions/runs/43071386607) / [Trial](https://github.com/g-kari/devsecops-console/actions/runs/43071386702) が成功。source ごとの生涯上限 H=4 は試験的な上限で、運用容量・retention の保証ではない。 |
| 同一 controller 内の限定復旧 | [PR #77](https://github.com/g-kari/devsecops-console/pull/77): 保持した terminal checkpoint の acknowledgement が不明な場合の明示的な読取照合。 | [事後 Check](https://github.com/g-kari/devsecops-console/actions/runs/43079548036) / [Trial](https://github.com/g-kari/devsecops-console/actions/runs/43079548185) 成功。同じ controller の存続期間内に限る。fetch/書込み再試行、新 reservation、durable release、fenced controller 接続、再起動復旧、runtime/UI caller 接続は行わない。 |
| 配布と品質 gate | [PR #54](https://github.com/g-kari/devsecops-console/pull/54) の Windows 常駐更新、[#75](https://github.com/g-kari/devsecops-console/pull/75) の tagless Trial、[#78](https://github.com/g-kari/devsecops-console/pull/78) の正式公開準備、[#81](https://github.com/g-kari/devsecops-console/pull/81) の lint/govulncheck/coverage/license gate。 | [v0.4.0](https://github.com/g-kari/devsecops-console/releases/tag/v0.4.0) は 2026-11-12 01:41 UTC に公開。後続 main 全変更の収録や各時点の CI 成功を意味しない。#81 は既存 lint 63 件を別課題として残し、PR では新規指摘のみをブロックする。 |

残る主要要件は、設定 scope/inventory・全試行履歴・生存監視、GitHub 継続収集、Trivy CI 経路、共通 enrichment の予約付き controller 接続と継続実行、保存評価と根拠 UI、Web 認証/RBAC、共通調査・対応・通知・SLA、AWS/WAF/SBOM、傾向分析、復旧・運用である。画面統合や保存層の完了を製品全体の完了としない。新しい読取中心の機能案は第 5.6 節に記す。

未マージの候補は上表に含めない。[PR #83](https://github.com/g-kari/devsecops-console/pull/83) の GoReleaser pin/provenance と契約テストの修復は基準 main に統合済み。旧 main の固定 version テスト失敗を引き継いだままとは扱わず、統合後の [Check](https://github.com/g-kari/devsecops-console/actions/runs/43223772505) / [Trial](https://github.com/g-kari/devsecops-console/actions/runs/43223772623) はこのスナップショットでは検証中として区別する。[PR #82](https://github.com/g-kari/devsecops-console/pull/82) の Go 更新と後続正式公開は既存の担当工程で、文書更新から重複着手しない。正式公開は最終 source の CI、tag、公開済み Release、成果物・checksum・version の一致を個別に確認する。

## 2. 互換性と既存機能の再利用

### 名前とデータの境界

リポジトリ名は `devsecops-console` が正である。一方、Go module `github.com/g-kari/dependabot-alert-notice`、配布バイナリ・version 出力・Release asset の `dependabot-alert-notice`、既存 updater の配布元設定は独立した互換性契約である。macOS の `service-macos.sh`、service label `xyz.0g0.security-notice`、既定 install の `~/Applications/security-notice/current`、data の `~/Library/Application Support/security-notice`、`config.yaml` と `data_path`（設定例では `store.db`）、既存の保存先 override も維持する。本仕様を理由に一括置換しない。変更が必要なら移行、旧参照、更新・ロールバックの検証を別変更で扱う。既存 devbox の pin、起動方法、サービス、データ配置も変更しない。

`alert_records` は Dependabot の承認、評価、通知 ID、マージ処理の正本として維持する。共通 Finding の triage と source lifecycle に承認状態を埋め込まない。既存 URL、Web/TUI/RSS の契約を保ち、共通モデルへの投影と legacy 更新は整合した transaction にする。古いバイナリと新しいバイナリを同じ DB に混在させない。

### 再利用するものと共通化で足すもの

次の機能は既存 Dependabot 経路に存在する。「機能がない」として作り直さず、入力の binding、適用対象、イベントを共通 Finding へ拡張する。

| 既存資産 | 維持・再利用 | 共通化で必要な追加 |
| --- | --- | --- |
| `internal/scoring` の `urgency-v1`、normalizer、期限計算 | profile、CVE assessment、CVSS/EPSS/KEV、不明区間、reasons/confidence の意味と既存閾値。 | source-native Finding/Asset と profile/assessment の明示 binding。脆弱性以外を無理に同じ数式へ入れない。 |
| `internal/threat` と feed 取得 | EPSS/KEV の独立した時計、失敗時の前回値保持、既存 feed の取得・検証。 | common enrichment observations/manifest への適合、対象 CVE の差分更新、再評価通知。legacy 保存先との二重更新・時計混同を防ぐ。 |
| `internal/risk` の service/worker と保存履歴 | 起動・変更・鮮度失効による再評価、入力変更競合の拒否、直前同一評価のみ省略、履歴・期限の同時保存。 | common Finding 用の評価単位と入力 snapshot。別資産・別環境へ assessment や期限を流用しない。preview は保存判断の代用にしない。 |
| 既存の解決・再発管理 | 完全取得を条件とする解決、履歴保持、再発案件、解決後の遅延評価・操作の拒否。 | 他ソースの完全性と明示状態の規約。共通 source 状態、triage、修正・再検査を別軸で接続する。 |
| `internal/notification`、Slack/Discord | 永続バッチ、最初の期限を延長しない集約、送信時の監視判定、送信先別 ID、失敗再試行。 | 共通イベント、ソース横断の範囲・購読・重複抑制、失敗・不明送信結果の可視化。外部送信の exactly-once を保証したと偽らない。 |
| `internal/policy`、control、merger の既存承認経路 | 対象除外の再検査、承認無効化、操作直列化、対象 PR の安全確認。 | Web principal/RBAC、共通 action の対象・revision・承認期限、監査。既存の approval ID に Finding UUID を渡さない。 |

根拠は [既存 README](../README.md)、[preview adapter](finding-priority-preview.md)、[preview API](finding-priority-preview-api.md)。試算用の [base](finding-priority-preview-input.md)、[profile](finding-priority-preview-profile-input.md)、[assessment](finding-priority-preview-assessment-input.md)、[CLI](finding-priority-preview-cli.md) の閉じた schema は、そのまま無制限の外部書き込み schema に転用しない。

## 3. 共通モデルと不変条件

### 境界と情報の保持

- Connector は認証、対象 scope、ページング、rate limit、Webhook/EventBridge 検証を担当する。
- Ingestion は入力制限・schema 検証、正規化、冪等性、coverage と履歴を担当する。
- Core は Finding/Asset、評価、triage、調査、対応方針を保持する。
- Action は外部 Issue/PR、通知、修正などの副作用を、権限・承認を再検査して実行する。取り込み transaction 内から外部変更しない。

既存の Asset は対象の provider/account/region/native identity と環境・重要性を表す。Finding は資産に対する source-native な問題であり、CVE そのものではない。Observation は source/native ID、観測時刻、run、選択した安全な証拠への参照を保持する。raw payload の無条件保存は要求しない。既存 adapter の秘密値・本文の非保存方針を維持し、将来 raw archive が必要な場合は保存目的・保持期間・アクセス制御を先に定義する。

IngestRun は試行と coverage の正本、Event は追記型の変更証跡とする。調査案件、Action、例外、通知 delivery は今後追加する業務モデルであり、現時点で全テーブルが実装済みという意味ではない。

### ID、状態、時刻

1. 厳密同一性は source、信頼済み tenant/account/scope、native finding ID に基づく。CVE、同じ alert number、rule、title だけで統合しない。source-native ID と共通 UUID を区別する。
2. 同一 CVE の関連表示は候補の関連付けであり、重複排除、同じ到達性、共有の修正・例外・解消を意味しない。
3. `source_status` の `active/resolved/suppressed/unknown`、local `triage_status`、承認、Action の実行状態を別に保持する。source の suppression は社内のリスク受容を意味しない。
4. first_seen、last_seen、source 発生/更新時刻、取得時刻、feed publication、評価 as_of を区別する。古い観測は履歴に残しても現在状態を巻き戻さない。
5. run、entities、observations、events は対象の transaction 単位で整合させる。replay は同じ入力・scope・時計なら同じ結果、同じ run ID で入力を変えれば conflict とする。
6. 正常終了した同じ対象範囲の完全取得だけが、欠落による解消判定の候補になる。さらにソース別の完了条件と監視対象を確認する。オフライン import は空を含め partial であり、欠落で解消しない。
7. 権限不足、429、timeout、途中ページ失敗、スキャン失敗、未検査、対象除外、interrupted run は解消の証拠にしない。
8. EPSS の実値ゼロと missing、KEV の過去 positive と現在の確認範囲を区別する。missing をゼロや KEV false にしない。脅威 feed の変化は検出元の解消を意味しない。

## 4. Phase 0: 保全とデータ基盤

コードとしての初期基盤は実装済み。後続変更は [Phase 0 の移行・復旧規約](security-phase0.md) を引き継ぐ。

- 既存 DB を再作成して履歴を失う経路を持ち込まず、version 付き additive migration を行う。
- schema 不明、source identity 不正、途中 backfill 失敗は rollback する。DB 削除による解決をしない。
- 実 DB を選ぶ前に全 writer 停止または SQLite の整合した backup を取り、孤立したコピーで移行と復旧を確認する。

合格条件: 合成の旧 DB に対し ID・評価・approval・notification ID・履歴を維持し、migration failure → repair → reopen、反復 migration、投影失敗 rollback、旧 workflow の回帰を再現できる。これは運用 DB での確認とは別に記録する。

## 5. Phase 1: GitHub / Trivy を継続運用できる共通体験へ

### 5.1 収集状態・coverage の読み取り

初期の `GET /api/v1/connectors/status` は実装済みである。その範囲は、**記録された source/scope の run/receipt** の読み取りに限り、設定 scope の inventory、全試行履歴、生存監視は引き続き別工程とする。以下の記録・時計・不明状態の境界を保ち、未マージの後続候補を main 実装済みとは扱わない。既存 [Findings/Assets API](security-phase1.md) を変更 API にしない。

- 同じ source 内の正確な retained scope を単位とし、source の違い、owner-wide/repository、account、CVE 選択を混同しない。記録された pair の総数は設定済み対象や資産の母数ではない。
- 最新の**記録済み** run と最後の成功 receipt を分け、記録された失敗・partial・running を過去の成功で隠さない。成功も partial になり得る。時刻、結果、coverage、retained run 件数を返しても、実際の全リクエスト数・全失敗数とは呼ばない。
- offline writer は入力検証前に DB に触らず、import/storage 失敗は原子的 rollback により失敗 receipt を残さない。成功 partial receipt しか残らない経路では、直近成功の後に失敗がなかったとは判断できない。Dependabot の attempt 記録も全試行の完全性を保証しない。
- `as_of` は現在の retained snapshot を評価する時計であり、履歴復元ではない。ledger age と source/feed の鮮度、SLA、稼働状態を分ける。未来の receipt は明示し、現在の status/coverage を unknown とする。保存された running は生存も停止も証明しないため、liveness は unknown とする。
- 未記録 scope は一覧に現れない。未設定・未スキャン・対象外・未記録の失敗を区別する根拠がないため、configured/unscanned inventory、attempt 履歴の完全性、asset 母数は unknown/null とし、coverage 百分率や「正常ゼロ対象」を推定しない。
- 認証情報、raw report/error、cursor、receipt body を返さない。pagination と query 検証を既存 API と揃える。page の group と scalar summary の materialization を bounded にし、正確な件数のための retained 全履歴の SQL 集約が constant-time とは約束しない。

後続工程では、version 付き設定 scope/inventory と、成功 import transaction から独立した attempt 記録・完了・照合の契約を定める。安全な source/scope 検証後の attempt と成功 receipt を別 ID で結び、既存 import UUID に running 行を先置きして衝突させない。既存 importer の validation 前 DB 不触と atomic rollback を保ち、記録開始前や記録不能の失敗まで把握できると主張しない。liveness は別の観測根拠と判定規約ができるまで unknown を維持する。read API 自身が欠けた失敗記録を作ることはない。

合格条件: 記録 pair のない empty 応答、記録済み成功後の失敗、partial/empty、running、future、source/scope 分離、同時更新を合成 DB で再現する。offline の未記録失敗や run のない scope を正常・未スキャン・全失敗と誤認せず unknown を保つ。件数・時計・pagination、bounded materialization、読取前後の DB 無変更と legacy API 互換を検証する。後続の inventory/attempt/liveness 契約の受入は初期 read API と分ける。

### 5.2 GitHub の継続収集と認証 context

Dependabot の既存収集を維持した上で Code Scanning / secret-free Secret Scanning の polling を追加し、必要なら検証済み Webhook と定期 API reconciliation を組み合わせる。

- 接続先、principal、repository と必要な read 権限を明示し、接続診断で不足を区別する。GitHub 用 credential context の固定・分離は Web 利用者認証ではない。
- page/cursor、429/Retry-After、再試行上限、timeout、重複 run、restart、監視範囲変更を管理する。対象設定の変更後に古い job が対象外へ書き込まない。
- Secret Scanning は upstream で literal secret を抑止し、adapter の非空 secret 拒否を維持する。資格情報の有効性検査・失効は収集の副作用に含めない。
- Webhook を導入するときは body 上限、署名、delivery ID、replay/順序逆転を検査する。受信だけで full coverage とせず、欠落を API 取得で補完する。
- プラン・権限で取得できないソースを正常ゼロ件にしない。明示 source state と欠落解消の判定を分離する。

合格条件: fake client/HTTP fixtures により複数ページ、重複、失敗、拒否、再開、順序逆転、署名不正、設定変更競合を検証する。何も取得できなかった run でも既存 Finding が閉じない。外部サービスへの接続・新権限は別の導入判断とする。

### 5.3 Trivy の安全な CI 入力経路

既存 JSON importer は report の検証と正規化であり、scanner ではない。次は CI の成果物と検査対象を結ぶ契約・workflow を作る。

- 信頼済みの repository/commit、workflow run、artifact digest、scan target、scanner/schema version、取得・観測時刻を manifest に結ぶ。未信頼 report の URL や ArtifactName から権限・対象 scope を採用しない。
- scan、report export、validate/dry-run、import の各結果を分ける。scan failure を空 report として取り込まず、`Status: fixed` をインストール修正済みと読まない。
- 最小権限、入力/圧縮展開サイズ・件数上限、secret metadata 非保存、credential-free な証拠参照を維持する。workflow の action/tool は選定した immutable revision に固定する。未信頼 fork/PR に秘密情報や書き込み権限を渡さない。
- workflow と synthetic report の契約検証を先に行える。実 scanner の導入・実行、registry/CI 接続、runtime や課金を伴う実行は選定・承認後に分けて確認する。
- SARIF、IaC、secret、license の検出は、現在の vulnerability-only JSON adapter が対応済みと扱わず、必要時に独立 schema/安全要件を設ける。

合格条件: synthetic report/manifest の一致・不一致、失敗・欠損・古い report、改変 bytes、対象違い、再送で deterministic な結果になる。scanner を動かしていない検証はその旨を記録する。

### 5.4 共通 Finding の継続 enrichment と優先度

既存 feed 取得、`urgency-v1`、risk worker を再利用する。まず common enrichment の保存契約に取得結果を接続し、その後、明示 profile/assessment に基づく永続評価へ進める。

- 対象 canonical CVE を bounded batch で選び、publication と observation を分けて保存する。feed 全体失敗・一部不正は前回の有効証拠を壊さず、失敗 run を残す。
- EPSS と KEV の時計を独立させる。古い publication は履歴であり、新しい値を置換しない。取り込み時刻だけで鮮度を延ばさない。
- Finding/asset/CVE/profile/repository と assessment を厳密に binding し、選択理由・入力 origin・model version・as_of を snapshot 化する。同一 CVE の別資産に流用しない。binding は入力の整合性検査であり、主張の真実・出典・authority の保証ではない。supplied `not_affected` はモデルの `not_affected` / `verified` / `planned` を作り得るため、永続判断に使う前に出典、主張者の権限、対象への適用根拠と現在の有効性を別途検証する。詳細は [assessment の解釈境界](finding-priority-preview-assessment-input.md)。
- assessment の `expires_at` は EPSS/KEV の feed freshness と独立して扱う。失効時刻の一致は expired とし、expiry/revocation/対象・revision 変更を契機に再評価する。feed の更新だけで assessment を更新・延命しない。
- common preview の read/CLI parity を維持する。preview を通知抑止、Finding close、risk acceptance、実期限の開始に使わない。永続化は検証済み入力を使う別 command/job とし、評価履歴と期限を transaction で保存する。入力 revision が計算中に変わったら古い保存を拒否して再評価する。
- missing、unsupported、stale、invalid を見せる。既存モデルの stale KEV historical-positive の扱いを隠さず、現在の侵害確認に言い換えない。model/閾値変更は別途 version と回帰検証を持つ。

合格条件: 固定時計で zero/missing、72 時間境界、stale/future、古い feed、profile 不一致、A→B→A、同時変更、再発を検証する。assessment expiry の直前・一致・直後、撤回・対象変更、feed freshness との独立性、未検証 claims の永続利用拒否を試験する。legacy と common の入力が等価なら既存モデル結果が一致し、preview 閲覧だけでは保存、通知抑止、Finding close、risk acceptance、実期限開始が発生しない。

### 5.5 Overview / Assets / 優先度表示と画面統合

PR #53 で native Overview/Assets/記録済み Integrations と共通 shell を統合し、既存画面の回帰と、記録された実 Chrome 32 ケース・撮影範囲の表示を確認した。以下は表示要件の全体像であり、個々の指標まで全て実装済みという意味ではない。未実装の期限・実 coverage・根拠 UI はデモ値で補わず、既存 Alerts、評価、設定、ログ、RSS、TUI の契約を保って追加する。

- Overview は open/critical/KEV/期限超過、source 別件数、同期状態と coverage、直近重大イベントを共通 filter scope と集計時刻付きで示す。page-only count と全体 count を明確に分ける。
- Assets は provider/account/region、repository/artifact、環境・重要性、検出元、最終観測を検索できる。Finding 一覧との行き来で filter を維持する。未管理資産と未検査資産を区別する。
- 優先度は「なぜ先か」「何が未確認か」「次に何を確認するか」を平易に示す。source severity、EPSS/KEV の出典と時計、profile/assessment、model reasons/confidence、保存済み期限を展開できる。
- 参考試算は明示 `as_of` と snapshot を残し、保存判断や予定期限を捏造しない。CVE のない Code/Secret/Threat Finding に架空の脆弱性スコアを付けない。
- empty/loading/error/partial/stale/no-access を区別する。色だけで状態を表さず、keyboard focus、ラベル、コントラスト、responsive layout、reduced motion を検証する。

合格条件: 同じ合成 DB に対し Overview の母数、Assets の内訳、Findings の検索結果が一致する。フィルター・paging・Back/Forward・再読込・無効 ID・履歴打切り・長い証拠・空状態を確認し、desktop/mobile の実レンダリング検証を別記録にする。全画面統一の完了を Findings 2 画面だけで宣言しない。

Phase 1 の終了条件: 上記の共通 read/coverage、継続収集の失敗安全性、相関・証拠・優先度の説明、主要画面の導線がオフライン統合テストで成立すること。ライブ接続・scanner 実行の運用受入は実施対象ごとに追加する。共通調査・外部修正など Phase 3 の完了をここで先取りしない。

### 5.6 追加する読取中心の機能案（未実装）

以下の 4 案は計画への追加であり、実装済みの機能や外部操作の許可ではない。既存の Findings API、source-native identity、参考試算、UI を再利用する。新しい live collector、認証情報、通知先、課金・公開範囲の変更を前提にしない。

#### 修正候補ボード

更新・設定変更などの候補を、その根拠と対象 Finding/Asset に結び付けて並べる。最初は読取専用とし、検証できる package identity/version、修正版、対象、検出元、観測時刻、既存 Issue/PR 参照だけを使う。外部操作と再検査を扱う第 7.1 節の Action 管理とは分離する。

合格条件: 同じ CVE や package 名だけで別 Asset・環境・版を統合しない。根拠が揃う範囲だけ同じ候補としてまとめ、元の Finding と履歴を保つ。欠損・古い証拠・部分取得を明示し、候補件数を修正可能件数や一括解消件数と呼ばない。ページ内集計と全体集計を区別し、合成データ・読取不変試験で確認する。自動修正、Issue/PR 作成・merge、triage/解消変更はこの工程に含めない。

#### Findings の保存検索

頻繁に使う検出元・重要度・Asset・CVE・source status 等の条件を名前付きで保存・再実行する。保存するのは条件であり、結果 snapshot ではない。KEV/EPSS の条件を追加する場合は、陽性・陰性・欠落・古い証拠・対象外を区別する。既存 filter/parser を再利用する。

合格条件: 条件 schema/version、空・不正・廃止 filter、更新・削除・競合、Back/Forward/reload を検証する。実行時刻・証拠の鮮度・件数範囲を示し、KEV 欠落を陰性や安全と扱わない。保存場所・所有者 scope を実装前に定め、利用者をまたぐ共有を既定にしない。server-side 保存を選ぶ場合は Web 認可契約を前提とする。秘密値や raw payload を保存条件・名前・URL に含めない。自動通知・定期実行・公開リンクは別工程とする。

#### Dependabot と Trivy の比較

元 Finding/Asset、source-native ID、repository/commit または image digest/対象 path、package identity/version、CVE、観測時刻、収集 scope/完全性を並べ、共通点・差分・比較不能な理由を示す。既存の same-CVE 関連 API は参考関連として再利用し、厳密な対象一致と区別する。

合格条件: 同じ CVE でも別 Asset・環境・版・時刻の観測を同一状態と扱わない。片方に無いだけで解消・未検出・製品の優劣を断定しない。部分取得、未 scan、古い観測、identity 不一致を合成 fixture で区別し、根拠が不足する組合せは比較不能とする。元 Finding/履歴を統合・削除せず、読取専用・件数/入力上限を検証する。collector/scanner 実行や一括 triage は含めない。

#### 優先度の条件比較

第 5.5 節の根拠付き優先度 UI の一部として、同じ Finding/Asset・評価時刻・入力 snapshot を固定し、モデルで扱える明示的な仮定を変えた参考結果を並べる。独立した保存評価エンジンを新設しない。

合格条件: baseline、変更した条件、model/profile/assessment version、as_of、理由・不足情報・差分を表示し、同じ snapshot から CLI/API で再現できる。公開範囲や資産重要度等の仮定と保存済み観測/判断を区別し、モデルに存在しない入力効果を推測しない。別 Asset の assessment、期限切れ・矛盾・欠落入力を検証する。試算だけで永続 risk、実期限、通知抑止、triage/解消を変更しない。

着手順は、既存の読取契約を使える範囲から小さく切り出す。保存検索の所有者 scope、比較の対象一致、候補集約の根拠、試算の入力契約を先に確定し、各案の合成受入と実画面検証を別に記録する。

## 6. Phase 2: AWS の形式別取り込みと同期

### 6.1 ASFF / OCSF / GuardDuty の独立 adapter

AWS の形式を一つの曖昧な JSON として扱わない。最初に外部接続不要の bounded offline adapter を実装する。

- Security Hub CSPM の [ASFF](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) は、ProductArn/Id、AwsAccountId、Region、Resources、RecordState/Workflow 等をその規約で検証する。source workflow と local triage を同一視しない。
- Security Hub の [OCSF](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-ocsf.html) は別 adapter とし、採用する schema version/class、identity、status/severity の mapping を fixture と文書で固定する。ASFF を暗黙変換して OCSF 対応済みとしない。
- GuardDuty finding は account、region、detector と native finding ID、resource、脅威 type、source timestamps を保つ。Security Hub 経由と直接取得の重複は原観測を残して関連付け、CVE がなくても表現できる。
- AWS partition、account ID、region、ARN の service/account/region/resource を識別する。取得元の認可済み scope と payload を照合し、payload の ARN で勝手に接続先を広げない。global resource や region/account が空の ARN はサービス別ルールで扱い、推測で補完しない。
- 標準 severity を写すだけで threat の exploitability を断定しない。未知 field/version、矛盾する identity、過大入力、secret を含み得る free text は fail-closed または明示した限定 projection とする。

合格条件: format ごとの versioned synthetic fixtures、別 account/region/partition、複数 resource、global ARN、同番号 native ID、unknown severity、malformed/conflicting input、replay/rollback/古い観測を検証する。ASFF と OCSF と直接 GuardDuty の source identity を保ち、個別の CVE がないものを CVE 検索へ混入させない。

### 6.2 API / EventBridge と reconciliation

adapter の後に collector を分けて実装する。採用対象の account/region、API、想定量、read/event 権限と費用を確認してから接続する。サービスの有効化、権限作成、全 account の自動探索、課金機能の起動を adapter の副作用にしない。

- API の pagination、差分 cursor、rate limit、途中失敗、完全取得 scope を保存する。停止した region を消滅・解消と扱わない。
- [GuardDuty EventBridge](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_eventbridge.html) 等の envelope と payload、許可 account/region/source/detail-type、入力サイズを照合する。event ID の重複排除と native finding の同一性を分ける。
- 再配信、遅延、順序逆転、欠落を想定し、古い event で新状態を戻さない。event の欠落・未配信は定期 API snapshot で埋め、event stream の沈黙で解消しない。
- queue retry、quarantine、cursor/checkpoint と DB commit の境界を定義する。結果不明の retry は既存 receipt を照合する。

Phase 2 の終了条件: fake AWS API と順序を変えた event fixture で、重複・欠落後の reconciliation が同じ最終状態へ収束し、account/region/ARN で検索・coverage 表示できる。実 account の権限、EventBridge route、費用、実 payload での稼働は別の運用受入で確認する。

## 7. Phase 3: 運用ワークフローと対象領域の拡張

### 7.1 共通トリアージ、調査案件、修正・再検査

共通トリアージを先に作り、その上に investigation と remediation を載せる。予定の `POST /api/v1/findings/{id}/triage` は Web 認証/RBAC、CSRF または API 用認証、監査、idempotency、revision 競合制御が揃ってから追加する。

- `new/triaged/in_progress/risk_accepted/closed` の遷移には actor、理由、時刻、対象 revision を残す。担当、分類、確認事項を保持し、source state を上書きしない。risk_accepted は有効な例外を参照する。
- bulk 操作は対象一覧と部分成功/失敗を明示し、scope 外や途中に変更された対象を黙って処理しない。同じ idempotency key の異なる要求は conflict とする。
- Investigation は複数 Finding/Asset を紐付ける一つの調査案件であり、Finding を統合しない。owner、status、timeline、仮説、証拠参照、判断、次の行動、関連案件を記録する。case を閉じても所属 Finding を一律に解消しない。
- Remediation Action は計画、承認待ち、実行中、成功、失敗、結果不明、取消などを区別する。Issue/PR URL、対象 commit/resource、提案差分、実行 receipt と再検査を関連付ける。
- Issue 作成、PR 作成・マージ、設定変更などは対象・操作・差分・影響・承認者を明確にし、実行直前に権限と最新状態を再検査する。AI は提案と根拠を返し、外部変更を独断で行わない。
- 再検査は同じ対象 scope と新しい検査証拠を結ぶ。新 artifact/version への置換も明示する。Action 成功、PR merge、スキャン失敗だけで解消しない。明示 source 解消または完全性を満たす検査で確認する。

合格条件: 合成 principal と fake action provider で不許可、期限切れ承認、変更後の古い承認、二重送信、通信切断で結果不明、部分失敗、再発を検証する。調査→承認→fake 修正→再検査→完了まで履歴が切れず、未確認の結果を成功扱いしない。

### 7.2 共通 SLA・例外管理

既存 risk の期限・再発案件を土台に、ソース横断の policy 適用を追加する。異なる asset/profile/source の期限を同一 CVE だけで共有しない。

- policy version、対象 scope、優先度、起算 event、期限、計算根拠を保存する。時刻は UTC で保持し、表示 zone を明記する。
- 同一案件の再評価で期限を延ばさず、緊急度上昇時の前倒し規約を維持する。policy 変更、再発、新規案件の期限は履歴と別に説明する。
- 例外は対象、理由、承認者、開始/期限、証拠、補完策、見直し条件を持つ。停止・延長を許す SLA 条件を明示し、例外があるだけで無期限に停止しない。
- 例外の失効・撤回・対象変更時は再評価し、source status を変更せず通知する。source の false_positive/suppressed と組織の受容を分ける。

合格条件: 固定時計で期限境界、risk 上昇、例外の重複・失効・撤回、policy 更新、解消・再発を再現する。legacy の期限と履歴は変更せず、共通 policy の対象外を明示する。

### 7.3 ソース横断通知

既存の Slack/Discord バッチを拡張し、finding/priority/coverage failure/overdue/exception/action の共通 event を受ける。

- 宛先、受信対象 scope、severity/priority、集約窓、重複抑制、初期大量取り込みの扱い、送信時の権限・監視判定を明示する。新しい source の導入で無条件に通知を開始しない。
- 送信待ちと delivery receipt を永続化し、再起動・失敗時に再開する。first deadline を後続 event で延ばさない。成功後に応答を失った場合は「結果不明」と照合手段を持つ。
- source の raw payload、secret、不要な個人情報を通知本文に出さない。詳細はアクセス制御された UI の正しい object にリンクする。外部ボタンの操作にも最新の承認・対象検査を適用する。

合格条件: fake sender で restart、宛先分離、対象除外、重複 event、送信中の更新、429、成功後の DB 保存失敗を再現する。未知の送信結果を「重複なし」と保証せず、既存の通知 ID・バッチ期限を壊さない。

### 7.4 WAF: provider と集約方法を選んでから実装

AWS WAF / Cloudflare WAF は候補であり、利用中・採用済みとはみなさない。最初の成果物は選定記録と共通 aggregate 契約とする。対象 provider、取得 API または集計ログ、plan/費用、retention、粒度、個人情報、rate limit、必要権限、検知の目的を比較する。

- 生 request ごとに Finding を作らない。web ACL/zone、rule、時間窓、action、集計 count 等の bounded event と、要調査の aggregate を分ける。
- provider/account/region または zone と window を identity に含め、重複 window、遅延到着、補正値、部分集計を扱う。block 件数の増加だけで侵害を断定しない。
- request body、cookie、token、不要な IP/URL query を common store や通知へ保存しない。生ログが必要なら別の保護された保管方式を選ぶ。

合格条件: 選んだ provider の synthetic aggregate を再送・重複・遅延・欠損させても正しい window に反映し、partial とゼロ件を分ける。実ログ接続と費用確認は別 gate にする。

### 7.5 SBOM: 監視方式と format の選定

Dependency-Track 等への API 接続と、ローカル SBOM の継続照合は別案として比較する。サービス導入を前提にしない。採用記録に必要 format/version（CycloneDX/SPDX 等）、component identity、脆弱性照合元、更新周期、false positive の扱い、費用と情報送信範囲を残す。

- SBOM は対象 artifact digest/release/commit と結び、component の purl/CPE/name/version、document identity、生成元と時刻を保持する。component 一致を都合よく補完しない。
- SBOM 更新と脆弱性 feed 更新の双方で再評価する。component 除去、version 更新、再発を履歴として残す。脆弱性のない SBOM と不完全な component 解析を区別する。
- CVE の候補照合はインストール影響の確定と分け、同じ component が別 asset にある場合の対応状態を共有しない。license/compliance を扱うなら別 policy にする。

合格条件: versioned synthetic SBOM の順序逆転、同じ digest の conflict、component 追加/除去、曖昧 ID、feed 差分、空・不完全 document を検証する。選定前の format や外部サービスを対応済みと表示しない。

### 7.6 傾向分析と性能

日次などの明示 window と対象 scope で、新規/解消/再発、age、期限超過、対応時間、source/asset/category 別の推移を示す。coverage の変化や大量 backfill を注記し、未収集による件数減をリスク改善と呼ばない。

- event/history に基づく as-of 集計と現在値を区別する。例外・対象外・未接続の分母、timezone と window 境界を定義する。
- N+1 query、巨大 raw JSON load、無制限 history を避け、索引・pagination・bounded export を使う。API latency、query plan、DB サイズ、ingest throughput、queue lag を測る。
- 計測は合成データの件数・分布・期間・実行資源・query・反復数を固定する。受入予算を先に設定し、変更前後の p50/p95・最大メモリ・取り込み速度を比較する。未測定の SLA 数値を保証しない。
- PostgreSQL/worker 分離は複数 writer、可用性、実測したボトルネックを根拠に判断し、最初から必須にしない。

Phase 3 の終了条件: 合成の複数領域 Finding から調査案件を作り、権限・承認付きの fake 修正、再検査、例外失効、期限・通知、傾向集計まで一貫して追える。WAF/SBOM は採用対象の明示契約を満たす。外部変更の実行可否は個別に判断する。

## 8. 全工程に必要なセキュリティと運用

### 8.1 Web 認証・RBAC は GitHub 認証と別

GitHub credential context は collector/updater/action がどの GitHub principal を使うかの問題であり、ブラウザー利用者を認証・認可しない。Web の全体仕様では、認証方式と trust boundary を選定し、Viewer/Analyst/Admin と scope を server-side で適用する。

- 既定 loopback を維持する。認証・TLS を確認する前に非 loopback 公開や CORS 緩和を行わない。
- 採用する reverse proxy/IdP/session 方式で principal を検証し、任意 client header による impersonation を防ぐ。session expiry/revocation、cookie の Secure/HttpOnly/SameSite、CSRF、origin 検査を設計する。
- UI のボタン非表示だけでなく、read/write API、旧 mutating route、接続設定、承認、TUI control の各境界に権限を適用する。API token を導入する場合は別の認証・保管要件を定める。
- secret-free のエラー・ログ、権限外 object の非開示、unsafe HTML/Markdown/link の防止、request/response 上限を共通化する。

合格条件: 合成 principal で未認証、期限切れ、別 scope、role 昇格、偽 header、CSRF、旧 route 迂回、二重操作を拒否する。認証方式の offline tests と実 IdP/proxy 設定検証を分ける。

### 8.2 承認・監査と AI の境界

すべての変更要求について actor、target、before/after または変更参照、理由、時刻、idempotency key、revision、承認・実行 receipt を追跡できるようにする。観測と監査の保持期間を定義し、秘密値を証跡に入れない。audit の追記性と actor の信頼性を別々に検証する。

承認後に対象や差分が変わったら再承認とし、期限切れ・取消・権限喪失を実行直前にも検査する。AI 評価は非信頼入力を読む隔離された助言であり、collector credential や外部 write 権限を渡さない。AI の出力・source の指示文を承認として扱わない。

### 8.3 backup / restore / 障害・日常運用

- versioned migration、整合 backup、restore、binary/DB 対応関係、rollback 手順を揃える。稼働中 SQLite の本体ファイルだけをコピーしない。
- isolated restore drill で row counts、IDs、観測・audit、評価/期限、通知待ち・送信 ID、approval/action receipt を照合する。restore 後の外部副作用は自動再送せず、既存 receipt と照合する。
- run 中断、queue backlog、DB lock/disk full、破損、backup failure、通知 failure、credential expiry を検知し、safe error code と復旧手順を示す。再起動しても失敗を成功に変えない。
- source ごとの同期遅延、API failure/429、取り込み件数、重複率、queue wait、DB 容量、backup 成功、通知失敗、Web 応答を計測する。logs/metrics に token・raw secret・不要な個人情報を含めない。
- retention と archive は audit/再検査/再発の必要期間を先に定める。容量対策のために唯一の証拠や運用 DB を消さない。
- Linux の unit/integration/race と、Windows/PowerShell、macOS packaging/native runtime の実行記録を分ける。実行できなかった check を pass と書かない。

合格条件: 合成 DB と fake services による停止 backup→破損/失敗注入→restore→整合確認を再現し、queue/action/notification の重複リスクを説明する。運用先の RPO/RTO、容量・性能予算、担当、稼働監視は選んだ環境で測定してから受け入れる。

## 9. 依存順序、検証ゲート、導入判断

実環境の許可待ちで、全コード作業を一律に止める必要はない。schema、pure adapter、読み取り API、mock collector、workflow、UI、業務モデルは合成データで先行できる。

1. **基盤の可視化**: 統合済みの Overview/Assets・native theme と収集状態 read API を土台に、設定 inventory/attempt/liveness の別契約と第 5.6 節の読取機能へ進む。記録 pair の件数を資産の母数へ転用せず、既存 offline slice と ID/時計の規約を固定する。
2. **継続収集と説明**: GitHub context/collector、Trivy CI 契約、common enrichment/永続評価を独立実装し、共通キュー・根拠 UI につなぐ。外部接続は adapter 後に個別確認する。
3. **安全な共通変更**: Web 認証/RBAC、監査、revision/idempotency を整備してから triage、調査、Action、SLA/例外、通知を接続する。read-only 開発はこの完了を待たなくてよい。
4. **対象拡張**: AWS の形式別 offline adapter → fake API/event reconciliation → 許可された account/region の導入。WAF/SBOM は方式選定 → 共通契約 → adapter → 必要なライブ接続の順に進める。
5. **運用受入**: 合成の横断シナリオ、trend/performance、backup/restore を各段階で継続し、実環境へ反映する前に環境固有の gate を追加する。

### 各変更で残す検証記録

- **仕様・静的 gate**: 対象契約、互換性、変更範囲、schema/version、safe defaults、docs/link の整合を確認する。
- **決定的 offline gate**: synthetic fixtures、固定時計、disposable DB、HTTP recorder/fake provider で正常・失敗・replay・race/競合・rollback を確認する。期待結果と実行した test を記録する。
- **統合 gate**: 既存回帰、該当 lint/vet/test/race/build、最終 commit の CI とレビューを確認する。focused pass、未実行、環境制約を区別し、未検証の工程を完了にしない。
- **ライブ/導入 gate**: 対象環境、principal、account/repository/region、data scope、権限・情報送信・費用、backup/rollback、監視を確認する。新認証、永続アクセス、外部副作用、公開、migration、deploy は適切な承認と個別結果を持つ。

マージ可否は最終差分のテスト結果とレビューで判断し、デプロイ可否はさらに対象環境の導入 gate で判断する。「production ready」という一語で未確認項目を隠さない。

## 10. 出典と仕様の読み方

- [原設計 v1.0](https://devsecops-architecture-ggg.mail590137.chatgpt.site/) の目的・データ境界・Phase 0–3 を維持し、本書で実装状況と受入条件を具体化した。
- 実装根拠は第 1 節の各 merged PR と各 slice 文書を優先する。古い slice 文書の「未接続」はその変更の境界であり、後続 slice の存在を否定する意味ではない。
- [GitHub security alerts](https://docs.github.com/en/enterprise-cloud@latest/code-security/concepts/security-at-scale/audit-security-alerts)、[Trivy JSON](https://trivy.dev/docs/latest/configuration/reporting/#json)、[FIRST EPSS](https://www.first.org/epss/data)、[CISA KEV schema](https://github.com/cisagov/kev-data/blob/develop/known_exploited_vulnerabilities_schema.json) を入力契約の一次資料とする。API・scanner・schema の採用 version は各実装で固定し、latest の追従だけに依存しない。
- [ASFF](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html)、[Security Hub OCSF](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-ocsf.html)、[GuardDuty EventBridge](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_eventbridge.html)、[OCSF](https://ocsf.io/) は Phase 2 の形式別設計の根拠であり、サービス契約・権限・採用の証明ではない。

本仕様の追加はドキュメント変更のみであり、既存環境の接続、実データ取得、scanner 実行、認証・権限変更、外部通知、料金発生、migration、deploy を実施するものではない。

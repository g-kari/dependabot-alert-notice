# 公開ロードマップの更新

公開ページ: https://devsecops-implementation-roadmap.mail590137.chatgpt.site/

## 正本と読取

公開状態データの正本は `docs/site-roadmap.json`。Siteは `https://raw.githubusercontent.com/g-kari/devsecops-console/main/docs/site-roadmap.json` を認証なしで読み取る。通常の状態更新ではSiteの再デプロイは不要。初回はSiteに同梱した公開時のスナップショットを表示し、取得成功後は新しいデータへ切り替える。取得失敗時は、そのページで直前に取得成功したスナップショットを保持する。画面の取得状態と確認日時を見る。

## 更新手順

1. 現在のmain・PR・該当コミットCI・工程台帳と担当の最新状況を読む。他の作業者がこのJSONを変更していないか確認し、二重更新を避ける。
2. 公開可能な進捗だけをJSONへ反映する。秘密値、資格情報、非公開の個人情報、実Findingや原文ログ、内部メモは含めない。
3. `checkedAt` は照合時刻。`lastSubstantiveProgressAt` と各工程の `lastProgressAt` は成果・検証・統合が実際に増えた時刻。確認だけで成果時刻や実績ガントを動かさない。活動報告は `activityAt` と別記する。
4. `status` は active / complete / partial / blocked / planned / waiting / decision。complete は説明した限定コード工程だけ。マージ、CI合格、リリース収録、実運用を混同しない。根拠リンクを保持する。
5. 担当、成果、待ち理由、次の行動、依存、最終照合時刻を更新する。古い稼働報告を現在も稼働中と断定しない。期日が承認・確定していなければ `plannedStart` / `plannedEnd` はnull。仮の日程や進捗率を作らない。
6. JSONの構文、schemaVersion=1、工程IDの一意性、必須項目、UTC時刻、https証拠リンク、機密混入を検査する。通常PRで公開し、必要なレビューと該当head CIを確認して統合する。Draft PRは作成しない。
7. 書込結果不明ならPR/head/blobを照合するまで再送しない。競合時は最新mainを読み、他者の情報を保持して統合する。
8. main上のJSONを再取得し、更新内容・commitを照合する。Siteの「最新データを確認」で取得成功と時刻・工程を確認する。未マージや取得失敗を反映完了と報告しない。

## 表示側の境界

Siteは閲覧中に5分ごとに公開JSONを再取得する。これはデータソースの再調査ではない。確認から24時間超は鮮度警告、activeの確認から6時間超は要再確認を表示する。閉じている間の更新は別途設定された作業がこのJSONを更新する必要がある。これは停止断定の閾値ではない。

実績ガントはPR作成からマージまでの観測期間であり、連続作業時間ではない。成果の証拠がない工程へ完了バーを足さない。

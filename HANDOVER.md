# MythoFable 引き継ぎドキュメント

## 概要
最新の Google Gemini 2.5-flash SDK に完全準拠した多段フォールバック型LLM運用（Gemini / OpenRouter / Llama-3.3-70B）をベースとし、無料クォータを無駄にしない「一撃必殺・防御型自律ループ」を確立。Tailscaleによる安全なiPhoneリモート操作と、動画視聴を妨げない「完全休止（Unload）仕様」を統合した、MacBook Air (2014) 向けの超軽量・高機能な自律防衛＆サイバー演習インフラです。

今回の累積アップデートにより、以下の機能が追加・強化されました：

**セキュリティ・監視：**
ヘルスチェック・ログローテーション・Chart.js攻撃統計グラフ・AIエージェント自律レポート・pfctl tableによるOSレベルIPブロック・深刻度別自動対応（HIGH=pfctl+BL / MEDIUM=BLのみ / LOW=記録のみ）・Tailscale(100.64.0.0/10)以外からのport 5000完全遮断・Tailscaleトラフィック監視（proxy_watcher）

**自動化：**
誤検知IP自動解除（auto_recovery）・脆弱性自動検知＆パッチ適用（auto_patcher）・false_positive自動判定・パッチ候補管理UI

**管理画面：**
多画面構成（管理/統計レポート/パッチ候補/ポートテスト/ログ管理/サービス管理/Rescue）・サービス個別一時停止・ログ一括クリア（3世代バックアップ）・リアルタイムサービス状態バッジ表示・HMACトークン認証・プロキシ監視セクション

---

## ディレクトリ構成 (~/gemini_mythos_m/)
- dashboard.py        : Flask管理画面（HTTPS port5000）
- log_watcher.py      : 攻撃ログ監視・深刻度別BL/pfctl登録・AI起動
- gemini_mythos_s.py  : AIエージェント 攻撃解析・レポート生成
- auto_recovery.py    : 誤検知IP自動解除（cron */5）
- auto_patcher.py     : 脆弱性自動検知・パッチ適用（cron 7,37）
- proxy_watcher.py    : Tailscale通信監視（cron 3,13,23,33,43,53）
- health_check.sh     : 死活監視（cron */5）
- patch_candidates/   : パッチ候補保存先
- backups/            : ログバックアップ（3世代管理）
- agent_reports.jsonl : AIレポート（最大500件）
- proxy.log           : プロキシ監視ログ（不審通信のみ）

## 画面・URL構成
- /admin      : 管理画面（メイン）
- /reports    : 統計レポート
- /patches    : パッチ候補管理
- /test_port  : ポートテスト
- /logs       : ログ管理
- /services   : サービス管理
- /rescue     : Rescue Panel
- /health     : 死活監視JSON
- /chart_data : グラフデータAPI

## /admin レイアウト
🔒 MythoFable 管理画面  [📡 /health] [🚨 Rescue]
[📊 統計レポート] [🔧 パッチ候補] [🔬 ポートテスト] [🗂️ ログ管理] [⏸️ サービス管理]
🟢 正常稼働中 | 自動更新: 30秒
[🟢 proxy_watcher] [🟢 auto_recovery] [🟢 auto_patcher] [🟢 health_check] [🟢 log_watcher]
📋 システムログ（直近20行・スクロール）
🔍 プロキシ監視 - 不審な通信（最新20件・スクロール）
📋 現在のpfctlルール（スクロール）
📊 ブロック済みIP一覧（pfctl gemini_block・スクロール）
🔴 ブラックリスト（スクロール）  ⚪ ホワイトリスト（スクロール）

## 自動防御フロー
攻撃検知 → 深刻度判定（HIGH=pfctl+BL / MEDIUM=BLのみ / LOW=記録）
→ AI解析・レポート保存 → false_positive判定 → auto_recovery自動解除
→ auto_patcher脆弱性スキャン → proxy_watcher通信監視

## cronスケジュール（重複なし）
0 * * * *              : orchestrator run_agent.sh
*/5 * * * *            : health_check.sh / auto_recovery.py
7,37 * * * *           : auto_patcher.py
3,13,23,33,43,53 * * * *: proxy_watcher.py
15 8,20 * * *          : dreaming.py
30 8,20 * * *          : agent_log_doctor.py
30 0,6,12,18 * * *     : agent_gemini.py
45 20 * * *            : logrotate

## launchd
- com.gemini-mythos.dashboard  : dashboard.py
- com.gemini-mythos.logwatcher : log_watcher.py
- com.gemini-mythos.pf         : pfctl自動ロード

## セキュリティ
- HTTPS（Tailscale証明書）
- HMACトークン認証（SHA-256・24文字・60秒有効）
- pfctl table gemini_block（動的IPブロック）
- Tailscale(100.64.0.0/10)以外からのport 5000遮断
- SECRET_KEY環境変数必須（フォールバックなし）
- X-Forwarded-For無効化

## アクセスURL
https://hz-k-2mba14.tailb82610.ts.net:5000/admin
https://hz-k-2mba14.tailb82610.ts.net:5000/reports
https://hz-k-2mba14.tailb82610.ts.net:5000/patches
https://hz-k-2mba14.tailb82610.ts.net:5000/test_port
https://hz-k-2mba14.tailb82610.ts.net:5000/logs
https://hz-k-2mba14.tailb82610.ts.net:5000/services
https://hz-k-2mba14.tailb82610.ts.net:5000/rescue
https://hz-k-2mba14.tailb82610.ts.net:5000/health

# MythoFable

MacBook Air上で動く、Tailscale経由のセキュリティ防衛・自動修復システム。不正アクセスの検知・自動ブロック・ログ診断・修正パッチの生成/適用までを一貫して行う。

- ダッシュボード本体: `dashboard.py`(Flask, HTTPS, port 5000)
- アクセス: `https://<tailscale-hostname>:5000/`(Tailscale証明書によるHTTPS)
- 認証: HMACトークン(SHA-256・24文字・60秒有効)

## 主な機能

### 1. アクセス監視・自動防御

- `log_watcher.py`: ログを監視し、深刻度別に自動対応(HIGH=pfctlブロック+ブラックリスト登録、MEDIUM=ブラックリストのみ、LOW=記録のみ)
- `ip_manager.py`: IPのブラックリスト/ホワイトリスト管理
- `pf_setup.sh`: pfctl(macOSファイアウォール)のanchor(`mythofable`)・テーブル(`mythofable_block`/`mythofable_pass`)設定。Tailscale(`100.64.0.0/10`)以外からの対象ポートアクセスをブロック
- `exit_node_monitor.py`: Tailscale Exit Node経由の接続状況を監視(5分毎)
- `proxy_watcher.py`: ネットワークインターフェース上の不審な通信を検知し自動ブロック

### 2. 自動復旧・自動パッチ

- `auto_recovery.py`: 誤検知(false positive)からの自動復旧(5分毎のcron)
- `auto_patcher.py`: 検知した脆弱性・問題に対する修正パッチを生成。正規表現ベースの修正で対応できない場合はOpenCode(無料枠LLM)にフォールバックするが、無料枠モデルは品質にばらつきがあるため自動適用はせず、`patch_candidates/`に保存してダッシュボード(`/patches`)から人手レビュー・承認を必須とする設計
- `health_check.sh`: 各サービスの死活監視

### 3. ダッシュボード画面

`dashboard.py` が提供する主な画面: `/`(admin)、`/rescue`、`/health`、`/access`、`/patches`(パッチ候補一覧・適用)、`/logs`(ログ管理)、`/services`(各サービスの起動/停止)、`/test_port`(ポート到達性テスト)。

## ファイル構成

```
dashboard.py           # Flaskダッシュボード本体(HTTPS, port 5000)
log_watcher.py          # ログ監視・深刻度別自動対応
mythofable_s.py          # セキュリティ関連サブシステム
ip_manager.py             # IPブラックリスト/ホワイトリスト管理
auto_patcher.py            # 自動パッチ生成
auto_recovery.py            # 誤検知からの自動復旧
exit_node_monitor.py         # Tailscale Exit Node監視
proxy_watcher.py               # 不審な通信の監視・自動ブロック
pf_setup.sh, health_check.sh     # pfctl設定・ヘルスチェック
agents/, core/, memory/, tools/, config/, prompts/  # エージェント関連モジュール
patch_candidates/, sandbox/, target_repo/            # 実行時生成物(.gitignore対象)
HANDOVER.md, MYTHOFABLE_MIGRATION.md                  # 移行・引き継ぎ資料(別途参照)
```

## セキュリティ関連ファイル(git管理対象外)

以下は`.gitignore`により意図的にgit追跡対象外にしている(機密情報・実行時データのため):

- `.env`(APIキー等)
- 証明書ファイル(`*.crt` / `*.key` / `*.pem`)
- `*.db`(`memory.db`等)
- `backups/`, `patch_candidates/`, `sandbox/`, `target_repo/`

## 運用上の注意

- 通信は必ずTailscale経由のHTTPSに限定する(pfctlでTailscale以外からのアクセスをブロック済み)
- `dashboard.py`等の主要ファイルはauto_patchのホワイトリスト対象で、オーケストレーター経由での自動修正が可能
- 詳細な移行履歴・引き継ぎ事項は `MYTHOFABLE_MIGRATION.md` / `HANDOVER.md` を参照

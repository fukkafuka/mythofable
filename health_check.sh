#!/bin/bash
# ============================================================
# health_check.sh — ① SecureGuard 死活監視スクリプト
#
# 設定方法（別デバイスまたは同Macで cron に登録）:
#   crontab -e
#   */5 * * * * /Users/fk/MythoFable/health_check.sh >> /Users/fk/MythoFable/health_check.log 2>&1
#
# 同Macで実行する場合: 5分ごとに /health を叩いてダウンを検知
# 別デバイス（iPad等）から Tailscale 経由で実行も可
# ============================================================

set -euo pipefail

HEALTH_URL="https://hz-k-2mba14.tailb82610.ts.net:5000/health"
LOG_FILE="/Users/fk/Logs/health_check.log"
ALERT_FILE="$HOME/MythoFable/health_alert.flag"
WATCHER_LOG="/Users/fk/Logs/watcher_stdout.log"

# ローテーション（1MB超えたら）
rotate_if_needed() {
    local file="$1"
    local max_bytes=1048576  # 1MB
    if [ -f "$file" ] && [ "$(wc -c < "$file")" -gt "$max_bytes" ]; then
        mv "$file" "${file}.1"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ── ログローテーション ──" > "$file"
    fi
}

rotate_if_needed "$LOG_FILE"

NOW=$(date '+%Y-%m-%d %H:%M:%S')

# ────────────────────────────────────────
# /health エンドポイントへリクエスト
# ────────────────────────────────────────
RESPONSE=$(curl -sk \
    --max-time 10 \
    --write-out "\nHTTP_CODE:%{http_code}" \
    "$HEALTH_URL" 2>/dev/null) || RESPONSE="ERROR"

HTTP_CODE=$(echo "$RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2 || echo "000")
BODY=$(echo "$RESPONSE" | grep -v "HTTP_CODE:" || echo "")

# ────────────────────────────────────────
# レスポンス評価
# ────────────────────────────────────────
if [ "$HTTP_CODE" = "200" ]; then
    # 正常
    BLACKLIST_COUNT=$(echo "$BODY" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('blacklist_count',0))" 2>/dev/null || echo "?")
    WATCHER_ALIVE=$(echo "$BODY"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('watcher_alive',False))" 2>/dev/null || echo "?")
    PF_ENABLED=$(echo "$BODY"     | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('pf_enabled',False))" 2>/dev/null || echo "?")

    echo "[$NOW] ✅ OK | HTTP=$HTTP_CODE | blacklist=$BLACKLIST_COUNT | watcher=$WATCHER_ALIVE | pf=$PF_ENABLED"

    # watcher が死んでいたら警告
    if [ "$WATCHER_ALIVE" = "False" ]; then
        echo "[$NOW] ⚠️ WARN: log_watcher.py が停止しています！" | tee -a "$WATCHER_LOG"
        echo "[$NOW] 🔄 log_watcher.py を再起動します..."
        launchctl stop com.mythofable.logwatcher 2>/dev/null || true
        launchctl start com.mythofable.logwatcher 2>/dev/null || true
        echo "[$NOW] ✅ log_watcher.py 再起動コマンド送信"
    fi

    # アラートフラグをクリア（復旧）
    if [ -f "$ALERT_FILE" ]; then
        echo "[$NOW] 🟢 復旧を検知。アラートフラグをクリアします"
        rm -f "$ALERT_FILE"
    fi

else
    # 異常（HTTP エラーまたはタイムアウト）
    echo "[$NOW] ❌ DOWN | HTTP=$HTTP_CODE | URL=$HEALTH_URL"

    # アラートフラグがなければ初回ダウン → 自動復旧試行
    if [ ! -f "$ALERT_FILE" ]; then
        echo "[$NOW] 🚨 初回ダウン検知。自動復旧を試みます..."
        touch "$ALERT_FILE"

        # dashboard.py を再起動
        echo "[$NOW] 🔄 dashboard.py を再起動します..."
        launchctl stop com.mythofable.dashboard 2>/dev/null || true
        sleep 2
        launchctl start com.mythofable.dashboard 2>/dev/null || true
        echo "[$NOW] ✅ dashboard.py 再起動コマンド送信"

        # log_watcher.py も再起動
        launchctl stop com.mythofable.logwatcher 2>/dev/null || true
        sleep 1
        launchctl start com.mythofable.logwatcher 2>/dev/null || true
        echo "[$NOW] ✅ log_watcher.py 再起動コマンド送信"
    else
        echo "[$NOW] ⚠️ 継続ダウン中（復旧試行済み）"
    fi
fi

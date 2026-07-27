#!/bin/bash
# ip_review.sh
# pfctl mythofable_block と blocked_ips.txt の同期確認 + 週次レポート
# cron: 0 9 * * 1 /bin/bash $HOME/MythoFable/ip_review.sh

MYTHOFABLE_DIR="$HOME/MythoFable"
BLOCKED_FILE="$MYTHOFABLE_DIR/blocked_ips.txt"
LOG="$HOME/Logs/health_check.log"
PF_ANCHOR="mythofable"
PF_TABLE="mythofable_block"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" >> "$LOG"
}

notify() {
    osascript -e "display notification \"$1\" with title \"MythoFable IP Review\"" 2>/dev/null
}

# ---------- pfctlテーブルのIP取得 ----------
PF_IPS=$(sudo pfctl -a "$PF_ANCHOR" -t "$PF_TABLE" -T show 2>/dev/null | tr -d ' ')
PF_COUNT=$(echo "$PF_IPS" | grep -c '[0-9]' 2>/dev/null || true)
PF_COUNT=${PF_COUNT:-0}
PF_COUNT=$(echo "$PF_COUNT" | tr -d ' \n')

# ---------- blocked_ips.txtのIP取得 ----------
FILE_IPS=""
FILE_COUNT=0
if [ -f "$BLOCKED_FILE" ]; then
    FILE_IPS=$(grep -v '^$' "$BLOCKED_FILE" | tr -d ' ')
    FILE_COUNT=$(echo "$FILE_IPS" | grep -c '[0-9]' 2>/dev/null || true)
    FILE_COUNT=${FILE_COUNT:-0}
    FILE_COUNT=$(echo "$FILE_COUNT" | tr -d ' \n')
fi

# ---------- 乖離チェック ----------
ONLY_IN_PF=$(comm -23 <(echo "$PF_IPS" | sort) <(echo "$FILE_IPS" | sort) | grep '[0-9]')
ONLY_IN_FILE=$(comm -13 <(echo "$PF_IPS" | sort) <(echo "$FILE_IPS" | sort) | grep '[0-9]')

log "[INFO] ip_review: pfctl=$PF_COUNT件 / blocked_ips.txt=$FILE_COUNT件"

# ---------- 乖離があれば警告 ----------
if [ -n "$ONLY_IN_PF" ]; then
    COUNT=$(echo "$ONLY_IN_PF" | wc -l | tr -d ' \n')
    log "[WARN] ip_review: pfctlのみ存在（blocked_ips.txtに未記録）: ${COUNT}件 → $ONLY_IN_PF"
    notify "⚠️ pfctlにのみ存在するIP: ${COUNT}件（blocked_ips.txtに未記録）"
fi

if [ -n "$ONLY_IN_FILE" ]; then
    COUNT=$(echo "$ONLY_IN_FILE" | wc -l | tr -d ' \n')
    log "[WARN] ip_review: blocked_ips.txtのみ存在（pfctlに未反映）: ${COUNT}件 → $ONLY_IN_FILE"
    notify "⚠️ pfctlに未反映のIP: ${COUNT}件"
fi

# ---------- 週次サマリー通知（件数が0でも送る） ----------
if [ "$PF_COUNT" -eq 0 ] && [ "$FILE_COUNT" -eq 0 ]; then
    log "[INFO] ip_review: ブロックIP 0件（正常）"
else
    MSG="ブロックIP: pfctl=${PF_COUNT}件 / ファイル=${FILE_COUNT}件"
    notify "🛡️ $MSG"
    log "[INFO] ip_review: $MSG"
    # IP一覧をログに残す
    if [ -n "$PF_IPS" ] && echo "$PF_IPS" | grep -q '[0-9]'; then
        log "[INFO] ip_review: ブロック中IP一覧: $(echo $PF_IPS | tr '\n' ' ')"
    fi
fi

#!/bin/bash
# ============================================================
# pf_setup.sh — ⑥ pfctl table セットアップ（macOS用）
#
# 実行方法:
#   chmod +x ~/MythoFable/pf_setup.sh
#   sudo ~/MythoFable/pf_setup.sh
#
# 効果:
#   - /etc/pf.conf に mythofable_block テーブルとアンカーを追加
#   - log_watcher.py が "pfctl -t mythofable_block -T add <IP>"
#     コマンドを使ってOSレベルでIPをブロックできるようになる
#   - Mac再起動後も launchd で自動的に pfctl が読み込まれる
# ============================================================

set -e

TABLE_NAME="mythofable_block"
PF_CONF="/etc/pf.conf"
ANCHOR_NAME="mythofable"
PF_ANCHOR_CONF="/etc/pf.anchors/mythofable"
PLIST_PATH="/Library/LaunchDaemons/com.mythofable.pf.plist"

echo "=== SecureGuard pfctl table セットアップ ==="

# ────────────────────────────────────────
# 1. アンカーファイルを作成
# ────────────────────────────────────────
echo "[1/4] アンカーファイルを作成: $PF_ANCHOR_CONF"
cat > "$PF_ANCHOR_CONF" <<ANCHOR
# SecureGuard — 攻撃者IPブロックテーブル
table <${TABLE_NAME}> persist
block drop in quick from <${TABLE_NAME}> to any
block drop out quick from any to <${TABLE_NAME}>
ANCHOR
echo "    ✅ アンカーファイル作成完了"

# ────────────────────────────────────────
# 2. /etc/pf.conf にアンカー参照を追加（重複防止）
# ────────────────────────────────────────
echo "[2/4] /etc/pf.conf にアンカーを追加..."
if grep -q "${ANCHOR_NAME}" "$PF_CONF"; then
    echo "    ⏭ 既に設定済み（スキップ）"
else
    # バックアップ
    cp "$PF_CONF" "${PF_CONF}.bak.$(date +%Y%m%d_%H%M%S)"
    cat >> "$PF_CONF" <<PFCONF

# === SecureGuard ===
anchor "${ANCHOR_NAME}"
load anchor "${ANCHOR_NAME}" from "${PF_ANCHOR_CONF}"
PFCONF
    echo "    ✅ /etc/pf.conf 更新完了"
fi

# ────────────────────────────────────────
# 3. pfctl をリロードして有効化
# ────────────────────────────────────────
echo "[3/4] pfctl をリロード..."
pfctl -f "$PF_CONF" 2>/dev/null && echo "    ✅ pf.conf リロード完了"
pfctl -e 2>/dev/null && echo "    ✅ pfctl 有効化完了" || echo "    ℹ️ pfctl は既に有効"

# ────────────────────────────────────────
# 4. 再起動後も pfctl を自動ロードする LaunchDaemon
# ────────────────────────────────────────
echo "[4/4] LaunchDaemon を設定: $PLIST_PATH"
cat > "$PLIST_PATH" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.mythofable.pf</string>
    <key>ProgramArguments</key>
    <array>
        <string>/sbin/pfctl</string>
        <string>-f</string>
        <string>/etc/pf.conf</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/mythofable-pf.log</string>
</dict>
</plist>
PLIST

# LaunchDaemon を読み込む
launchctl load "$PLIST_PATH" 2>/dev/null && echo "    ✅ LaunchDaemon 登録完了" \
    || echo "    ⚠️ LaunchDaemon は既にロード済み（正常）"

# ────────────────────────────────────────
# 完了メッセージ
# ────────────────────────────────────────
echo ""
echo "=== セットアップ完了 ==="
echo ""
echo "テーブルの確認コマンド:"
echo "  sudo pfctl -t ${TABLE_NAME} -T show"
echo ""
echo "IPを手動で追加するコマンド:"
echo "  sudo pfctl -t ${TABLE_NAME} -T add 1.2.3.4"
echo ""
echo "IPを手動で削除するコマンド:"
echo "  sudo pfctl -t ${TABLE_NAME} -T delete 1.2.3.4"
echo ""
echo "pfctl の状態確認:"
echo "  sudo pfctl -s info"
echo "  sudo pfctl -s rules"

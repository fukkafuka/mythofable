#!/bin/bash
# ============================================================
# deploy.sh — SecureGuard 更新版デプロイスクリプト
#
# 実行方法:
#   chmod +x ~/MythoFable/deploy.sh
#   ~/MythoFable/deploy.sh
# ============================================================

set -e

DEPLOY_DIR="$HOME/MythoFable"
UPDATE_DIR="$(dirname "$0")"  # このスクリプトと同じディレクトリ
BACKUP_DIR="$DEPLOY_DIR/backups/pre_update_$(date +%Y%m%d_%H%M%S)"

echo "=== SecureGuard デプロイ開始 ==="
echo ""

# ────────────────────────────────────────
# 1. デプロイ前バックアップ
# ────────────────────────────────────────
echo "[1/5] デプロイ前バックアップ: $BACKUP_DIR"
mkdir -p "$BACKUP_DIR"
for f in dashboard.py log_watcher.py mythofable_s.py; do
    [ -f "$DEPLOY_DIR/$f" ] && cp "$DEPLOY_DIR/$f" "$BACKUP_DIR/"
done
echo "    ✅ バックアップ完了"

# ────────────────────────────────────────
# 2. サービス停止
# ────────────────────────────────────────
echo "[2/5] サービス停止..."
launchctl stop com.mythofable.dashboard  2>/dev/null && echo "    ✅ dashboard 停止" || echo "    ⏭ dashboard は既に停止"
launchctl stop com.mythofable.logwatcher 2>/dev/null && echo "    ✅ logwatcher 停止" || echo "    ⏭ logwatcher は既に停止"
sleep 2

# ────────────────────────────────────────
# 3. ファイルをデプロイ
# ────────────────────────────────────────
echo "[3/5] ファイルをデプロイ..."
cp "$UPDATE_DIR/dashboard.py"       "$DEPLOY_DIR/dashboard.py"
cp "$UPDATE_DIR/log_watcher.py"     "$DEPLOY_DIR/log_watcher.py"
cp "$UPDATE_DIR/mythofable_s.py" "$DEPLOY_DIR/mythofable_s.py"
chmod +x "$UPDATE_DIR/health_check.sh"
cp "$UPDATE_DIR/health_check.sh"    "$DEPLOY_DIR/health_check.sh"
chmod +x "$DEPLOY_DIR/health_check.sh"
echo "    ✅ Python ファイル デプロイ完了"

# pf_setup.sh もコピー
cp "$UPDATE_DIR/pf_setup.sh" "$DEPLOY_DIR/pf_setup.sh"
chmod +x "$DEPLOY_DIR/pf_setup.sh"
echo "    ✅ pf_setup.sh コピー完了"

# ────────────────────────────────────────
# 4. サービス再起動
# ────────────────────────────────────────
echo "[4/5] サービス再起動..."
launchctl start com.mythofable.dashboard  && echo "    ✅ dashboard 起動"
sleep 1
launchctl start com.mythofable.logwatcher && echo "    ✅ logwatcher 起動"

# ────────────────────────────────────────
# 5. cron に health_check.sh を登録
# ────────────────────────────────────────
echo "[5/5] cron に health_check.sh を登録..."
CRON_ENTRY="*/5 * * * * $DEPLOY_DIR/health_check.sh >> $DEPLOY_DIR/health_check.log 2>&1"
# 重複登録防止
EXISTING=$(crontab -l 2>/dev/null || echo "")
if echo "$EXISTING" | grep -q "health_check.sh"; then
    echo "    ⏭ cron は既に登録済み（スキップ）"
else
    (echo "$EXISTING"; echo "$CRON_ENTRY") | crontab -
    echo "    ✅ cron 登録完了（5分ごとに死活監視）"
fi

# ────────────────────────────────────────
# 完了
# ────────────────────────────────────────
echo ""
echo "=== デプロイ完了 ==="
echo ""
echo "次のステップ（初回のみ）:"
echo "  ⑥ pfctl table セットアップ:"
echo "     sudo $DEPLOY_DIR/pf_setup.sh"
echo ""
echo "確認コマンド:"
echo "  tail -f $DEPLOY_DIR/watcher_stdout.log"
echo "  tail -f $DEPLOY_DIR/agent_stdout.log"
echo "  curl -sk https://hz-k-2mba14.tailb82610.ts.net:5000/health | python3 -m json.tool"
echo ""
echo "ロールバック:"
echo "  cp $BACKUP_DIR/*.py $DEPLOY_DIR/"

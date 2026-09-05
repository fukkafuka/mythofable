"""
mythofable_s.py — SecureGuard AIエージェント

⑤ 自律ループ強化版
- 攻撃ログを解析してパターンを分類
- 対応アクションを判断・記録
- agent_reports.jsonl にレポートを書き出し（ダッシュボードで表示）
- core.loop が存在すれば従来の run_loop() も実行
"""

import os
import sys
import re
import json
import datetime
import hashlib

AGENT_DIR          = os.path.expanduser("~/MythoFable")
BLACKLIST_FILE     = os.path.join(AGENT_DIR, "blocked_ips.txt")
WHITELIST_FILE     = os.path.join(AGENT_DIR, "whitelist.txt")
AGENT_REPORTS_FILE = os.path.join(AGENT_DIR, "agent_reports.jsonl")
AGENT_LOG          = "/Users/fk/Logs/agent_stdout.log"

# レポートは最大500件（古いものから削除）
MAX_REPORTS = 500

# ─────────────────────────────────────────
# ユーティリティ
# ─────────────────────────────────────────
_SANITIZER_PATH = os.path.expanduser("~/.config/ai-keys")
if _SANITIZER_PATH not in sys.path:
    sys.path.insert(0, _SANITIZER_PATH)
try:
    from secret_sanitizer import sanitize_secrets as _sanitize_secrets
except Exception:
    def _sanitize_secrets(text):
        return text

def log(msg):
    msg = _sanitize_secrets(str(msg))
    now = datetime.datetime.now().strftime("%H:%M:%S")
    line = f"[{now}] [AGENT] {msg}"
    print(line)

def read_file_lines(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip()]

# ─────────────────────────────────────────
# ⑤ 攻撃ログ解析
# ─────────────────────────────────────────

# 攻撃パターン辞書 (pattern_name, regex, severity, description)
ATTACK_PATTERNS = [
    ("SQL_INJECTION_UNION",   r"union\s+select|union\s+all\s+select",
     "HIGH",   "UNION SELECT によるSQLインジェクション"),
    ("SQL_INJECTION_BASIC",   r"'|%27|--|;--|\bOR\b\s+1=1|\bAND\b\s+1=1",
     "HIGH",   "基本的なSQLインジェクション"),
    ("SQL_INJECTION_SLEEP",   r"sleep\s*\(|benchmark\s*\(|waitfor\s+delay",
     "HIGH",   "時間ベースのブラインドSQLインジェクション"),
    ("XSS_SCRIPT",            r"<script|javascript:|onerror=|onload=",
     "MEDIUM", "クロスサイトスクリプティング（XSS）"),
    ("PATH_TRAVERSAL",        r"\.\./|\.\.\\|%2e%2e",
     "MEDIUM", "パストラバーサル攻撃"),
    ("CMD_INJECTION",         r";.*?(ls|cat|id|whoami|pwd|wget|curl)|`[^`]+`|\$\([^)]+\)",
     "HIGH",   "コマンドインジェクション"),
    ("BRUTE_FORCE_LOGIN",     r"username=.*&password=|login.*username=",
     "MEDIUM", "ブルートフォース・ログイン試行"),
    ("SCANNER_PROBE",         r"\.php\?|\.asp\?|wp-admin|phpmyadmin|\.env",
     "LOW",    "スキャナーによる探索"),
    ("FILE_INCLUDE",          r"=http://|=ftp://|include.*=.*\.\./",
     "HIGH",   "リモートファイルインクルード（RFI）"),
    ("ADMIN_PROBE",           r"/admin|/administrator|/manager|/panel",
     "LOW",    "管理画面への不正アクセス試行"),
]

def analyze_attack_line(line):
    """1行の攻撃ログを解析してパターンを返す"""
    lower = line.lower()
    matched = []
    for name, pattern, severity, desc in ATTACK_PATTERNS:
        if re.search(pattern, lower, re.IGNORECASE):
            matched.append({"name": name, "severity": severity, "desc": desc})
    return matched

def extract_ip(line):
    """ログ行からIPアドレスを抽出"""
    m = re.match(r"^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", line)
    if m:
        return m.group(1)
    m6 = re.match(r"^([0-9a-fA-F:]{3,})", line)
    if m6:
        return m6.group(1)
    return "UNKNOWN"

def extract_url(line):
    """ログ行からURLパスを抽出"""
    m = re.search(r'"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\s"]+)', line)
    if m:
        return m.group(1)
    return ""

def determine_severity(patterns):
    """検知パターン群から最高severityを返す"""
    if any(p["severity"] == "HIGH" for p in patterns):
        return "HIGH"
    if any(p["severity"] == "MEDIUM" for p in patterns):
        return "MEDIUM"
    return "LOW"

def determine_actions(patterns, ip, blacklist):
    """対応アクションを決定する"""
    actions = []
    severity = determine_severity(patterns)

    if ip in blacklist:
        actions.append("blacklist登録済み（既存）")
    else:
        actions.append("blacklist登録済み（今回）")

    if severity == "HIGH":
        actions.append("pfctl OSレベルブロック")
        actions.append("緊急フラグ設定")
    elif severity == "MEDIUM":
        actions.append("pfctl OSレベルブロック")
    else:
        actions.append("ログ記録のみ")

    return actions

def build_summary(patterns, url, line):
    """レポートサマリーを生成"""
    lines = []
    if patterns:
        lines.append("【検知パターン】")
        for p in patterns:
            lines.append(f"  • [{p['severity']}] {p['name']}: {p['desc']}")
    else:
        lines.append("【検知】未分類の攻撃パターン")

    if url:
        # URLは長すぎる場合は切り詰め
        short_url = url if len(url) <= 120 else url[:117] + "..."
        lines.append(f"【URL】{short_url}")

    # 元ログの先頭100文字
    lines.append(f"【ログ】{line[:100]}{'...' if len(line) > 100 else ''}")
    return "\n".join(lines)

# ─────────────────────────────────────────
# ⑤ レポート書き込み
# ─────────────────────────────────────────
def save_report(report):
    """agent_reports.jsonl にレポートを追記し、上限を超えたら古いものを削除"""
    # 既存レポートを読み込み
    existing = []
    if os.path.exists(AGENT_REPORTS_FILE):
        with open(AGENT_REPORTS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        existing.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass

    existing.append(report)

    # 上限超えたら古いものを削除
    if len(existing) > MAX_REPORTS:
        existing = existing[-MAX_REPORTS:]

    with open(AGENT_REPORTS_FILE, "w", encoding="utf-8") as f:
        for r in existing:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

# ─────────────────────────────────────────
# ⑤ メイン解析処理
# ─────────────────────────────────────────
def analyze_and_report(attack_log_path):
    """攻撃ログを解析してレポートを生成・保存する"""
    if not os.path.exists(attack_log_path):
        log(f"攻撃ログが見つかりません: {attack_log_path}")
        return

    blacklist = read_file_lines(BLACKLIST_FILE)

    with open(attack_log_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    if not lines:
        log("攻撃ログが空です")
        return

    # 最新の攻撃ログ行を処理（重複は報告IDで管理）
    # 既存レポートのIDセットを取得して重複処理を防ぐ
    existing_ids = set()
    if os.path.exists(AGENT_REPORTS_FILE):
        with open(AGENT_REPORTS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    r = json.loads(line.strip())
                    existing_ids.add(r.get("report_id", ""))
                except Exception:
                    pass

    new_reports = 0
    for raw_line in lines:
        raw_line = raw_line.strip()
        if not raw_line:
            continue

        # レポートIDを生成（同一行の重複処理を防ぐ）
        report_id = hashlib.md5(raw_line.encode()).hexdigest()[:12]
        if report_id in existing_ids:
            continue

        attacker_ip = extract_ip(raw_line)
        url         = extract_url(raw_line)
        patterns    = analyze_attack_line(raw_line)
        severity    = determine_severity(patterns) if patterns else "LOW"
        actions     = determine_actions(patterns, attacker_ip, blacklist)
        summary     = build_summary(patterns, url, raw_line)

        # 誤検知判定: パターンなし かつ LOW → false_positive候補
        fp = (len(patterns) == 0 and severity == "LOW")

        report = {
            "report_id"    : report_id,
            "timestamp"    : datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "attacker_ip"  : attacker_ip,
            "severity"     : severity,
            "patterns"     : [p["name"] for p in patterns],
            "summary"      : summary,
            "actions"      : actions,
            "raw_log"      : raw_line[:200],
            "false_positive": fp,
            "recovered"    : False,
        }

        save_report(report)
        existing_ids.add(report_id)
        new_reports += 1

        log(f"📋 レポート生成 [{severity}] IP={attacker_ip} パターン={[p['name'] for p in patterns]}")

    if new_reports > 0:
        log(f"✅ {new_reports}件のレポートを agent_reports.jsonl に保存しました")
    else:
        log("新しい攻撃ログなし（全て処理済み）")

# ─────────────────────────────────────────
# エントリポイント
# ─────────────────────────────────────────
def main():
    log("=== SecureGuard AIエージェント 起動 ===")

    # コマンドライン引数: 攻撃ログパス
    attack_log = None
    if len(sys.argv) >= 2:
        attack_log = sys.argv[1]
        log(f"攻撃ログ: {attack_log}")
        analyze_and_report(attack_log)
    else:
        log("引数なし（攻撃ログ未指定）")

    # ★ Step⑥ 長期自律実行: タスク再開 or 新規作成
    try:
        from core.loop import run_loop
        from memory.store import (
            get_resumable_task, create_task, cleanup_old_tasks
        )

        cleanup_old_tasks(days=7)  # 古いタスクを定期削除

        task_id = None
        if attack_log:
            # 再開可能な未完了タスクを確認
            resumable = get_resumable_task(attack_log)
            if resumable:
                task_id, resume_phase, resume_ctx, resume_goals = resumable
                log(f"♻️ タスク再開: {task_id} (前回フェーズ: {resume_phase})")
            else:
                task_id = create_task(attack_log)
                log(f"🆕 新規タスク作成: {task_id}")

        log("core.loop を呼び出します...")
        run_loop(task_id=task_id)

    except ImportError:
        log("core.loop は未インストール（スタンドアロンモードで動作）")
    except Exception as e:
        log(f"core.loop エラー: {e}")

    log("=== AIエージェント 終了 ===")

if __name__ == "__main__":
    main()

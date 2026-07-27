import os
import time
import subprocess
import re
import datetime

WATCH_LOG      = "/Users/fk/Logs/dashboard.log"
BLACKLIST_FILE = os.path.expanduser("~/MythoFable/blocked_ips.txt")
WHITELIST_FILE = os.path.expanduser("~/MythoFable/whitelist.txt")
WATCHER_LOG    = "/Users/fk/Logs/watcher_stdout.log"
AGENT_DIR      = os.path.expanduser("~/MythoFable")

# ⑥ pfctl table名（/etc/pf.conf と pf_setup.sh で設定済みのもの）
PF_TABLE_NAME  = "mythofable_block"

def extract_port(line):
    """ログ行から送信元ポートを抽出"""
    import re
    # フォーマット: IP - - [日時] "METHOD /path HTTP/1.1" status -
    # 送信元ポートはdashboard.logに含まれないため宛先port(5000)を記録
    # 送信元ポートが含まれる場合は抽出
    m = re.search(r':(\d{2,5})\s*-\s*-\s*\[', line)
    if m:
        return m.group(1)
    return "5000"  # デフォルトはMythoFableのport

# ─────────────────────────────────────────
# 深刻度クイック判定（BL/pfctl判断用）
# ─────────────────────────────────────────
_SEV_HIGH = [
    r"union\s+select", r"sleep\s*\(", r"benchmark\s*\(", r"waitfor\s+delay",
    r";.{0,30}(ls|cat|id|whoami|wget|curl)", r"=http://", r"=ftp://",
    r"`[^`]+`", r"\$\([^)]+\)",
    r"'\s*(or|and)\s*'?\d", r"'--", r"%27--", r"'\s*or\s*'1'='1",
    r"drop\s+table", r"insert\s+into", r"delete\s+from", r"update\s+set",
    r"exec\s*\(", r"xp_cmdshell", r"/etc/passwd", r"cmd\.exe",
    r"%3cscript", r"%3e.*%3c", r"169\.254\.169\.254",
    r"\$\{jndi:", r"\$\{env:", r"\$\{sys:",
    r"/\.env", r"/\.git", r"/wp-admin", r"/wp-login", r"/phpmyadmin",
    r"/shell\.php", r"/config\.php", r"\.(bak|sql|tar|zip)(\?|$|\s)",
]
_SEV_MEDIUM = [
    r"username=.*&password=", r"login.*username=",
    r"<script", r"javascript:", r"onerror=", r"onload=",
    r"\.\./", r"%2e%2e",
    r"%2f\.\.%2f", r"\.\./\.\./", r"\.\.\.\./",
    r"<!entity", r"<!doctype.*system",
    r"/etc/shadow", r"/proc/self", r"/var/log",
]
import re as _re
def quick_severity(line):
    low = line.lower()
    for p in _SEV_HIGH:
        if _re.search(p, low, _re.IGNORECASE):
            return "HIGH"
    for p in _SEV_MEDIUM:
        if _re.search(p, low, _re.IGNORECASE):
            return "MEDIUM"
    return "LOW"

# ─────────────────────────────────────────
# ② ログローテーション（1MB超えで自動ローテーション、最大3世代）
# ─────────────────────────────────────────
def rotate_log(filepath, max_bytes=1 * 1024 * 1024, backup_count=3):
    """ファイルサイズが上限を超えたらローテーション"""
    if not os.path.exists(filepath):
        return
    if os.path.getsize(filepath) < max_bytes:
        return
    for i in range(backup_count - 1, 0, -1):
        src = f"{filepath}.{i}"
        dst = f"{filepath}.{i + 1}"
        if os.path.exists(src):
            if i + 1 > backup_count:
                os.remove(src)
            else:
                os.rename(src, dst)
    os.rename(filepath, f"{filepath}.1")
    with open(filepath, "w", encoding="utf-8") as f:
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        f.write(f"[{now}] ── ログローテーション実施 ──\n")
    print(f"[ROTATE] 📁 {os.path.basename(filepath)} をローテーションしました")

def watcher_log(msg):
    """watcher_stdout.log への書き込み（ローテーション付き）"""
    rotate_log(WATCHER_LOG)
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{now}] {msg}"
    with open(WATCHER_LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")

# ─────────────────────────────────────────
# ⑥ pfctl table 操作
# ─────────────────────────────────────────
def pf_in_pass_table(ip):
    """mythofable_passテーブルにIPが含まれているか確認"""
    try:
        r = subprocess.run(
            ["/usr/bin/sudo", "/sbin/pfctl", "-a", "mythofable", "-t", "mythofable_pass", "-T", "show"],
            capture_output=True, text=True, timeout=5)
        return ip in r.stdout
    except Exception:
        return False

def pf_table_add(ip):
    """
    pfctl のテーブル mythofable_block へIPを追加してOSレベルでブロック。
    pf_setup.sh で /etc/pf.conf にテーブルとアンカーを設定済みの前提。
    """
    try:
        # テーブルにIP追加（永続的なブロック）
        r = subprocess.run(
            ["sudo", "pfctl", "-a", "mythofable", "-t", PF_TABLE_NAME, "-T", "add", ip],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            watcher_log(f"[PF] 🧱 pfctl table {PF_TABLE_NAME} に {ip} を追加しました")
        else:
            watcher_log(f"[PF] ⚠️ pfctl table add 失敗: {r.stderr.strip()}")
            # テーブルが未設定の場合はフォールバック: 旧来の pfctl -f / -e
            _pf_fallback()
    except Exception as e:
        watcher_log(f"[PF] ⚠️ pfctl 例外: {e}")
        _pf_fallback()

def pf_table_remove(ip):
    """pfctl テーブルからIPを削除（解除時に使用）"""
    try:
        r = subprocess.run(
            ["sudo", "pfctl", "-a", "mythofable", "-t", PF_TABLE_NAME, "-T", "delete", ip],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            watcher_log(f"[PF] 🔓 pfctl table {PF_TABLE_NAME} から {ip} を削除しました")
        else:
            watcher_log(f"[PF] ⚠️ pfctl table delete 失敗: {r.stderr.strip()}")
    except Exception as e:
        watcher_log(f"[PF] ⚠️ pfctl remove 例外: {e}")

def _pf_fallback():
    """テーブルが使えない場合のフォールバック（従来方式）"""
    try:
        subprocess.run(["sudo", "pfctl", "-f", "/etc/pf.conf"], stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "pfctl", "-e"], stderr=subprocess.DEVNULL)
        watcher_log("[PF] 🧱 pfctl フォールバック: /etc/pf.conf をリロードしました")
    except Exception as e:
        watcher_log(f"[PF] ❌ pfctl フォールバックも失敗: {e}")

# ─────────────────────────────────────────
# ユーティリティ
# ─────────────────────────────────────────
def load_list(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip()]

# ─────────────────────────────────────────
# メインループ
# ─────────────────────────────────────────
def watch_log_stream():
    if not os.path.exists(WATCH_LOG):
        with open(WATCH_LOG, "w") as f:
            f.write("")

    watcher_log("[START] 👁 log_watcher 起動しました")

    with open(WATCH_LOG, "r", encoding="utf-8", errors="ignore") as f:
        f.seek(0, os.SEEK_END)
        while True:
            try:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                log_line = line.strip()
                if not log_line:
                    continue

                # 内部ログは無視（無限ループ防止）
                if (log_line.startswith('[') or log_line.startswith('*') or
                        log_line.startswith(' *') or
                        '[DENY]' in log_line or '[ALLOW]' in log_line or
                        '[RESCUE]' in log_line or '[MOVE]' in log_line or
                        '[UNBLOCK]' in log_line):
                    continue

                lower_line = log_line.lower()

                # 攻撃パターン検知
                if "username=" not in lower_line and "'" not in log_line and "%27" not in lower_line:
                    continue

                # IPアドレス取得（IPv4優先、次にIPv6）
                attacker_ip = "UNKNOWN"
                ip_match = re.match(r"^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", log_line)
                if ip_match:
                    attacker_ip = ip_match.group(1).strip()
                else:
                    ip_match6 = re.match(r"^([0-9a-fA-F:]{3,})", log_line)
                    if ip_match6:
                        attacker_ip = ip_match6.group(1).strip()

                if attacker_ip == "UNKNOWN":
                    watcher_log(f"[WARN] 攻撃パターン検知（IP識別不能）: {log_line[:80]}")

                blacklist = load_list(BLACKLIST_FILE)
                whitelist = load_list(WHITELIST_FILE)

                # 深刻度判定
                severity = quick_severity(log_line)

                # 既にblacklist登録済みならスキップ
                if attacker_ip in blacklist:
                    if severity == "HIGH":
                        pf_table_add(attacker_ip)  # pfctl漏れ補完
                    watcher_log(f"[SKIP] {attacker_ip} は既にBL登録済み ({severity})")
                    continue

                attacker_port = extract_port(log_line)
                watcher_log(f"[ALERT] 🚨 攻撃検知！IP: {attacker_ip}:{attacker_port} 深刻度: {severity}")

                if severity == "HIGH":
                    if is_trusted(attacker_ip):
                        watcher_log(f"[TRUST] 🛡️ {attacker_ip} はwhitelist+mythofable_pass登録済みのため全ブロックをスキップ")
                    else:
                        # WLとBLの同時存在を防ぐ: WLから削除してBLへ
                        if attacker_ip in whitelist:
                            whitelist.remove(attacker_ip)
                            with open(WHITELIST_FILE, "w", encoding="utf-8") as wf:
                                for ip in sorted(set(whitelist)):
                                    wf.write(ip + "\n")
                            watcher_log(f"[MOVE] {attacker_ip} WL→BL強制移動")
                        with open(BLACKLIST_FILE, "a", encoding="utf-8") as bf:
                            bf.write(f"{attacker_ip}\n")
                        if pf_in_pass_table(attacker_ip):
                            watcher_log(f"[SKIP] 🛡️ {attacker_ip} はmythofable_passに登録済みのためpfctlブロックをスキップ")
                        else:
                            pf_table_add(attacker_ip)
                        watcher_log(f"[HIGH] 🔴 {attacker_ip}:{attacker_port} pfctl+BLブロック実施")

                elif severity == "MEDIUM":
                    if is_trusted(attacker_ip):
                        watcher_log(f"[TRUST] 🛡️ {attacker_ip} は完全信頼デバイスのためBL登録をスキップ")
                    else:
                        if attacker_ip in whitelist:
                            whitelist.remove(attacker_ip)
                            with open(WHITELIST_FILE, "w", encoding="utf-8") as wf:
                                for ip in sorted(set(whitelist)):
                                    wf.write(ip + "\n")
                            watcher_log(f"[MOVE] {attacker_ip} WL→BL強制移動")
                        with open(BLACKLIST_FILE, "a", encoding="utf-8") as bf:
                            bf.write(f"{attacker_ip}\n")
                        watcher_log(f"[MEDIUM] 🟡 {attacker_ip}:{attacker_port} BLのみ登録（pfctlなし）")

                else:
                    watcher_log(f"[LOW] 🟢 {attacker_ip}:{attacker_port} 記録のみ（ブロックなし）")

                # ⑤ AIエージェントを非同期で起動（攻撃ログと詳細情報を渡す）
                try:
                    venv_python = os.path.join(AGENT_DIR, ".venv/bin/python3")
                    agent_script = os.path.join(AGENT_DIR, "mythofable_s.py")
                    web_attack_log = "/Users/fk/Logs/web_attack.log"
                    agent_log = "/Users/fk/Logs/agent_stdout.log"
                    agent_err = "/Users/fk/Logs/agent_stderr.log"

                    # ② agent_stdout.log のローテーション確認
                    rotate_log(agent_log)

                    # 攻撃ログをweb_attack.logに記録
                    with open(web_attack_log, "a", encoding="utf-8") as waf:
                        waf.write(f"{log_line}\n")

                    # AIエージェントをバックグラウンドで起動
                    cmd = (
                        f"cd {AGENT_DIR} && PYTHONUNBUFFERED=1 "
                        f"{venv_python} -u {agent_script} {web_attack_log} "
                        f">> {agent_log} 2>> {agent_err} &"
                    )
                    subprocess.Popen(cmd, shell=True, cwd=AGENT_DIR)
                    watcher_log(f"[AI] 🤖 AIエージェントを起動しました（攻撃者IP: {attacker_ip}:{attacker_port}）")
                except Exception as e:
                    watcher_log(f"[AI] ⚠️ AIエージェント起動失敗: {e}")

            except Exception as e:
                watcher_log(f"[ERROR] ⚠️ ループ例外（継続）: {e}")
                time.sleep(1)

if __name__ == "__main__":
    watch_log_stream()

#!/usr/bin/env python3
"""
proxy_watcher.py - Tailscale経由トラフィック監視
接続先IP・PORT・ドメインを記録し不審な通信をAIエージェントに通知
cron: */1 * * * * (1分ごとにtcpdumpを実行・解析)
"""
import os, re, subprocess, datetime, json, ipaddress, socket
import sys

BASE_DIR    = os.path.expanduser("~/MythoFable")
PROXY_LOG   = "/Users/fk/Logs/proxy.log"
REPORT_FILE = os.path.join(BASE_DIR, "agent_reports.jsonl")
BLACKLIST   = os.path.join(BASE_DIR, "blocked_ips.txt")
WATCHER_LOG = "/Users/fk/Logs/watcher_stdout.log"
PF_TABLE    = "mythofable_block"
TAILSCALE_IF = "utun5"
CAPTURE_SECS = 55  # 55秒キャプチャ

# 既知の安全なIP・ドメイン（ホワイトリスト）
SAFE_RANGES = [
    "100.64.0.0/10",   # Tailscale
    "100.100.100.0/24",# Tailscale DNS
    "127.0.0.0/8",     # localhost
]

# 不審なポート（通常の通信では使わない）
SUSPICIOUS_PORTS = {
    22, 23, 25, 110, 135, 137, 138, 139, 445,
    1433, 1521, 3306, 3389, 4444, 5900, 6379,
    8080, 8443, 9200, 27017
}

# 許可ポート（通常のインターネット通信）
ALLOWED_PORTS = {80, 443, 53, 123, 5000}

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
    with open(WATCHER_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{now}] [PROXY] {msg}\n")

def proxy_log(entry):
    with open(PROXY_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")

def is_safe_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
        for r in SAFE_RANGES:
            if addr in ipaddress.ip_network(r):
                return True
    except Exception:
        pass
    return False

def resolve_host(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def load_blacklist():
    if not os.path.exists(BLACKLIST):
        return []
    with open(BLACKLIST) as f:
        return [l.strip() for l in f if l.strip()]

def block_ip(ip, reason):
    """IPをpfctl mythofable_blockに追加"""
    try:
        subprocess.run(
            ["/usr/bin/sudo", "/sbin/pfctl", "-a", "mythofable",
             "-t", PF_TABLE, "-T", "add", ip],
            capture_output=True, text=True, timeout=5
        )
        # blacklistにも追加
        bl = load_blacklist()
        if ip not in bl:
            bl.append(ip)
            with open(BLACKLIST, "w") as f:
                for b in sorted(set(bl)):
                    f.write(b + "\n")
        log(f"🚫 自動ブロック: {ip} 理由: {reason}")
    except Exception as e:
        log(f"⚠️ ブロック失敗: {ip} {e}")

def save_report(ip, port, host, reason, severity):
    """agent_reports.jsonlにレポート保存"""
    entry = {
        "timestamp"  : datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "attacker_ip": ip,
        "severity"   : severity,
        "patterns"   : ["PROXY_DETECT"],
        "summary"    : f"[PROXY] {reason} - {ip}:{port}" + (f" ({host})" if host else ""),
        "actions"    : ["proxy監視検知"],
        "false_positive": False,
        "recovered"  : False,
    }
    existing = []
    if os.path.exists(REPORT_FILE):
        with open(REPORT_FILE) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        existing.append(json.loads(line))
                    except Exception:
                        pass
    existing.append(entry)
    if len(existing) > 500:
        existing = existing[-500:]
    with open(REPORT_FILE, "w") as f:
        for r in existing:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

def analyze_traffic(lines):
    """tcpdump出力を解析"""
    connections = {}  # (src_ip, dst_ip, dst_port) → count
    bl = load_blacklist()

    for line in lines:
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="ignore")
        # IP.PORT > IP.PORT パターン
        m = re.search(
            r'(\d+\.\d+\.\d+\.\d+)\.(\d+)\s*>\s*(\d+\.\d+\.\d+\.\d+)\.(\d+)',
            line
        )
        if not m:
            continue
        src_ip, src_port, dst_ip, dst_port = m.group(1), int(m.group(2)), m.group(3), int(m.group(4))

        # Tailscale自身のIPはスキップ
        if src_ip == "100.109.207.78":
            key = (src_ip, dst_ip, dst_port)
            connections[key] = connections.get(key, 0) + 1

    blacklist_ips = set(bl)
    detected = []

    for (src, dst, port), count in connections.items():
        if is_safe_ip(dst):
            continue

        host = resolve_host(dst)
        severity = "LOW"
        reason = ""

        # BL登録済み
        if dst in blacklist_ips:
            reason = "ブラックリスト登録済みIPへの接続"
            severity = "HIGH"

        # 不審なポート
        elif port in SUSPICIOUS_PORTS:
            reason = f"不審なポート({port})への接続"
            severity = "HIGH" if port in {4444, 1433, 3306, 3389} else "MEDIUM"

        # 大量接続（1分間に50回以上）
        elif count >= 50 and port not in ALLOWED_PORTS:
            reason = f"大量接続({count}回/分) port:{port}"
            severity = "MEDIUM"

        if reason:
            detected.append({
                "src": src, "dst": dst, "port": port,
                "count": count, "host": host,
                "reason": reason, "severity": severity
            })

    return detected

def main():
    # 起動ログは出力しない

    # tcpdumpで55秒キャプチャ
    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "/usr/sbin/tcpdump",
             "-i", TAILSCALE_IF, "-n", "-t",
             "-c", "1000",  # 最大1000パケット
             "--immediate-mode"],
            capture_output=True, text=True,
            timeout=CAPTURE_SECS
        )
        lines = result.stdout.splitlines()
    except subprocess.TimeoutExpired as e:
        raw = e.stdout if e.stdout else b""
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="ignore")
        lines = raw.splitlines()
    except Exception as e:
        log(f"❌ tcpdump失敗: {e}")
        return

    if not lines:
        return

    # パケット数ログは出力しない

    # 解析
    detected = analyze_traffic(lines)

    if not detected:
        return

    for d in detected:
        entry = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": d["src"], "dst_ip": d["dst"],
            "dst_port": d["port"], "count": d["count"],
            "host": d["host"], "reason": d["reason"],
            "severity": d["severity"], "action": ""
        }

        if d["severity"] == "HIGH":
            block_ip(d["dst"], d["reason"])
            entry["action"] = "自動ブロック"
            log(f"🔴 HIGH検知→自動ブロック: {d['dst']}:{d['port']} ({d['reason']})")
        elif d["severity"] == "MEDIUM":
            entry["action"] = "要確認"
            log(f"🟡 MEDIUM検知: {d['dst']}:{d['port']} ({d['reason']})")
        else:
            entry["action"] = "記録のみ"
            log(f"🟢 LOW検知: {d['dst']}:{d['port']} ({d['reason']})")

        proxy_log(entry)
        save_report(d["dst"], d["port"], d["host"], d["reason"], d["severity"])

    # 完了ログは出力しない

if __name__ == "__main__":
    main()

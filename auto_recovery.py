#!/usr/bin/env python3
"""
auto_recovery.py - false_positive判定IPの自動解除
cron: */5 * * * * ~/MythoFable/.venv/bin/python3 ~/MythoFable/auto_recovery.py
"""
import os, json, subprocess, datetime

BASE_DIR       = os.path.expanduser("~/MythoFable")
REPORTS_FILE   = os.path.join(BASE_DIR, "agent_reports.jsonl")
BLACKLIST_FILE = os.path.join(BASE_DIR, "blocked_ips.txt")
WATCHER_LOG    = "/Users/fk/Logs/watcher_stdout.log"
PF_TABLE_NAME  = "mythofable_block"

def log(msg):
    now = datetime.datetime.now().strftime("%H:%M:%S")
    with open(WATCHER_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{now}] {msg}\n")

def load_list(path):
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return [l.strip() for l in f if l.strip()]

def save_list(path, items):
    with open(path, "w") as f:
        for ip in sorted(set(items)):
            f.write(ip + "\n")

def pf_remove(ip):
    try:
        r = subprocess.run(
            ["sudo", "pfctl", "-a", "mythofable", "-t", PF_TABLE_NAME, "-T", "delete", ip],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            log(f"[RECOVERY] 🔓 pfctl {ip} を解除しました")
        else:
            log(f"[RECOVERY] ⚠️ pfctl解除失敗: {r.stderr.strip()}")
    except Exception as e:
        log(f"[RECOVERY] ⚠️ pfctl例外: {e}")

def main():
    if not os.path.exists(REPORTS_FILE):
        return

    reports = []
    with open(REPORTS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    reports.append(json.loads(line))
                except Exception:
                    pass

    recovered = []
    for r in reports:
        if r.get("false_positive") is True and not r.get("recovered"):
            ip = r.get("attacker_ip", "")
            if ip and ip != "UNKNOWN":
                bl = load_list(BLACKLIST_FILE)
                if ip in bl:
                    bl.remove(ip)
                    save_list(BLACKLIST_FILE, bl)
                    pf_remove(ip)
                    log(f"[RECOVERY] ✅ {ip} を誤検知として自動解除しました")
                    recovered.append(ip)
                else:
                    log(f"[RECOVERY] ℹ️ {ip} はBL未登録（解除不要）")
            r["recovered"] = True

    if recovered:
        with open(REPORTS_FILE, "w", encoding="utf-8") as f:
            for r in reports:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        log(f"[RECOVERY] 📋 自動解除完了: {len(recovered)}件 {recovered}")

if __name__ == "__main__":
    main()

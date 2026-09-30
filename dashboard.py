import os
import hmac
import hashlib
import datetime
import time
import threading
import subprocess
import json
from flask import Flask, render_template_string, request, Response, redirect

app = Flask(__name__)

BASE_DIR = "/Users/fk/MythoFable"
LOG_FILE           = "/Users/fk/Logs/dashboard.log"
WATCHER_LOG_DISPLAY= "/Users/fk/Logs/watcher_stdout.log"
BLACKLIST_FILE     = os.path.join(BASE_DIR, "blocked_ips.txt")
WHITELIST_FILE     = os.path.join(BASE_DIR, "whitelist.txt")
WATCHER_LOG        = "/Users/fk/Logs/watcher_stdout.log"
AGENT_REPORTS_FILE = os.path.join(BASE_DIR, "agent_reports.jsonl")  # ⑤ Agent reports
REDTEAM_REPORTS_FILE = os.path.join(BASE_DIR, "redteam_reports.jsonl")  # redteam_probe.py出力

SECRET_KEY = os.environ.get('FLASK_SECRET')
if not SECRET_KEY:
    raise RuntimeError('FLASK_SECRET environment variable is not set')

# ─────────────────────────────────────────
# ② ログローテーション（1MB超えで自動ローテーション、最大3世代）
# ─────────────────────────────────────────
def rotate_log(filepath, max_bytes=1 * 1024 * 1024, backup_count=3):
    """ファイルサイズが上限を超えたらローテーション"""
    if not os.path.exists(filepath):
        return
    if os.path.getsize(filepath) < max_bytes:
        return
    # .3 → 削除、.2 → .3、.1 → .2、現行 → .1
    for i in range(backup_count - 1, 0, -1):
        src = f"{filepath}.{i}"
        dst = f"{filepath}.{i + 1}"
        if os.path.exists(src):
            if i + 1 > backup_count:
                os.remove(src)
            else:
                os.rename(src, dst)
    os.rename(filepath, f"{filepath}.1")
    # 新しい空ファイルを作成
    with open(filepath, "w", encoding="utf-8") as f:
        now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        f.write(f"[{now}] ── ログローテーション実施 ──\n")

# ─────────────────────────────────────────
# トークン（60秒有効）
# ─────────────────────────────────────────
def make_token(action, ip):
    window = int(time.time()) // 60
    msg = f"{action}:{ip}:{window}".encode()
    return hmac.new(SECRET_KEY.encode(), msg, hashlib.sha256).hexdigest()[:24]

def verify_token(action, ip, token):
    for delta in [0, -1]:
        window = int(time.time()) // 60 + delta
        msg = f"{action}:{ip}:{window}".encode()
        expected = hmac.new(SECRET_KEY.encode(), msg, hashlib.sha256).hexdigest()[:24]
        if hmac.compare_digest(expected, token or ''):
            return True
    return False

app.jinja_env.globals['make_token'] = make_token

# ─────────────────────────────────────────
# 重複ログ防止 / 重複リクエスト防止
# ─────────────────────────────────────────
_last_log = {}
_used_tokens = {}
_used_tokens_lock = threading.Lock()

def is_duplicate_request(key):
    now_ts = time.time()
    with _used_tokens_lock:
        expired = [k for k, t in _used_tokens.items() if now_ts - t > 3]
        for k in expired:
            del _used_tokens[k]
        if key in _used_tokens:
            return True
        _used_tokens[key] = now_ts
        return False

def write_watcher_log(msg):
    now_ts = time.time()
    if msg in _last_log and now_ts - _last_log[msg] < 10:
        return
    _last_log[msg] = now_ts
    if os.path.exists(WATCHER_LOG):
        with open(WATCHER_LOG, "r", encoding="utf-8") as f:
            lines = f.readlines()
        if lines:
            last_line = lines[-1].strip()
            if msg in last_line:
                try:
                    last_time_str = last_line[1:9]
                    last_dt = datetime.datetime.strptime(last_time_str, "%H:%M:%S")
                    now_dt = datetime.datetime.now()
                    last_dt = last_dt.replace(year=now_dt.year, month=now_dt.month, day=now_dt.day)
                    if (now_dt - last_dt).total_seconds() < 10:
                        return
                except Exception:
                    pass
    # ② 書き込み前にローテーション確認
    rotate_log(WATCHER_LOG)
    now = datetime.datetime.now().strftime("%H:%M:%S")
    line = f"[{now}] {msg}"
    with open(WATCHER_LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def write_log(msg):
    # ② ローテーション確認
    rotate_log(LOG_FILE)
    now = datetime.datetime.now().strftime('%d/%b/%Y %H:%M:%S')
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{now}] {msg}\n")

# ─────────────────────────────────────────
# ⑤ Agent Reports 読み込み（最新5件）
# ─────────────────────────────────────────
def load_agent_reports(count=5):
    """agent_reports.jsonlから最新レポートを読み込む"""
    if not os.path.exists(AGENT_REPORTS_FILE):
        return []
    reports = []
    try:
        with open(AGENT_REPORTS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        reports.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        # 新しい順に返す
        return list(reversed(reports[-count:]))
    except Exception:
        return []


def load_redteam_reports(count=50):
    """redteam_reports.jsonl(redteam_probe.py出力)から最新レポートを読み込む"""
    if not os.path.exists(REDTEAM_REPORTS_FILE):
        return []
    reports = []
    try:
        with open(REDTEAM_REPORTS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        reports.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
        return list(reversed(reports[-count:]))
    except Exception:
        return []

# ─────────────────────────────────────────
# ④ グラフ用データ集計
# ─────────────────────────────────────────
def get_chart_data():
    """agent_reports.jsonl からグラフ用データを集計する"""
    if not os.path.exists(AGENT_REPORTS_FILE):
        return {"hourly": {}, "patterns": {}, "top_ips": [], "severity": {}, "total": 0}
    reports = []
    try:
        with open(AGENT_REPORTS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        reports.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except Exception:
        return {"hourly": {}, "patterns": {}, "top_ips": [], "severity": {}, "total": 0}

    # 時間帯別攻撃数（0〜23時）HIGH/MEDIUM/LOW別
    hourly_high   = {str(i): 0 for i in range(24)}
    hourly_medium = {str(i): 0 for i in range(24)}
    hourly_low    = {str(i): 0 for i in range(24)}
    # 攻撃パターン分布
    patterns = {}
    # IP別攻撃数
    ip_counts = {}

    today = datetime.datetime.now().strftime("%Y-%m-%d")
    for r in reports:
        # 時間帯（今日0:00以降のみ集計）
        try:
            ts  = r.get("timestamp", "")
            if not ts.startswith(today):
                continue
            h   = str(int(ts[11:13]))
            sev = r.get("severity", "LOW").upper()
            if sev == "HIGH":
                hourly_high[h]   = hourly_high.get(h, 0) + 1
            elif sev == "MEDIUM":
                hourly_medium[h] = hourly_medium.get(h, 0) + 1
            else:
                hourly_low[h]    = hourly_low.get(h, 0) + 1
        except Exception:
            pass
        # パターン
        for p in r.get("patterns", []):
            patterns[p] = patterns.get(p, 0) + 1
        # IP
        ip = r.get("attacker_ip", "UNKNOWN")
        if ip and ip != "UNKNOWN":
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

    # Top 5 IP
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_ips = [{"ip": ip, "count": cnt} for ip, cnt in top_ips]

    return {
        "hourly_high"  : hourly_high,
        "hourly_medium": hourly_medium,
        "hourly_low"   : hourly_low,
        "patterns": patterns,
        "top_ips" : top_ips,
        "total"   : len(reports),
        "severity": {
            "HIGH"  : sum(1 for r in reports if r.get("severity") == "HIGH"),
            "MEDIUM": sum(1 for r in reports if r.get("severity") == "MEDIUM"),
            "LOW"   : sum(1 for r in reports if r.get("severity") == "LOW"),
        }
    }

# ─────────────────────────────────────────
# CORSヘッダー
# ─────────────────────────────────────────
@app.before_request
def check_access():
    """全ルートへのアクセスをBL/pfctlで一括チェック
    2026-07-29: 従来は例外発生時に一律で許可(fail-open)していたが、
    クライアントIP特定・ブラックリスト読み込みの失敗はセキュリティ判定の根幹に関わるため
    fail-closed(拒否)に変更。pfctl側の一時的な失敗のみ、ブラックリストファイルによる
    一次チェックで担保されているとみなし、従来通り許容する。"""
    if request.path.startswith('/rescue'):
        return None
    try:
        client_ip = get_client_ip()
    except Exception:
        return render_template_string(BLOCKED_TEMPLATE, ip='unknown'), 403
    try:
        if client_ip in read_file_lines(BLACKLIST_FILE):
            return render_template_string(BLOCKED_TEMPLATE, ip=client_ip), 403
    except Exception:
        return render_template_string(BLOCKED_TEMPLATE, ip=client_ip), 403
    try:
        r = subprocess.run(["/usr/bin/sudo", "/sbin/pfctl", "-a", "mythofable",
                           "-t", "mythofable_block", "-T", "show"],
                          capture_output=True, text=True, timeout=5)
        pf_block_ips = [l.strip() for l in r.stdout.splitlines() if l.strip()]
        if client_ip in pf_block_ips:
            return render_template_string(BLOCKED_TEMPLATE, ip=client_ip), 403
    except Exception:
        pass
    return None

@app.after_request
def add_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Vary'] = '*'
    # HTTPアクセスログをdashboard.logに書き込み（log_watcherが監視）
    try:
        client_ip = get_client_ip()
        method    = request.method
        path_qs   = request.full_path.rstrip('?')
        status    = response.status_code
        now       = datetime.datetime.now().strftime('%d/%b/%Y %H:%M:%S')
        rotate_log(LOG_FILE)
        with open(LOG_FILE, "a", encoding="utf-8") as _f:
            _f.write(f"{client_ip} - - [{now}] \"{method} {path_qs} HTTP/1.1\" {status} -\n")
    except Exception:
        pass
    return response

# ─────────────────────────────────────────
# アクセス拒否画面
# ─────────────────────────────────────────
BLOCKED_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>🚫 アクセス拒否</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">
    <script>
        window.addEventListener("unload", function() {});
        window.addEventListener("pageshow", function(e) {
            if (e.persisted) { location.replace("/rescue"); }
        });
        for (var i = 0; i < 20; i++) { history.pushState(null, null, "/blocked"); }
        window.onpopstate = function() { history.pushState(null, null, "/blocked"); };
    </script>
    <style>
        body { font-family: monospace; background: #000; color: #f44;
               display: flex; justify-content: center; align-items: center;
               min-height: 100vh; margin: 0; }
        .box { text-align: center; padding: 40px; border: 2px solid #f44;
               border-radius: 8px; background: #0a0000; max-width: 340px; }
        h1 { font-size: 48px; margin: 0 0 16px; }
        h2 { color: #f44; font-size: 20px; margin: 0 0 12px; }
        .ip { color: #ff0; font-size: 16px; margin: 12px 0; padding: 8px;
              border: 1px solid #ff0; border-radius: 4px; background: #1a1a00; }
        p { color: #888; font-size: 13px; margin: 16px 0 0; }
        .rescue-btn { display: inline-block; margin-top: 20px; padding: 10px 20px;
                      color: #0f0; border: 1px solid #0f0; text-decoration: none;
                      font-family: monospace; font-size: 13px; border-radius: 4px; }
    </style>
</head>
<body>
<div class="box">
    <h1>🚫</h1>
    <h2>アクセス拒否</h2>
    <div class="ip">{{ ip }}</div>
    <p>このIPアドレスはブラックリストに登録されました。<br>アクセスは遮断されています。</p>
    <a href="/rescue" rel="noreferrer" class="rescue-btn">🚨 Rescue Panel</a>
</div>
</body>
</html>"""

# ─────────────────────────────────────────
# 管理画面テンプレート（⑤ Agent Reports セクション追加）
# ─────────────────────────────────────────
DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>SecureGuard - 管理画面</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">
    <meta http-equiv="Pragma" content="no-cache">
    <meta http-equiv="Expires" content="0">
    <script>
        window.addEventListener("unload", function() {});
        window.addEventListener("pageshow", function(e) {
            if (e.persisted) { location.replace("/?t=" + Date.now()); }
        });
    </script>
    <style>
        body { font-family: monospace; background: #000; color: #0f0; padding: 16px; }
        h1 { color: #fff; border-bottom: 1px solid #333; padding-bottom: 8px; font-size: 18px; }
        h2 { color: #0ff; border-bottom: 1px solid #333; padding-bottom: 4px; font-size: 15px; margin-top: 24px; }
        .status { color: #0f0; font-size: 13px; margin-bottom: 20px; }
        .access-box { background: #111; border: 1px solid #333; border-radius: 6px; padding: 16px; margin-bottom: 20px; }
        .access-box p { color: #888; font-size: 12px; margin: 0 0 12px; }
        .btn-row { display: flex; gap: 12px; flex-wrap: wrap; }
        .btn-allow { flex:1; min-width:120px; padding:14px 8px; text-align:center;
                     background:#000; color:#0f0; border:2px solid #0f0;
                     text-decoration:none; font-family:monospace; font-size:14px; border-radius:6px; display:block; }
        .btn-allow:active { background:#0f0; color:#000; }
        .btn-deny  { flex:1; min-width:120px; padding:14px 8px; text-align:center;
                     background:#000; color:#f44; border:2px solid #f44;
                     text-decoration:none; font-family:monospace; font-size:14px; border-radius:6px; display:block; }
        .btn-deny:active { background:#f44; color:#000; }
        .ip-list { list-style:none; padding:0; margin:0; }
        .ip-list li { padding:6px 0; border-bottom:1px solid #222; display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
        .btn-sm-green { display:inline-block; padding:3px 10px; background:#000; color:#0f0; border:1px solid #0f0; text-decoration:none; font-family:monospace; font-size:12px; border-radius:3px; }
        .btn-sm-cyan  { display:inline-block; padding:3px 10px; background:#000; color:#0ff; border:1px solid #0ff; text-decoration:none; font-family:monospace; font-size:12px; border-radius:3px; }
        .btn-sm-red   { display:inline-block; padding:3px 10px; background:#000; color:#f44; border:1px solid #f44; text-decoration:none; font-family:monospace; font-size:12px; border-radius:3px; }
        .btn-sm-gray  { display:inline-block; padding:3px 10px; background:#000; color:#888; border:1px solid #888; text-decoration:none; font-family:monospace; font-size:12px; border-radius:3px; }
        .message { color:#ff0; background:#111; padding:10px; border:1px solid #ff0; border-radius:4px; margin-bottom:16px; font-size:13px; }
        .rescue-link { display:inline-block; margin-top:8px; color:#f44; font-size:13px; text-decoration:none; border:1px solid #f44; padding:4px 10px; border-radius:3px; }
        pre { background:#000; padding:10px; border-radius:3px; max-height:120px; overflow-y:auto; color:#0f0; white-space:pre-wrap; font-size:11px; }
        .container { display:flex; gap:16px; flex-wrap:wrap; }
        .box { flex:1; min-width:260px; }
        /* ⑤ Agent Reports */
        .report-card { background:#0a0a15; border:1px solid #336; border-radius:6px; padding:12px; margin-bottom:10px; }
        .report-card .report-header { display:flex; gap:8px; align-items:center; margin-bottom:6px; flex-wrap:wrap; }
        .report-card .sev-high   { color:#f44; border:1px solid #f44; padding:1px 6px; border-radius:3px; font-size:11px; }
        .report-card .sev-medium { color:#fa0; border:1px solid #fa0; padding:1px 6px; border-radius:3px; font-size:11px; }
        .report-card .sev-low    { color:#0f0; border:1px solid #0f0; padding:1px 6px; border-radius:3px; font-size:11px; }
        .report-card .r-ip   { color:#ff0; font-size:12px; }
        .report-card .r-time { color:#555; font-size:11px; }
        .report-card .r-body { color:#aaa; font-size:12px; margin-top:4px; white-space:pre-wrap; line-height:1.5; }
        .report-card .r-action { color:#0ff; font-size:11px; margin-top:4px; }
        /* ① Health link */
        .health-link { color:#0f0; font-size:11px; text-decoration:none; border:1px solid #333; padding:2px 8px; border-radius:3px; margin-left:8px; }
        /* ④ グラフ */
        .chart-grid { display:flex; gap:16px; flex-wrap:wrap; margin-bottom:20px; }
        .chart-box  { flex:1; min-width:260px; background:#050510; border:1px solid #223; border-radius:6px; padding:14px; }
        .chart-box h3 { color:#0ff; font-size:13px; margin:0 0 10px; border-bottom:1px solid #223; padding-bottom:4px; }
        .chart-wrap { position:relative; height:160px; }
        .sev-summary { display:flex; gap:10px; margin-top:8px; flex-wrap:wrap; }
        .sev-badge { flex:1; text-align:center; padding:8px 4px; border-radius:4px; font-size:12px; font-family:monospace; }
        .sev-badge.high   { background:#1a0000; border:1px solid #f44; color:#f44; }
        .sev-badge.medium { background:#1a1000; border:1px solid #fa0; color:#fa0; }
        .sev-badge.low    { background:#001a00; border:1px solid #0f0; color:#0f0; }
        .top-ip-row { display:flex; align-items:center; gap:8px; margin-bottom:6px; }
        .top-ip-bar { height:14px; background:#0a3; border-radius:2px; min-width:4px; transition:width 0.3s; }
        .top-ip-label { color:#ff0; font-size:11px; min-width:100px; word-break:break-all; }
        .top-ip-count { color:#888; font-size:11px; margin-left:auto; }
    </style>
</head>
<body>
    <h1>🔒 SecureGuard 管理画面
        <a href="/health" target="_blank" class="health-link">📡 /health</a>
        <a href="/rescue" rel="noreferrer" class="health-link" style="border-color:#f44;color:#f44;">🚨 Rescue</a>
    </h1>
    <div style="margin:4px 0 12px;display:flex;gap:8px;flex-wrap:wrap;">
        <a href="/reports" rel="noreferrer" class="health-link" style="border-color:#0ff;color:#0ff;">📊 統計レポート</a>
        <a href="/patches" rel="noreferrer" class="health-link" style="border-color:#fa0;color:#fa0;">🔧 パッチ候補</a>
        <a href="/redteam" rel="noreferrer" class="health-link" style="border-color:#0f0;color:#0f0;">🎯 レッドチーム</a>
        <a href="/test_port" rel="noreferrer" class="health-link" style="border-color:#f0f;color:#f0f;">🔬 ポートテスト</a>
        <a href="/logs" rel="noreferrer" class="health-link" style="border-color:#fa0;color:#fa0;">🗂️ ログ管理</a>
        <a href="/services" rel="noreferrer" class="health-link" style="border-color:#0cf;color:#0cf;">⏸️ サービス管理</a>
    </div>
    <p class="status">🟢 正常稼働中 &nbsp;|&nbsp; 自動更新: 30秒</p>
    <div style="display:flex;gap:6px;flex-wrap:wrap;margin:4px 0 12px;font-size:11px;font-family:monospace;">
    {% for svc in services %}
        <span style="padding:2px 8px;border-radius:3px;border:1px solid {% if svc.active %}#0f0{% else %}#f44{% endif %};color:{% if svc.active %}#0f0{% else %}#f44{% endif %};">
        {% if svc.active %}🟢{% else %}🔴{% endif %} {{ svc.name }}
        </span>
    {% endfor %}
    </div>

    {% if message %}
    <div class="message">{{ message }}</div>
    {% endif %}

    <h2>📋 システムログ (直近20行)</h2>
    <pre>{{ logs }}</pre>

    <div style="margin-bottom:20px;">
        <h2>📡 Exit Node 接続状況
            <span style="font-size:11px;color:#555;font-weight:normal;margin-left:8px;">
                🔄 <select id="exit-interval" onchange="updateExitInterval(this.value)"
                    style="background:#222;color:#0ff;border:1px solid #444;border-radius:3px;font-size:11px;padding:1px 4px;">
                    <option value="5">5秒</option>
                    <option value="10">10秒</option>
                    <option value="15">15秒</option>
                    <option value="20">20秒</option>
                    <option value="25">25秒</option>
                    <option value="30">30秒</option>
                    <option value="60">60秒</option>
                    <option value="120">120秒</option>
                    <option value="0">手動</option>
                </select>間隔
                <span id="exit-updated" style="margin-left:6px;"></span>
            </span>
        </h2>
        <div style="display:flex;gap:16px;flex-wrap:wrap;">
            <div style="flex:1;min-width:280px;">
                <h3 style="color:#0ff;font-size:13px;margin-bottom:6px;">← インバウンド (Tailscale)</h3>
                <div style="max-height:150px;overflow-y:auto;" id="exit-inbound-wrap">
                <table style="width:100%;border-collapse:collapse;font-size:11px;background:#0a1a1a;border:1px solid #333;border-radius:6px;">
                    <tr style="border-bottom:1px solid #333;">
                        <th style="color:#0ff;padding:4px 8px;text-align:left;">時刻</th>
                        <th style="color:#0ff;padding:4px 8px;text-align:left;">接続元IP</th>
                        <th style="color:#0ff;padding:4px 8px;text-align:left;">PORT</th>
                        <th style="color:#0ff;padding:4px 8px;text-align:left;">状態</th>
                    </tr>
                    <tbody id="exit-inbound-body"></tbody>
                </table>
                </div>
            </div>
            <div style="flex:1;min-width:280px;">
                <h3 style="color:#fa0;font-size:13px;margin-bottom:6px;">→ アウトバウンド (インターネット)</h3>
                <div style="max-height:150px;overflow-y:auto;" id="exit-outbound-wrap">
                <table style="width:100%;border-collapse:collapse;font-size:11px;background:#1a1a0a;border:1px solid #333;border-radius:6px;">
                    <tr style="border-bottom:1px solid #333;">
                        <th style="color:#fa0;padding:4px 8px;text-align:left;">時刻</th>
                        <th style="color:#fa0;padding:4px 8px;text-align:left;">接続先IP</th>
                        <th style="color:#fa0;padding:4px 8px;text-align:left;">PORT</th>
                        <th style="color:#fa0;padding:4px 8px;text-align:left;">状態</th>
                    </tr>
                    <tbody id="exit-outbound-body"></tbody>
                </table>
                </div>
            </div>
        </div>
    </div>
    <script>
    function renderExitRows(data, bodyId, colorIp, colorPort) {
        var tbody = document.getElementById(bodyId);
        if (!tbody) return;
        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" style="padding:8px;color:#555;font-size:12px;">接続なし</td></tr>';
            return;
        }
        tbody.innerHTML = data.map(function(c) {
            var t = c.last_seen ? c.last_seen.substring(11,16) : '';
            return '<tr style="border-bottom:1px solid #222;">' +
                '<td style="padding:4px 8px;color:#666;">' + t + '</td>' +
                '<td style="padding:4px 8px;color:' + colorIp + ';">' + c.remote_ip + '</td>' +
                '<td style="padding:4px 8px;color:' + colorPort + ';">' + c.remote_port + '</td>' +
                '<td style="padding:4px 8px;color:#0f0;">' + c.state + '</td>' +
                '</tr>';
        }).join('');
    }
    function fetchExitNode() {
        fetch('/exit_node/data')
            .then(function(r){ return r.json(); })
            .then(function(d) {
                renderExitRows(d.inbound,  'exit-inbound-body',  '#0ff', '#fa0');
                renderExitRows(d.outbound, 'exit-outbound-body', '#fa0', '#fa0');
                var el = document.getElementById('exit-updated');
                if (el) el.textContent = '🔄 ' + new Date().toLocaleTimeString('ja-JP');
            })
            .catch(function(){});
    }
    var _exitTimer = null;
    function updateExitInterval(sec) {
        sec = parseInt(sec);
        if (isNaN(sec)) sec = 15;
        if (sec > 0) sec = Math.max(5, Math.min(300, sec));
        document.getElementById('exit-interval').value = sec;
        localStorage.setItem('exitNodeInterval', sec);
        if (_exitTimer) clearInterval(_exitTimer);
        _exitTimer = (sec > 0) ? setInterval(fetchExitNode, sec * 1000) : null;
    }
    var _storedSec = localStorage.getItem('exitNodeInterval');
    var _savedSec = (_storedSec !== null) ? parseInt(_storedSec) : 15;
    updateExitInterval(_savedSec);
    if (_savedSec > 0) fetchExitNode();
    </script>

    <div style="margin-bottom:20px;">
        <h2>🔍 プロキシ監視 - 不審な通信 (最新20件)</h2>
        {% if proxy_alerts %}
        <div style="max-height:150px;overflow-y:auto;">
        <table style="width:100%;border-collapse:collapse;font-size:11px;background:#1a0a0a;border:1px solid #333;border-radius:6px;">
            <tr style="border-bottom:1px solid #333;">
                <th style="color:#0ff;padding:5px 8px;text-align:left;">時刻</th>
                <th style="color:#0ff;padding:5px 8px;text-align:left;">深刻度</th>
                <th style="color:#0ff;padding:5px 8px;text-align:left;">接続先</th>
                <th style="color:#0ff;padding:5px 8px;text-align:left;">PORT</th>
                <th style="color:#0ff;padding:5px 8px;text-align:left;">理由</th>
                <th style="color:#0ff;padding:5px 8px;text-align:left;">対応</th>
            </tr>
            {% for a in proxy_alerts %}
            <tr style="border-bottom:1px solid #222;">
                <td style="padding:5px 8px;color:#666;">{{ a.timestamp[11:16] }}</td>
                <td style="padding:5px 8px;">
                    {% if a.severity == "HIGH" %}<span style="color:#f44;">🔴 HIGH</span>
                    {% elif a.severity == "MEDIUM" %}<span style="color:#fa0;">🟡 MED</span>
                    {% else %}<span style="color:#0f0;">🟢 LOW</span>{% endif %}
                </td>
                <td style="padding:5px 8px;color:#f44;">{{ a.dst_ip }}{% if a.host %}<br><span style="color:#888;font-size:10px;">{{ a.host }}</span>{% endif %}</td>
                <td style="padding:5px 8px;color:#fa0;">{{ a.dst_port }}</td>
                <td style="padding:5px 8px;color:#aaa;">{{ a.reason }}</td>
                <td style="padding:5px 8px;color:#0ff;">{{ a.action }}</td>
            </tr>
            {% endfor %}
        </table>
        </div>
        {% else %}
        <p style="color:#555;font-size:12px;padding:4px 0;">不審な通信なし ✅</p>
        {% endif %}
    </div>

    <div style="margin-bottom:20px;">
        <h2>📋 現在のpfctlルール</h2>
        <div style="max-height:120px;overflow-y:auto;">
        <table style="width:100%;border-collapse:collapse;font-size:12px;background:#1a1a1a;border:1px solid #333;border-radius:6px;">
            <tr style="border-bottom:1px solid #333;"><th style="color:#0ff;padding:6px 8px;text-align:left;">ルール</th><th style="color:#0ff;padding:6px 8px;text-align:left;">状態</th></tr>
            {% for rule in pf_rules %}
            <tr style="border-bottom:1px solid #222;">
                <td style="padding:6px 8px;color:#aaa;font-size:11px;">{{ rule }}</td>
                <td style="padding:6px 8px;">{% if 'pass' in rule %}<span style="color:#0f0;border:1px solid #0f0;padding:1px 6px;border-radius:3px;font-size:11px;">PASS</span>{% else %}<span style="color:#f44;border:1px solid #f44;padding:1px 6px;border-radius:3px;font-size:11px;">BLOCK</span>{% endif %}</td>
            </tr>
            {% endfor %}
        </table>
        </div>
    </div>

    <div style="margin-bottom:20px;">
        <h2>📊 IP管理</h2>
        <div style="max-height:200px;overflow-y:auto;">
        <table style="width:100%;border-collapse:collapse;font-size:12px;background:#1a1a1a;border:1px solid #333;border-radius:6px;">
            <tr style="border-bottom:1px solid #333;">
                <th style="color:#0ff;padding:6px 8px;text-align:left;">種別</th>
                <th style="color:#0ff;padding:6px 8px;text-align:left;">IP</th>
                <th style="color:#0ff;padding:6px 8px;text-align:left;">操作</th>
            </tr>
            {% for ip in pf_blocked %}
            <tr style="border-bottom:1px solid #222;">
                <td style="padding:5px 8px;"><span style="color:#f44;border:1px solid #f44;padding:1px 6px;border-radius:3px;font-size:11px;">🧱 mythofable_block</span></td>
                <td style="padding:5px 8px;color:#f44;">{{ ip }}</td>
                <td style="padding:5px 8px;">
                    <a href="/rescue/action?action=pf_block_to_pass&ip={{ ip }}&token={{ make_token('pf_block_to_pass', ip) }}" style="color:#0f0;border:1px solid #0f0;padding:1px 6px;border-radius:3px;font-size:11px;text-decoration:none;">→pass</a>
                    <a href="/rescue/action?action=pf_block_delete&ip={{ ip }}&token={{ make_token('pf_block_delete', ip) }}" style="color:#888;border:1px solid #888;padding:1px 6px;border-radius:3px;font-size:11px;text-decoration:none;margin-left:4px;">削除</a>
                </td>
            </tr>
            {% endfor %}
            {% for ip in pf_passed %}
            <tr style="border-bottom:1px solid #222;">
                <td style="padding:5px 8px;"><span style="color:#0f0;border:1px solid #0f0;padding:1px 6px;border-radius:3px;font-size:11px;">🟢 mythofable_pass</span></td>
                <td style="padding:5px 8px;color:#0f0;">{{ ip }}</td>
                <td style="padding:5px 8px;">
                    <a href="/rescue/action?action=pf_pass_to_block&ip={{ ip }}&token={{ make_token('pf_pass_to_block', ip) }}" style="color:#f44;border:1px solid #f44;padding:1px 6px;border-radius:3px;font-size:11px;text-decoration:none;">→block</a>
                    <a href="/rescue/action?action=pf_pass_delete&ip={{ ip }}&token={{ make_token('pf_pass_delete', ip) }}" style="color:#888;border:1px solid #888;padding:1px 6px;border-radius:3px;font-size:11px;text-decoration:none;margin-left:4px;">削除</a>
                </td>
            </tr>
            {% endfor %}
            {% for ip in blacklisted %}
            <tr style="border-bottom:1px solid #222;">
                <td style="padding:5px 8px;"><span style="color:#f88;border:1px solid #f88;padding:1px 6px;border-radius:3px;font-size:11px;">🔴 BL</span></td>
                <td style="padding:5px 8px;color:#f88;">{{ ip }}</td>
                <td style="padding:5px 8px;">
                    <a href="/action?action=unblock&ip={{ ip }}&token={{ make_token('unblock', ip) }}" rel="noreferrer" style="color:#0f0;border:1px solid #0f0;padding:1px 6px;border-radius:3px;font-size:11px;text-decoration:none;">[解除]</a>
                    <a href="/action?action=to_whitelist&ip={{ ip }}&token={{ make_token('to_whitelist', ip) }}" rel="noreferrer" style="color:#0ff;border:1px solid #0ff;padding:1px 6px;border-radius:3px;font-size:11px;text-decoration:none;margin-left:4px;">[WHITE↑]</a>
                </td>
            </tr>
            {% endfor %}
            {% for ip in whitelisted %}
            <tr style="border-bottom:1px solid #222;">
                <td style="padding:5px 8px;"><span style="color:#0ff;border:1px solid #0ff;padding:1px 6px;border-radius:3px;font-size:11px;">⚪ WL</span></td>
                <td style="padding:5px 8px;color:#0ff;">{{ ip }}</td>
                <td style="padding:5px 8px;">
                    <a href="/action?action=to_blacklist&ip={{ ip }}&token={{ make_token('to_blacklist', ip) }}" rel="noreferrer" style="color:#f44;border:1px solid #f44;padding:1px 6px;border-radius:3px;font-size:11px;text-decoration:none;">[BLACK↓]</a>
                    <a href="/action?action=delete_white&ip={{ ip }}&token={{ make_token('delete_white', ip) }}" rel="noreferrer" style="color:#888;border:1px solid #888;padding:1px 6px;border-radius:3px;font-size:11px;text-decoration:none;margin-left:4px;">[削除]</a>
                </td>
            </tr>
            {% endfor %}
            {% if not pf_blocked and not pf_passed and not blacklisted and not whitelisted %}
            <tr><td colspan="3" style="padding:10px;color:#555;text-align:center;">登録なし</td></tr>
            {% endif %}
        </table>
        </div>
    </div>
</body>
</html>"""

# ─────────────────────────────────────────
# Rescue画面
# ─────────────────────────────────────────
# -----------------------------------------
# エージェントレポート画面テンプレート
# -----------------------------------------
REPORTS_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>SecureGuard - 統計 &amp; AIレポート</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
    <style>
        body { background:#111; color:#ccc; font-family:monospace; padding:20px; max-width:960px; margin:0 auto; }
        h1 { color:#0ff; font-size:20px; margin-bottom:16px; }
        h2 { color:#0ff; font-size:15px; margin:24px 0 8px; }
        .back-btn { display:inline-block; margin-bottom:20px; padding:7px 16px; color:#0f0; border:1px solid #0f0; text-decoration:none; font-family:monospace; font-size:13px; border-radius:3px; }
        .back-btn:hover { background:rgba(0,255,0,0.1); }
        .chart-grid { display:flex; gap:16px; flex-wrap:wrap; margin-bottom:20px; }
        .chart-box  { flex:1; min-width:260px; background:#050510; border:1px solid #223; border-radius:6px; padding:14px; }
        .chart-box h3 { color:#0ff; font-size:13px; margin:0 0 10px; border-bottom:1px solid #223; padding-bottom:4px; }
        .chart-wrap { position:relative; height:160px; }
        .sev-summary { display:flex; gap:10px; margin-top:8px; flex-wrap:wrap; }
        .sev-badge { flex:1; text-align:center; padding:8px 4px; border-radius:4px; font-size:12px; font-family:monospace; }
        .sev-badge.high   { background:#1a0000; border:1px solid #f44; color:#f44; }
        .sev-badge.medium { background:#1a0f00; border:1px solid #fa0; color:#fa0; }
        .sev-badge.low    { background:#001a00; border:1px solid #0f0; color:#0f0; }
        .report-card { background:#1a1a1a; border:1px solid #333; border-radius:6px; padding:14px; margin-bottom:14px; }
        .report-header { display:flex; gap:8px; align-items:center; margin-bottom:6px; flex-wrap:wrap; }
        .sev-high   { color:#f44; font-weight:bold; }
        .sev-medium { color:#fa0; font-weight:bold; }
        .sev-low    { color:#0f0; font-weight:bold; }
        .r-ip   { color:#0cf; font-size:13px; }
        .r-time { color:#666; font-size:11px; margin-left:auto; }
        .r-body { color:#aaa; font-size:13px; line-height:1.5; white-space:pre-wrap; }
        .r-action { color:#0f0; font-size:12px; margin-top:6px; }
        .empty  { color:#555; font-size:13px; padding:20px 0; }
        .sep { border:none; border-top:1px solid #333; margin:28px 0; }
    </style>
</head>
<body>
    <a href="/admin" rel="noreferrer" class="back-btn">← ダッシュボードに戻る</a>
    <h1>📊 統計 &amp; 🤖 AIエージェントレポート</h1>

    <h2>📊 攻撃統計ダッシュボード</h2>
    <div class="sev-summary" id="sevSummary">
        <div class="sev-badge high">🔴 HIGH<br><span id="sevHigh">-</span></div>
        <div class="sev-badge medium">🟡 MEDIUM<br><span id="sevMedium">-</span></div>
        <div class="sev-badge low">🟢 LOW<br><span id="sevLow">-</span></div>
        <div class="sev-badge" style="background:#0a0a0a;border:1px solid #333;color:#aaa;">📋 TOTAL<br><span id="sevTotal">-</span></div>
    </div>
    <div class="chart-grid" style="margin-top:14px;">
        <div class="chart-box" style="flex:2; min-width:300px;">
            <h3>⏰ 時間帯別攻撃数 (24h)</h3>
            <div class="chart-wrap"><canvas id="hourlyChart"></canvas></div>
        </div>
        <div class="chart-box">
            <h3>🎯 攻撃パターン分布</h3>
            <div class="chart-wrap"><canvas id="patternChart"></canvas></div>
        </div>
    </div>
    <div class="chart-box" style="margin-bottom:20px;">
        <h3>🏴‍☠️ Top 攻撃者 IP</h3>
        <div id="topIpList" style="max-height:120px;overflow-y:auto;"><p style="color:#555;font-size:12px;">データなし</p></div>
    </div>
    <script>
    (function() {
        Chart.defaults.color = '#888';
        Chart.defaults.borderColor = '#222';
        var hourlyChart = null, patternChart = null;

        function renderCharts(data) {
            // サマリーバッジ
            document.getElementById('sevHigh').textContent   = data.severity.HIGH   || 0;
            document.getElementById('sevMedium').textContent = data.severity.MEDIUM || 0;
            document.getElementById('sevLow').textContent    = data.severity.LOW    || 0;
            document.getElementById('sevTotal').textContent  = data.total           || 0;

            // 時間帯別積み上げ棒グラフ (HIGH=赤/MEDIUM=橙/LOW=緑)
            var hours  = Array.from({length:24}, function(_,i){ return i + '時'; });
            var cHigh   = Array.from({length:24}, function(_,i){ return data.hourly_high[String(i)]   || 0; });
            var cMedium = Array.from({length:24}, function(_,i){ return data.hourly_medium[String(i)] || 0; });
            var cLow    = Array.from({length:24}, function(_,i){ return data.hourly_low[String(i)]    || 0; });

            if (hourlyChart) hourlyChart.destroy();
            hourlyChart = new Chart(document.getElementById('hourlyChart'), {
                type: 'bar',
                data: {
                    labels: hours,
                    datasets: [
                        { label: 'HIGH',   data: cHigh,   backgroundColor: 'rgba(255,68,68,0.85)',  borderWidth:0, borderRadius:2 },
                        { label: 'MEDIUM', data: cMedium, backgroundColor: 'rgba(255,170,0,0.85)', borderWidth:0 },
                        { label: 'LOW',    data: cLow,    backgroundColor: 'rgba(0,255,0,0.6)',    borderWidth:0 }
                    ]
                },
                options: {
                    responsive: true, maintainAspectRatio: false,
                    plugins: { legend: { display: true, labels: { color:'#aaa', font:{size:10} } } },
                    scales: {
                        x: { stacked: true, ticks: { font:{size:9}, maxRotation:0 }, grid: { color:'#111' } },
                        y: { stacked: true, ticks: { font:{size:10} }, grid: { color:'#1a1a1a' }, beginAtZero:true }
                    }
                }
            });

            // 攻撃パターン ドーナツ
            var patKeys = Object.keys(data.patterns);
            var patVals = patKeys.map(function(k){ return data.patterns[k]; });
            var palette = ['#f44','#fa0','#0f0','#0ff','#f0f','#ff0','#08f','#f80'];

            if (patternChart) patternChart.destroy();
            if (patKeys.length === 0) {
                var ctx = document.getElementById('patternChart').getContext('2d');
                ctx.fillStyle = '#555';
                ctx.font = '12px monospace';
                ctx.textAlign = 'center';
                ctx.fillText('データなし', ctx.canvas.width/2, ctx.canvas.height/2);
            } else {
                patternChart = new Chart(document.getElementById('patternChart'), {
                    type: 'doughnut',
                    data: {
                        labels: patKeys,
                        datasets: [{
                            data: patVals,
                            backgroundColor: palette.slice(0, patKeys.length),
                            borderColor: '#000',
                            borderWidth: 2,
                        }]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'bottom',
                                labels: { font: { size: 9 }, boxWidth: 10, padding: 6 }
                            }
                        }
                    }
                });
            }

            // Top IP リスト
            var topEl = document.getElementById('topIpList');
            if (!data.top_ips || data.top_ips.length === 0) {
                topEl.innerHTML = '<p style="color:#555;font-size:12px;">データなし（攻撃検知後に表示されます）</p>';
            } else {
                var maxCnt = data.top_ips[0].count;
                topEl.innerHTML = data.top_ips.map(function(item, idx) {
                    var pct = Math.round((item.count / maxCnt) * 100);
                    var medal = idx === 0 ? '🥇' : idx === 1 ? '🥈' : idx === 2 ? '🥉' : '  ';
                    return '<div class="top-ip-row">'
                        + '<span style="font-size:14px;width:20px;">' + medal + '</span>'
                        + '<span class="top-ip-label">' + item.ip + '</span>'
                        + '<div class="top-ip-bar" style="width:' + pct + 'px;max-width:120px;"></div>'
                        + '<span class="top-ip-count">' + item.count + '件</span>'
                        + '</div>';
                }).join('');
            }
        }

        function fetchAndRender() {
            fetch('/chart_data')
                .then(function(r){ return r.json(); })
                .then(function(d){ renderCharts(d); })
                .catch(function(e){ console.warn('chart_data fetch error', e); });
        }

        // 初回 & 30秒ごとに更新
        fetchAndRender();
        setInterval(fetchAndRender, 30000);
    })();
    </script>


    <hr class="sep">
    <h2>🤖 AIエージェントレポート (最新{{ agent_reports|length }}件)</h2>
    <div style="max-height:500px;overflow-y:auto;padding-right:4px;">
    {% if agent_reports %}
    {% for r in agent_reports %}
    <div class="report-card">
        <div class="report-header">
            {% if r.severity == 'HIGH' %}
            <span class="sev-high">🔴 HIGH</span>
            {% elif r.severity == 'MEDIUM' %}
            <span class="sev-medium">🟡 MEDIUM</span>
            {% else %}
            <span class="sev-low">🟢 LOW</span>
            {% endif %}
            <span class="r-ip">{{ r.attacker_ip }}</span>
            <span class="r-time">{{ r.timestamp }}</span>
        </div>
        <div class="r-body">{{ r.summary }}</div>
        {% if r.actions %}
        <div class="r-action">→ 対応: {{ r.actions | join(' / ') }}</div>
        {% endif %}
    </div>
    {% endfor %}
    {% else %}
    <p class="empty">AIレポートなし（攻撃検知時に自動生成されます）</p>
    {% endif %}
    </div>
</body>
</html>"""


# ─────────────────────────────────────────
# パッチ候補管理画面テンプレート
# ─────────────────────────────────────────
PATCHES_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>SecureGuard - パッチ候補</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">
    <style>
        body { background:#111; color:#ccc; font-family:monospace; padding:20px; max-width:960px; margin:0 auto; }
        h1 { color:#0ff; font-size:20px; margin-bottom:16px; }
        .back-btn { display:inline-block; margin-bottom:20px; padding:7px 16px; color:#0f0; border:1px solid #0f0; text-decoration:none; font-family:monospace; font-size:13px; border-radius:3px; }
        .card { background:#1a1a1a; border:1px solid #333; border-radius:6px; padding:14px; margin-bottom:16px; }
        .card.pending { border-color:#fa0; }
        .card.applied { border-color:#0f0; opacity:0.6; }
        .card-header { display:flex; gap:10px; align-items:center; margin-bottom:10px; flex-wrap:wrap; }
        .badge-pending { color:#fa0; font-weight:bold; font-size:12px; border:1px solid #fa0; padding:2px 8px; border-radius:3px; }
        .badge-applied { color:#0f0; font-weight:bold; font-size:12px; border:1px solid #0f0; padding:2px 8px; border-radius:3px; }
        .fname { color:#0ff; font-size:14px; font-weight:bold; }
        .ts { color:#666; font-size:11px; margin-left:auto; }
        .finding { background:#111; border:1px solid #222; border-radius:4px; padding:8px 10px; margin:6px 0; font-size:12px; }
        .finding .sev-high { color:#f44; font-weight:bold; }
        .finding .sev-medium { color:#fa0; font-weight:bold; }
        .finding .line-code { color:#888; font-size:11px; margin-top:4px; white-space:pre-wrap; word-break:break-all; }
        .apply-btn { display:inline-block; margin-top:10px; padding:6px 16px; color:#0ff; border:1px solid #0ff; text-decoration:none; font-family:monospace; font-size:12px; border-radius:3px; cursor:pointer; }
        .apply-btn:hover { background:rgba(0,255,255,0.1); }
        .empty { color:#555; font-size:13px; padding:20px 0; }
        .count { color:#666; font-size:12px; margin-bottom:16px; }
    </style>
</head>
<body>
    <a href="/admin" rel="noreferrer" class="back-btn">← ダッシュボードに戻る</a>
    <h1>🔧 パッチ候補管理</h1>
    <div class="count">{{ candidates|length }} 件（pending: {{ candidates|selectattr('status','equalto','pending')|list|length }}件）</div>
    <div style="max-height:500px;overflow-y:auto;padding-right:4px;">
    {% if candidates %}
    {% for c in candidates %}
    <div class="card {{ c.status }}">
        <div class="card-header">
            {% if c.status == 'pending' %}
            <span class="badge-pending">⚠️ PENDING</span>
            {% else %}
            <span class="badge-applied">✅ APPLIED</span>
            {% endif %}
            <span class="fname">{{ c.file | replace('/Users/fk/MythoFable/', '') }}</span>
            <span class="ts">{{ c.timestamp }}</span>
        </div>
        {% for fi in c.findings %}
        <div class="finding">
            {% if fi.severity == 'HIGH' %}
            <span class="sev-high">🔴 HIGH</span>
            {% else %}
            <span class="sev-medium">🟡 MEDIUM</span>
            {% endif %}
            &nbsp;{{ fi.name }} — {{ fi.desc }}（行 {{ fi.line_no }}）
            <div class="line-code">{{ fi.line }}</div>
        </div>
        {% endfor %}
        {% if c.ai_patch %}
        <div style="background:#1a1410;border:1px solid #fa0;border-radius:4px;padding:10px;margin:10px 0;">
            <div style="color:#fa0;font-size:12px;font-weight:bold;">🤖 AI(OpenCode)生成パッチ候補 — {{ c.ai_warning }}</div>
            <pre style="color:#9c9;font-size:11px;white-space:pre-wrap;word-break:break-all;margin-top:8px;max-height:300px;overflow-y:auto;">{{ c.ai_patch }}</pre>
        </div>
        {% endif %}
        {% if c.status == 'pending' %}
        <a href="/patches/apply?file={{ c.filename }}&token={{ make_token('patch_apply', c.filename) }}" rel="noreferrer" class="apply-btn">🔧 このパッチを適用</a>
        {% else %}
        <div style="color:#0f0;font-size:12px;margin-top:8px;">✅ 適用済み: {{ c.get('applied_at','') }}</div>
        {% endif %}
    </div>
    {% endfor %}
    {% else %}
    <p class="empty">パッチ候補なし（auto_patcherが脆弱性を検知すると表示されます）</p>
    {% endif %}
    </div>
</body>
</html>"""


# ─────────────────────────────────────────
# レッドチーム検証結果画面テンプレート
# ─────────────────────────────────────────
REDTEAM_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>SecureGuard - レッドチーム検証</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">
    <style>
        body { background:#111; color:#ccc; font-family:monospace; padding:20px; max-width:960px; margin:0 auto; }
        h1 { color:#0ff; font-size:20px; margin-bottom:6px; }
        .desc { color:#888; font-size:12px; margin-bottom:16px; }
        .back-btn { display:inline-block; margin-bottom:20px; padding:7px 16px; color:#0f0; border:1px solid #0f0; text-decoration:none; font-family:monospace; font-size:13px; border-radius:3px; }
        .back-btn:hover { background:rgba(0,255,0,0.1); }
        .sev-summary { display:flex; gap:10px; margin-bottom:20px; flex-wrap:wrap; }
        .sev-badge { flex:1; min-width:80px; text-align:center; padding:8px 4px; border-radius:4px; font-size:12px; }
        .sev-badge.high    { background:#1a0000; border:1px solid #f44; color:#f44; }
        .sev-badge.medium  { background:#1a0f00; border:1px solid #fa0; color:#fa0; }
        .sev-badge.low     { background:#001a1a; border:1px solid #0cf; color:#0cf; }
        .sev-badge.info    { background:#0a0a0a; border:1px solid #555; color:#888; }
        .card { background:#1a1a1a; border:1px solid #333; border-radius:6px; padding:12px 14px; margin-bottom:12px; }
        .card.sev-border-high   { border-color:#f44; }
        .card.sev-border-medium { border-color:#fa0; }
        .r-header { display:flex; gap:8px; align-items:center; margin-bottom:6px; flex-wrap:wrap; }
        .outcome  { font-weight:bold; font-size:12px; padding:2px 8px; border-radius:3px; }
        .outcome.high   { color:#f44; border:1px solid #f44; }
        .outcome.medium { color:#fa0; border:1px solid #fa0; }
        .outcome.low    { color:#0cf; border:1px solid #0cf; }
        .outcome.info   { color:#888; border:1px solid #555; }
        .cat   { color:#0ff; font-size:12px; }
        .r-time{ color:#666; font-size:11px; margin-left:auto; }
        .r-body{ color:#aaa; font-size:13px; line-height:1.5; }
        .r-trigger { color:#888; font-size:11px; margin-top:6px; white-space:pre-wrap; word-break:break-all; background:#111; border:1px solid #222; border-radius:4px; padding:6px 8px; }
        .empty { color:#555; font-size:13px; padding:20px 0; }
        .count { color:#666; font-size:12px; margin-bottom:16px; }
    </style>
</head>
<body>
    <a href="/admin" rel="noreferrer" class="back-btn">← ダッシュボードに戻る</a>
    <h1>🎯 レッドチーム検証</h1>
    <p class="desc">redteam_probe.pyが定期的に自律エージェントへ攻撃を試み、防御(deny-list・承認フロー等)が
    実際に機能するか検証した結果です。BYPASSED/FALSE_POSITIVE相当は<a href="/patches" style="color:#fa0;">パッチ候補</a>にも出ます。</p>

    <div class="sev-summary">
        <div class="sev-badge high">🔴 BYPASSED<br>{{ counts.get('BYPASSED', 0) }}</div>
        <div class="sev-badge medium">🟡 BLOCKED<br>{{ counts.get('BLOCKED', 0) }}</div>
        <div class="sev-badge medium">🟡 FALSE_POSITIVE<br>{{ counts.get('FALSE_POSITIVE', 0) }}</div>
        <div class="sev-badge low">🔵 承認待ち等<br>{{ counts.get('REQUIRES_APPROVAL', 0) + counts.get('COMMAND_PROPOSED', 0) }}</div>
        <div class="sev-badge info">⚪ OK/NO_EFFECT<br>{{ counts.get('OK', 0) + counts.get('NO_EFFECT', 0) }}</div>
    </div>

    <div class="count">直近{{ reports|length }}件を表示</div>
    <div style="max-height:600px;overflow-y:auto;padding-right:4px;">
    {% if reports %}
    {% for r in reports %}
    <div class="card {% if r.severity == 'HIGH' %}sev-border-high{% elif r.severity == 'MEDIUM' %}sev-border-medium{% endif %}">
        <div class="r-header">
            <span class="outcome {{ r.severity|lower }}">{{ r.outcome }}</span>
            <span class="cat">{{ r.target }} / {{ r.category }}</span>
            <span class="r-time">{{ r.timestamp }}</span>
        </div>
        <div class="r-body">{{ r.summary }}</div>
        {% if r.detail and r.detail.trigger %}
        <div class="r-trigger">{{ r.detail.trigger }}</div>
        {% endif %}
    </div>
    {% endfor %}
    {% else %}
    <p class="empty">検証結果なし（redteam_probe.pyの初回実行後に表示されます）</p>
    {% endif %}
    </div>
</body>
</html>"""
TEST_PORT_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>SecureGuard - ポートテスト</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { background:#111; color:#ccc; font-family:monospace; padding:20px; max-width:800px; margin:0 auto; }
        h1 { color:#0ff; font-size:20px; margin-bottom:16px; }
        .back-btn { display:inline-block; margin-bottom:20px; padding:7px 16px; color:#0f0; border:1px solid #0f0; text-decoration:none; font-family:monospace; font-size:13px; border-radius:3px; }
        .card { background:#1a1a1a; border:1px solid #333; border-radius:6px; padding:16px; margin-bottom:16px; }
        .card h3 { color:#0ff; font-size:14px; margin:0 0 12px; }
        .result { background:#0a0a0a; border:1px solid #222; border-radius:4px; padding:10px; margin-top:10px; font-size:12px; min-height:40px; }
        .ok { color:#0f0; }
        .ng { color:#f44; }
        .warn { color:#fa0; }
        .test-btn { display:inline-block; padding:6px 14px; color:#0ff; border:1px solid #0ff; text-decoration:none; font-family:monospace; font-size:12px; border-radius:3px; cursor:pointer; margin:4px; }
        .test-btn:hover { background:rgba(0,255,255,0.1); }
        table { width:100%; border-collapse:collapse; font-size:12px; margin-top:8px; }
        th { color:#0ff; border-bottom:1px solid #333; padding:6px 8px; text-align:left; }
        td { border-bottom:1px solid #1a1a1a; padding:6px 8px; }
        .badge-pass { color:#0f0; border:1px solid #0f0; padding:1px 6px; border-radius:3px; font-size:11px; }
        .badge-block { color:#f44; border:1px solid #f44; padding:1px 6px; border-radius:3px; font-size:11px; }
    </style>
</head>
<body>
    <a href="/admin" rel="noreferrer" class="back-btn">← ダッシュボードに戻る</a>
    <h1>🔬 ポート・ファイアウォールテスト</h1>

    <div class="card">
        <h3>📡 アクセス判定</h3>
        <p style="color:#888;font-size:12px;">あなたのIP: <strong style="color:#ff0;">{{ my_ip }}</strong></p>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;">
            <a href="/access?action=allow&next=test_port&ip={{ my_ip }}&token={{ make_token('allow', my_ip) }}" rel="noreferrer noopener"
               class="test-btn" style="border-color:#0f0;color:#0f0;" onclick="if(this.dataset.clicked){return false;}this.dataset.clicked=1;this.style.opacity=0.5;">✅ 通常アクセス（whitelist登録）</a>
            <a href="/access?action=deny&next=test_port&ip={{ my_ip }}&token={{ make_token('deny', my_ip) }}" rel="noreferrer noopener"
               class="test-btn" style="border-color:#f44;color:#f44;" onclick="if(this.dataset.clicked){return false;}this.dataset.clicked=1;this.style.opacity=0.5;">🚫 不正アクセス（blacklist登録）</a>
        </div>
    </div>

    <div class="card">
        <h3>🧪 テスト用ダミー攻撃</h3>
        <p style="color:#888;font-size:12px;">ダミー攻撃レポートを生成します</p>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;">
            <a href="/test_attack?sev=HIGH&next=test_port&token={{ make_token('test_attack', 'HIGH') }}" rel="noreferrer" class="test-btn" style="border-color:#f44;color:#f44;">🔴 HIGH攻撃テスト</a>
            <a href="/test_attack?sev=MEDIUM&next=test_port&token={{ make_token('test_attack', 'MEDIUM') }}" rel="noreferrer" class="test-btn" style="border-color:#fa0;color:#fa0;">🟡 MEDIUM攻撃テスト</a>
            <a href="/test_attack?sev=LOW&next=test_port&token={{ make_token('test_attack', 'LOW') }}" rel="noreferrer" class="test-btn" style="border-color:#0f0;color:#0f0;">🟢 LOW攻撃テスト</a>
        </div>
    </div>

    <div class="card">
        <h3>🧪 ブラックリスト・pfctlテスト</h3>
        <p style="color:#888;font-size:12px;">テスト用IPをBL追加→pfctl確認→解除まで自動実行します</p>
        <a href="/test_port/run?token={{ make_token('test_port', 'run') }}" rel="noreferrer" class="test-btn">🔴 BL+pfctlテスト実行</a>
        {% if test_result %}
        <div class="result">
            {% for line in test_result %}
            <div class="{% if '✅' in line %}ok{% elif '❌' in line %}ng{% elif '⚠️' in line %}warn{% endif %}">{{ line }}</div>
            {% endfor %}
        </div>
        {% endif %}
    </div>

    <div class="card">
        <h3>🔍 プロキシ監視テスト</h3>
        <p style="color:#888;font-size:12px;">ダミーの不審通信をproxy.logに追加してダッシュボードの表示を確認します</p>
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;">
            <a href="/test_proxy?sev=HIGH&token={{ make_token('test_proxy', 'HIGH') }}" rel="noreferrer" class="test-btn" style="border-color:#f44;color:#f44;">🔴 HIGH不審通信テスト</a>
            <a href="/test_proxy?sev=MEDIUM&token={{ make_token('test_proxy', 'MEDIUM') }}" rel="noreferrer" class="test-btn" style="border-color:#fa0;color:#fa0;">🟡 MEDIUM不審通信テスト</a>
            <a href="/test_proxy?sev=LOW&token={{ make_token('test_proxy', 'LOW') }}" rel="noreferrer" class="test-btn" style="border-color:#0f0;color:#0f0;">🟢 LOW不審通信テスト</a>
            <a href="/test_proxy?action=clear&token={{ make_token('test_proxy', 'clear') }}" rel="noreferrer" class="test-btn" style="border-color:#666;color:#666;" onclick="return confirm('テストデータをクリアしますか？');">🗑️ テストデータクリア</a>
        </div>
    </div>

    <div class="card">
        <h3>🌐 Tailscale IP情報</h3>
        <div style="max-height:120px;overflow-y:auto;">
        <table>
            <tr><th>項目</th><th>値</th></tr>
            <tr><td>このMacのTailscale IP</td><td style="color:#0ff;">{{ tailscale_ip }}</td></tr>
            <tr><td>Tailscale IPレンジ</td><td style="color:#0f0;">100.64.0.0/10 ✅ 許可</td></tr>
            <tr><td>あなたのIP</td><td style="color:#ff0;">{{ my_ip }}</td></tr>
            <tr><td>Tailscale経由</td><td>{% if tailscale_ok %}<span class="ok">✅ はい（port 5000アクセス可）</span>{% else %}<span class="ng">❌ いいえ（port 5000ブロック対象）</span>{% endif %}</td></tr>
        </table>
        </div>
    </div>
</body>
</html>"""


# ─────────────────────────────────────────
# ログ管理画面テンプレート
# ─────────────────────────────────────────
LOGS_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>SecureGuard - ログ管理</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">
    <style>
        body { background:#111; color:#ccc; font-family:monospace; padding:20px; max-width:900px; margin:0 auto; }
        h1 { color:#0ff; font-size:20px; margin-bottom:16px; }
        .back-btn { display:inline-block; margin-bottom:20px; padding:7px 16px; color:#0f0; border:1px solid #0f0; text-decoration:none; font-family:monospace; font-size:13px; border-radius:3px; }
        .back-btn:hover { background:rgba(0,255,0,0.1); }
        table { width:100%; border-collapse:collapse; font-size:13px; background:#1a1a1a; border:1px solid #333; border-radius:6px; }
        th { color:#0ff; padding:8px 12px; text-align:left; border-bottom:1px solid #333; }
        td { padding:8px 12px; border-bottom:1px solid #222; }
        .clear-btn { display:inline-block; padding:4px 12px; color:#f44; border:1px solid #f44; text-decoration:none; font-family:monospace; font-size:11px; border-radius:3px; }
        .clear-btn:hover { background:rgba(255,68,68,0.1); }
        .size { color:#888; }
        .message { background:#1a2a1a; border:1px solid #0f0; border-radius:4px; padding:10px; margin-bottom:16px; color:#0f0; font-size:13px; }
        .preview-box { background:#000; border:1px solid #222; border-radius:4px; padding:8px; margin-top:6px; max-height:80px; overflow-y:auto; font-size:10px; color:#666; white-space:pre-wrap; }
    </style>
</head>
<body>
    <a href="/admin" rel="noreferrer" class="back-btn">← ダッシュボードに戻る</a>
    <a href="/log_clear_all?token={{ make_token('log_clear_all', 'all') }}" rel="noreferrer"
       style="display:inline-block;margin-bottom:20px;margin-left:8px;padding:7px 16px;color:#f44;border:1px solid #f44;text-decoration:none;font-family:monospace;font-size:13px;border-radius:3px;"
       onclick="return confirm('全てのログをバックアップ後クリアしますか？');">🗑️ 全てクリア</a>
    <h1>🗂️ ログ管理</h1>
    {% if message %}
    <div class="message">{{ message }}</div>
    {% endif %}
    <table>
        <tr>
            <th>ログファイル</th>
            <th>サイズ</th>
            <th>最終更新</th>
            <th>操作</th>
        </tr>
        {% for lf in log_files %}
        <tr>
            <td>
                {{ lf.name }}
                {% if lf.preview %}
                <div class="preview-box">{{ lf.preview }}</div>
                {% endif %}
            </td>
            <td class="size">{{ lf.size }}</td>
            <td class="size">{{ lf.mtime }}</td>
            <td>
                <a href="/log_clear?log={{ lf.name }}&next=logs&token={{ make_token('log_clear', lf.name) }}"
                   rel="noreferrer" class="clear-btn"
                   onclick="return confirm('{{ lf.name }} をバックアップ後クリアしますか？');">🗑️ クリア</a>
            </td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>"""


# ─────────────────────────────────────────
# サービス管理画面テンプレート
# ─────────────────────────────────────────
SERVICES_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>SecureGuard - サービス管理</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">
    <style>
        body { background:#111; color:#ccc; font-family:monospace; padding:20px; max-width:900px; margin:0 auto; }
        h1 { color:#0ff; font-size:20px; margin-bottom:16px; }
        .back-btn { display:inline-block; margin-bottom:20px; padding:7px 16px; color:#0f0; border:1px solid #0f0; text-decoration:none; font-family:monospace; font-size:13px; border-radius:3px; }
        .back-btn:hover { background:rgba(0,255,0,0.1); }
        table { width:100%; border-collapse:collapse; font-size:13px; background:#1a1a1a; border:1px solid #333; border-radius:6px; }
        th { color:#0ff; padding:10px 12px; text-align:left; border-bottom:1px solid #333; }
        td { padding:10px 12px; border-bottom:1px solid #222; vertical-align:middle; }
        .badge-on  { color:#0f0; border:1px solid #0f0; padding:2px 10px; border-radius:3px; font-size:12px; }
        .badge-off { color:#f44; border:1px solid #f44; padding:2px 10px; border-radius:3px; font-size:12px; }
        .btn-stop  { display:inline-block; padding:4px 12px; color:#fa0; border:1px solid #fa0; text-decoration:none; font-family:monospace; font-size:12px; border-radius:3px; }
        .btn-start { display:inline-block; padding:4px 12px; color:#0f0; border:1px solid #0f0; text-decoration:none; font-family:monospace; font-size:12px; border-radius:3px; }
        .btn-stop:hover  { background:rgba(255,170,0,0.1); }
        .btn-start:hover { background:rgba(0,255,0,0.1); }
        .desc { color:#666; font-size:11px; margin-top:3px; }
        .message { background:#1a2a1a; border:1px solid #0f0; border-radius:4px; padding:10px; margin-bottom:16px; color:#0f0; font-size:13px; }
        .warn { background:#2a1a00; border:1px solid #fa0; border-radius:4px; padding:10px; margin-bottom:16px; color:#fa0; font-size:12px; }
    </style>
</head>
<body>
    <a href="/admin" rel="noreferrer" class="back-btn">← ダッシュボードに戻る</a>
    <h1>⏸️ サービス管理</h1>
    {% if message %}
    <div class="message">{{ message }}</div>
    {% endif %}
    <table>
        <tr>
            <th>サービス</th>
            <th>種別</th>
            <th>状態</th>
            <th>操作</th>
        </tr>
        {% for svc in services %}
        <tr>
            <td>
                <strong>{{ svc.name }}</strong>
                <div class="desc">{{ svc.desc }}</div>
            </td>
            <td style="color:#888;font-size:12px;">{{ svc.kind }}</td>
            <td>
                {% if svc.active %}
                <span class="badge-on">🟢 稼働中</span>
                {% else %}
                <span class="badge-off">🔴 停止中</span>
                {% endif %}
            </td>
            <td>
                {% if svc.active %}
                <a href="/service_ctrl?svc={{ svc.id }}&action=stop&token={{ make_token('service_ctrl', svc.id) }}"
                   rel="noreferrer" class="btn-stop"
                   onclick="return confirm('{{ svc.name }} を一時停止しますか？');">⏸️ 一時停止</a>
                {% else %}
                <a href="/service_ctrl?svc={{ svc.id }}&action=start&token={{ make_token('service_ctrl', svc.id) }}"
                   rel="noreferrer" class="btn-start">▶️ 再開</a>
                {% endif %}
            </td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>"""


RESCUE_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
    <title>🚨 Rescue - SecureGuard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate">
    <script>
        window.addEventListener("unload", function() {});
        window.addEventListener("pageshow", function(e) {
            if (e.persisted) { location.replace("/rescue?t=" + Date.now()); }
        });
    </script>
    <style>
        body { font-family: monospace; background: #000; color: #0f0; padding: 20px; }
        h1 { color: #f44; border-bottom: 1px solid #f44; padding-bottom: 8px; font-size: 20px; }
        h2 { color: #0ff; border-bottom: 1px solid #333; padding-bottom: 5px; font-size: 15px; }
        .ip-list { list-style:none; padding:0; margin:0; }
        .ip-list li { padding:10px 0; border-bottom:1px solid #222; display:flex; align-items:center; gap:10px; flex-wrap:wrap; }
        .ip-text { flex:1; font-size:14px; word-break:break-all; }
        .btn-unblock { display:inline-block; padding:8px 16px; background:#000; color:#0f0; border:2px solid #0f0; text-decoration:none; font-family:monospace; font-size:14px; border-radius:4px; min-width:80px; text-align:center; }
        .btn-white   { display:inline-block; padding:8px 16px; background:#000; color:#0ff; border:2px solid #0ff; text-decoration:none; font-family:monospace; font-size:14px; border-radius:4px; min-width:80px; text-align:center; }
        .message { color:#ff0; background:#111; padding:12px; border:1px solid #ff0; border-radius:4px; margin:12px 0; font-size:14px; }
        .empty { color:#555; padding:10px 0; }
        .nav a { color:#0f0; text-decoration:none; border:1px solid #0f0; padding:6px 14px; font-family:monospace; font-size:13px; border-radius:3px; }
        .report-nav-btn { display:inline-block; padding:8px 18px; color:#0ff; border:1px solid #0ff; text-decoration:none; font-family:monospace; font-size:13px; border-radius:3px; }
    </style>
</head>
<body>
    <div class="nav" style="margin-bottom:16px;">
        <a href="https://hz-k-2mba14.tailb82610.ts.net:5000/">← 管理画面へ</a>
    </div>
    <h1>🚨 Rescue Panel</h1>
    <p style="color:#888;font-size:12px;">ブラックリストのIPを解除・ホワイトリストへ移動できます</p>

    {% if message %}
    <div class="message">{{ message }}</div>
    {% endif %}

    <h2>🔴 ブラックリスト ({{ blacklisted|length }}件)</h2>
    <ul class="ip-list">
        {% for ip in blacklisted %}
        <li>
            <span class="ip-text">❌ {{ ip }}</span>
            <a href="/rescue/action?action=bl_to_wl&ip={{ ip }}&token={{ make_token('bl_to_wl', ip) }}" rel="noreferrer" class="btn-white">[BL→WL]</a>
            <a href="/rescue/action?action=bl_delete&ip={{ ip }}&token={{ make_token('bl_delete', ip) }}" rel="noreferrer" style="display:inline-block;padding:8px 16px;background:#000;color:#888;border:2px solid #888;text-decoration:none;font-family:monospace;font-size:14px;border-radius:4px;">[削除]</a>
        </li>
        {% else %}
        <li><span class="empty">ブラックリストは空です ✅</span></li>
        {% endfor %}
    </ul>

    <h2>⚪ ホワイトリスト ({{ whitelisted|length }}件)</h2>
    <ul class="ip-list">
        {% for ip in whitelisted %}
        <li>
            <span class="ip-text">✅ {{ ip }}</span>
            <a href="/rescue/action?action=wl_to_bl&ip={{ ip }}&token={{ make_token('wl_to_bl', ip) }}" rel="noreferrer" class="btn-unblock">[WL→BL]</a>
            <a href="/rescue/action?action=wl_delete&ip={{ ip }}&token={{ make_token('wl_delete', ip) }}" rel="noreferrer" style="display:inline-block;padding:8px 16px;background:#000;color:#888;border:2px solid #888;text-decoration:none;font-family:monospace;font-size:14px;border-radius:4px;">[削除]</a>
        </li>
        {% else %}
        <li><span class="empty">ホワイトリストは空です</span></li>
        {% endfor %}
    </ul>

    <h2>🧱 pfctl mythofable_block ({{ pf_blocked|length }}件)</h2>
    <ul class="ip-list">
        {% for ip in pf_blocked %}
        <li>
            <span class="ip-text">🧱 {{ ip }}</span>
            <a href="/rescue/action?action=pf_block_to_pass&ip={{ ip }}&token={{ make_token('pf_block_to_pass', ip) }}" rel="noreferrer" class="btn-white">[block→pass]</a>
            <a href="/rescue/action?action=pf_block_delete&ip={{ ip }}&token={{ make_token('pf_block_delete', ip) }}" rel="noreferrer" style="display:inline-block;padding:8px 16px;background:#000;color:#888;border:2px solid #888;text-decoration:none;font-family:monospace;font-size:14px;border-radius:4px;">[削除]</a>
        </li>
        {% else %}
        <li><span class="empty">pfctl mythofable_blockなし ✅</span></li>
        {% endfor %}
    </ul>

    <h2>🟢 pfctl mythofable_pass ({{ pf_passed|length }}件)</h2>
    <ul class="ip-list">
        {% for ip in pf_passed %}
        <li>
            <span class="ip-text">🟢 {{ ip }}</span>
            <a href="/rescue/action?action=pf_pass_to_block&ip={{ ip }}&token={{ make_token('pf_pass_to_block', ip) }}" rel="noreferrer" class="btn-unblock">[pass→block]</a>
            <a href="/rescue/action?action=pf_pass_delete&ip={{ ip }}&token={{ make_token('pf_pass_delete', ip) }}" rel="noreferrer" style="display:inline-block;padding:8px 16px;background:#000;color:#888;border:2px solid #888;text-decoration:none;font-family:monospace;font-size:14px;border-radius:4px;">[削除]</a>
        </li>
        {% else %}
        <li><span class="empty">pfctl mythofable_passなし</span></li>
        {% endfor %}
    </ul>
</body>
</html>"""

# ─────────────────────────────────────────
# ユーティリティ
# ─────────────────────────────────────────
def read_file_lines(filepath):
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def save_file_lines(filepath, lines):
    with open(filepath, "w", encoding="utf-8") as f:
        for line in sorted(set(lines)):
            f.write(line + "\n")

def get_client_ip():
    # Tailscale経由のみ想定: X-Forwarded-Forは信頼しない
    return request.remote_addr

def render_dashboard(message=None):
    blacklisted    = read_file_lines(BLACKLIST_FILE)
    whitelisted    = read_file_lines(WHITELIST_FILE)
    logs = ""
    if os.path.exists(WATCHER_LOG):
        with open(WATCHER_LOG, "r", encoding="utf-8") as f:
            logs = "".join(reversed(f.readlines()[-20:]))
    # pfctlルール取得
    pf_rules = []
    try:
        r = subprocess.run(["/usr/bin/sudo", "/sbin/pfctl", "-s", "rules"],
                          capture_output=True, text=True, timeout=5)
        pf_rules = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        pf_rules = ["pfctl取得失敗"]
    # mythofable_block一覧取得
    pf_blocked = []
    try:
        r = subprocess.run(["/usr/bin/sudo", "/sbin/pfctl", "-a", "mythofable",
                           "-t", "mythofable_block", "-T", "show"],
                          capture_output=True, text=True, timeout=5)
        pf_blocked = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        pf_blocked = []
    pf_passed = []
    try:
        r = subprocess.run(["/usr/bin/sudo", "/sbin/pfctl", "-a", "mythofable",
                           "-t", "mythofable_pass", "-T", "show"],
                          capture_output=True, text=True, timeout=5)
        pf_passed = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        pf_passed = []
    # proxy.log から最新の不審通信を取得
    proxy_alerts = []
    proxy_log_file = "/Users/fk/Logs/proxy.log"
    if os.path.exists(proxy_log_file):
        try:
            with open(proxy_log_file, "r", encoding="utf-8") as pf:
                for line in pf:
                    line = line.strip()
                    if line:
                        try:
                            proxy_alerts.append(json.loads(line))
                        except Exception:
                            pass
            proxy_alerts = proxy_alerts[-20:]  # 最新20件
            proxy_alerts.reverse()
        except Exception:
            pass
    # exit_node_connections取得
    exit_inbound, exit_outbound = [], []
    try:
        import sqlite3 as _sq
        _con = _sq.connect(os.path.expanduser('~/MythoFable/memory.db'))
        _con.row_factory = _sq.Row
        exit_inbound  = [dict(r) for r in _con.execute(
            "SELECT * FROM exit_node_connections WHERE direction='inbound'  ORDER BY last_seen DESC LIMIT 30")]
        exit_outbound = [dict(r) for r in _con.execute(
            "SELECT * FROM exit_node_connections WHERE direction='outbound' ORDER BY last_seen DESC LIMIT 30")]
        _con.close()
    except Exception:
        pass

    return render_template_string(DASHBOARD_TEMPLATE,
                                  blacklisted=blacklisted,
                                  whitelisted=whitelisted,
                                  logs=logs,
                                  my_ip=get_client_ip(),
                                  message=message,
                                  pf_rules=pf_rules,
                                  pf_blocked=pf_blocked,
                                  pf_passed=pf_passed,
                                  proxy_alerts=proxy_alerts,
                                  exit_inbound=exit_inbound,
                                  exit_outbound=exit_outbound,
                                  services=get_services_status())

# ─────────────────────────────────────────
# ① ヘルスチェックエンドポイント
# ─────────────────────────────────────────
@app.route('/exit_node/data')
def exit_node_data():
    client_ip = get_client_ip()
    if client_ip in read_file_lines(BLACKLIST_FILE):
        return json.dumps({"inbound":[],"outbound":[]}), 403
    inbound, outbound = [], []
    try:
        import sqlite3 as _sq
        _con = _sq.connect(os.path.expanduser('~/MythoFable/memory.db'))
        _con.row_factory = _sq.Row
        inbound  = [dict(r) for r in _con.execute(
            "SELECT * FROM exit_node_connections WHERE direction='inbound'  ORDER BY last_seen DESC LIMIT 30")]
        outbound = [dict(r) for r in _con.execute(
            "SELECT * FROM exit_node_connections WHERE direction='outbound' ORDER BY last_seen DESC LIMIT 30")]
        _con.close()
    except Exception:
        pass
    from flask import Response as _Resp
    return _Resp(json.dumps({"inbound":inbound,"outbound":outbound},ensure_ascii=False),
                 mimetype='application/json')

@app.route('/reports')
def reports_page():
    client_ip = get_client_ip()
    if client_ip in read_file_lines(BLACKLIST_FILE):
        return render_template_string(BLOCKED_TEMPLATE, ip=client_ip), 403
    return render_template_string(REPORTS_TEMPLATE, agent_reports=load_agent_reports(20))

@app.route('/redteam')
def redteam_page():
    client_ip = get_client_ip()
    if client_ip in read_file_lines(BLACKLIST_FILE):
        return render_template_string(BLOCKED_TEMPLATE, ip=client_ip), 403
    reports = load_redteam_reports(50)
    counts = {}
    for r in reports:
        counts[r.get("outcome", "?")] = counts.get(r.get("outcome", "?"), 0) + 1
    return render_template_string(REDTEAM_TEMPLATE, reports=reports, counts=counts)

@app.route('/test_attack')
def test_attack():
    import json, datetime, random
    sev = request.args.get('sev', 'HIGH').upper()
    token = request.args.get('token', '')
    if not verify_token('test_attack', sev, token):
        return 'Forbidden', 403
    if sev not in ('HIGH','MEDIUM','LOW'):
        sev = 'HIGH'
    now = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    fake_ips = ['198.51.100.1','203.0.113.42','192.0.2.99','10.20.30.40','172.16.0.5']
    pattern_pool = {
        'HIGH':   ['SSH Brute Force','Port Scan','RootKit'],
        'MEDIUM': ['HTTP Scan','Web Crawl','Login Attempt'],
        'LOW':    ['Ping Sweep','DNS Lookup','FTP Probe'],
    }
    ip = random.choice(fake_ips)
    pats = random.sample(pattern_pool[sev], k=random.randint(1,2))
    entry = {
        "timestamp"  : now,
        "attacker_ip": ip,
        "severity"   : sev,
        "patterns"   : pats,
        "summary"    : f"[TEST] {sev}レベル攻撃を{ip}から検知。パターン: {', '.join(pats)}",
        "actions"    : ["ブロック", "ログ記録"]
    }
    reports_file = os.path.join(BASE_DIR, "agent_reports.jsonl")
    with open(reports_file, 'a', encoding='utf-8') as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + '\n')
    blacklist = read_file_lines(BLACKLIST_FILE)
    if ip not in blacklist:
        blacklist.append(ip)
        save_file_lines(BLACKLIST_FILE, blacklist)
        write_log(f"[TEST-BLOCK] {ip} をブラックリストに登録")
    # mythofable_block テーブルにも追加
    try:
        subprocess.run(
            ["/usr/bin/sudo", "/sbin/pfctl", "-a", "mythofable", "-t", "mythofable_block", "-T", "add", ip],
            capture_output=True, text=True, timeout=5
        )
        write_log(f"[TEST-BLOCK] pfctl mythofable_block に {ip} を追加")
    except Exception as e:
        write_log(f"[TEST-BLOCK] pfctl追加失敗: {e}")
    msg = f"🧪 テストレポート追加 & ブロック: {sev} / {ip}"
    next_page = request.args.get("next", "")
    if next_page == "test_port":
        from urllib.parse import quote
        return redirect(f"/test_port?msg={quote(msg)}")
    return render_dashboard(message=msg)

@app.route('/patches')
def patches_page():
    import glob
    client_ip = get_client_ip()
    if client_ip in read_file_lines(BLACKLIST_FILE):
        return render_template_string(BLOCKED_TEMPLATE, ip=client_ip), 403
    cdir = os.path.join(BASE_DIR, 'patch_candidates')
    candidates = []
    for fp in sorted(glob.glob(os.path.join(cdir, '*.json')), reverse=True):
        try:
            with open(fp, 'r', encoding='utf-8') as f:
                d = json.load(f)
                d['filename'] = os.path.basename(fp)
            candidates.append(d)
        except Exception:
            pass
    return render_template_string(PATCHES_TEMPLATE, candidates=candidates)

@app.route('/patches/apply')
def patches_apply():
    import glob, ast as ast_mod, shutil
    client_ip = get_client_ip()
    if client_ip in read_file_lines(BLACKLIST_FILE):
        return render_template_string(BLOCKED_TEMPLATE, ip=client_ip), 403
    filename = request.args.get('file', '')
    token    = request.args.get('token', '')
    if not filename or not verify_token('patch_apply', filename, token):
        return 'Forbidden', 403
    cdir  = os.path.join(BASE_DIR, 'patch_candidates')
    fpath = os.path.join(cdir, filename)
    if not os.path.exists(fpath):
        return render_dashboard(message='❌ パッチ候補ファイルが見つかりません')
    try:
        with open(fpath, 'r', encoding='utf-8') as f:
            d = json.load(f)
        if d.get('status') == 'applied':
            return render_dashboard(message='ℹ️ このパッチは既に適用済みです')
        target = d.get('file', '')
        if not os.path.exists(target):
            return render_dashboard(message=f'❌ 対象ファイルが見つかりません: {target}')
        # バックアップ作成
        shutil.copy(target, target + '.pre_manual_patch')
        with open(target, 'r', encoding='utf-8') as f:
            code = f.read()
        import re
        if d.get('ai_patch'):
            # ★ AI(OpenCode)生成パッチを使用（手動レビュー済み前提）
            patched = d['ai_patch']
        else:
            # 脆弱性箇所の置換（SQLi f-string → パラメータ化クエリ）
            patched = re.sub(
                r'(\s*query\s*=\s*)f(["\'])(.+?)["\']',
                lambda m: m.group(1) + m.group(2) + re.sub(r"\{[^}]+\}", "?", m.group(3)) + m.group(2) + "  # [PATCHED]",
                code
            )
        # 構文チェック
        try:
            ast_mod.parse(patched)
        except SyntaxError as e:
            return render_dashboard(message=f'❌ パッチ適用失敗（構文エラー）: {e}')
        with open(target, 'w', encoding='utf-8') as f:
            f.write(patched)
        # ステータス更新
        d['status'] = 'applied'
        d['applied_at'] = __import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        d['applied_by'] = 'manual'
        with open(fpath, 'w', encoding='utf-8') as f:
            json.dump(d, f, ensure_ascii=False, indent=2)
        write_watcher_log(f'[PATCH] ✅ 手動パッチ適用: {os.path.basename(target)}')
        return render_dashboard(message=f'✅ パッチ適用完了: {os.path.basename(target)}')
    except Exception as e:
        return render_dashboard(message=f'❌ パッチ適用エラー: {e}')

@app.route('/test_port')
def test_port_page():
    client_ip = get_client_ip()
    if client_ip in read_file_lines(BLACKLIST_FILE):
        return render_template_string(BLOCKED_TEMPLATE, ip=client_ip), 403
    # pfctlルール取得
    pf_rules = []
    try:
        r = subprocess.run(['/usr/bin/sudo','/sbin/pfctl','-s','rules'], capture_output=True, text=True, timeout=5)
        pf_rules = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        pf_rules = ['pfctl取得失敗']
    # Tailscale IP確認
    tailscale_ip = 'unknown'
    try:
        r = subprocess.run(['ifconfig'], capture_output=True, text=True)
        import re
        m = re.search(r'inet (100\.\d+\.\d+\.\d+)', r.stdout)
        if m:
            tailscale_ip = m.group(1)
    except Exception:
        pass
    # Tailscale経由チェック（100.64.0.0/10）
    import ipaddress
    try:
        tailscale_ok = ipaddress.ip_address(client_ip) in ipaddress.ip_network('100.64.0.0/10')
    except Exception:
        tailscale_ok = False
    # pfctl mythofable_block一覧
    pf_blocked = []
    try:
        r = subprocess.run(['/usr/bin/sudo','/sbin/pfctl','-a','mythofable','-t','mythofable_block','-T','show'],
                          capture_output=True, text=True, timeout=5)
        pf_blocked = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        pass
    test_result = request.args.get('result', '').split('|') if request.args.get('result') else []
    msg = request.args.get('msg', '')
    if msg:
        test_result = [msg] + test_result
    return render_template_string(TEST_PORT_TEMPLATE,
        pf_rules=pf_rules, tailscale_ip=tailscale_ip,
        tailscale_ok=tailscale_ok, my_ip=client_ip,
        pf_blocked=pf_blocked, test_result=test_result)

@app.route('/test_port/run')
def test_port_run():
    client_ip = get_client_ip()
    if client_ip in read_file_lines(BLACKLIST_FILE):
        return render_template_string(BLOCKED_TEMPLATE, ip=client_ip), 403
    token = request.args.get('token','')
    if not verify_token('test_port', 'run', token):
        return 'Forbidden', 403
    results = []
    TEST_IP = '192.0.2.254'  # テスト用ダミーIP（RFC5737）
    try:
        # BL追加
        bl = read_file_lines(BLACKLIST_FILE)
        if TEST_IP not in bl:
            bl.append(TEST_IP)
            with open(BLACKLIST_FILE, 'w') as f:
                for ip in sorted(set(bl)):
                    f.write(ip + '\n')
        results.append(f'✅ テストIP {TEST_IP} をBLに追加')
        # pfctl追加
        r = subprocess.run(['/usr/bin/sudo','/sbin/pfctl','-a','mythofable','-t','mythofable_block','-T','add', TEST_IP],
                          capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            results.append(f'✅ pfctl mythofable_block に {TEST_IP} を追加')
        else:
            results.append(f'⚠️ pfctl追加: {r.stderr.strip()}')
        # pfctl確認
        r = subprocess.run(['/usr/bin/sudo','/sbin/pfctl','-a','mythofable','-t','mythofable_block','-T','show'],
                          capture_output=True, text=True, timeout=5)
        if TEST_IP in r.stdout:
            results.append(f'✅ pfctl確認: {TEST_IP} がブロックリストに存在')
        else:
            results.append(f'❌ pfctl確認: {TEST_IP} が見つからない')
        # 解除
        bl = read_file_lines(BLACKLIST_FILE)
        if TEST_IP in bl:
            bl.remove(TEST_IP)
            with open(BLACKLIST_FILE, 'w') as f:
                for ip in sorted(set(bl)):
                    f.write(ip + '\n')
        r = subprocess.run(['/usr/bin/sudo','/sbin/pfctl','-a','mythofable','-t','mythofable_block','-T','delete', TEST_IP],
                          capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            results.append(f'✅ {TEST_IP} をBL・pfctlから解除完了')
        else:
            results.append(f'⚠️ pfctl解除: {r.stderr.strip()}')
        results.append('✅ テスト完了！BL+pfctl連携は正常です')
    except Exception as e:
        results.append(f'❌ テストエラー: {e}')
    from urllib.parse import quote
    return redirect(f'/test_port?result={quote("|".join(results))}')

@app.route('/log_clear_all')
def log_clear_all():
    import shutil as _shutil, datetime as _dt, glob as _glob
    client_ip = get_client_ip()
    if client_ip in read_file_lines(BLACKLIST_FILE):
        return render_template_string(BLOCKED_TEMPLATE, ip=client_ip), 403
    token = request.args.get('token', '')
    if not verify_token('log_clear_all', 'all', token):
        return 'Forbidden', 403
    log_names = [
        'watcher_stdout.log', 'proxy.log', 'agent_stdout.log',
        'dashboard.log', 'web_attack.log', 'health_check.log',
        'agent_stderr.log', 'watcher_stderr.log', 'dashboard_run.log'
    ]
    ts = _dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = os.path.join(BASE_DIR, 'backups', ts)
    os.makedirs(backup_dir, exist_ok=True)
    cleared = []
    for lname in log_names:
        lpath = os.path.join("/Users/fk/Logs", lname)
        if os.path.exists(lpath):
            _shutil.copy2(lpath, os.path.join(backup_dir, lname))
            with open(lpath, 'w', encoding='utf-8') as fh:
                fh.write(f'[{_dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}] ── ログクリア実施 ──\n')
            cleared.append(lname)
    # 古いバックアップを削除（3世代以上）
    old_backups = sorted(_glob.glob(os.path.join(BASE_DIR, 'backups', '*')))
    for old in old_backups[:-3]:
        _shutil.rmtree(old, ignore_errors=True)
    write_watcher_log(f'[LOG_CLEAR] 🗑️ 全ログクリア ({len(cleared)}件) → backups/{ts}/')
    from urllib.parse import quote
    msg = f'✅ {len(cleared)}件のログをクリアしました（バックアップ: backups/{ts}/）'
    return redirect(f'/logs?msg={quote(msg)}')

@app.route('/log_clear')
def log_clear():
    import shutil as _shutil
    client_ip = get_client_ip()
    if client_ip in read_file_lines(BLACKLIST_FILE):
        return render_template_string(BLOCKED_TEMPLATE, ip=client_ip), 403
    log_name = request.args.get('log', '')
    token    = request.args.get('token', '')
    if not log_name or not verify_token('log_clear', log_name, token):
        return 'Forbidden', 403
    # 許可されたログファイルのみ
    allowed_logs = [
        'watcher_stdout.log', 'proxy.log', 'agent_stdout.log',
        'dashboard.log', 'web_attack.log', 'health_check.log',
        'agent_stderr.log', 'watcher_stderr.log', 'dashboard_run.log'
    ]
    if log_name not in allowed_logs:
        return 'Invalid log name', 400
    log_path = os.path.join("/Users/fk/Logs", log_name)
    if not os.path.exists(log_path):
        return render_dashboard(message=f'⚠️ {log_name} は存在しません')
    # バックアップ（3世代管理）
    import datetime as _dt, glob as _glob
    ts = _dt.datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_dir = os.path.join(BASE_DIR, 'backups', ts)
    os.makedirs(backup_dir, exist_ok=True)
    _shutil.copy2(log_path, os.path.join(backup_dir, log_name))
    # 古いバックアップを削除（3世代以上）
    old_backups = sorted(_glob.glob(os.path.join(BASE_DIR, 'backups', '*')))
    for old in old_backups[:-3]:
        _shutil.rmtree(old, ignore_errors=True)
    # ログをクリア
    with open(log_path, 'w', encoding='utf-8') as fh:
        fh.write(f'[{_dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}] ── ログクリア実施 ──\n')
    write_watcher_log(f'[LOG_CLEAR] 🗑️ {log_name} をバックアップ後クリア → backups/{ts}/')
    _next = request.args.get("next", "")
    _msg = f"✅ {log_name} をクリアしました（バックアップ: backups/{ts}/）"
    if _next == "logs":
        from urllib.parse import quote
        return redirect(f"/logs?msg={quote(_msg)}")
    return render_dashboard(message=_msg)

@app.route('/logs')
def logs_page():
    import datetime as _dt
    client_ip = get_client_ip()
    if client_ip in read_file_lines(BLACKLIST_FILE):
        return render_template_string(BLOCKED_TEMPLATE, ip=client_ip), 403
    log_names = [
        "watcher_stdout.log", "proxy.log", "agent_stdout.log",
        "dashboard.log", "web_attack.log", "health_check.log",
        "agent_stderr.log", "watcher_stderr.log", "dashboard_run.log"
    ]
    log_files = []
    for lname in log_names:
        lpath = os.path.join("/Users/fk/Logs", lname)
        if os.path.exists(lpath):
            sz = os.path.getsize(lpath)
            size_str = f"{sz}B" if sz < 1024 else (f"{sz//1024}KB" if sz < 1024*1024 else f"{sz//1024//1024}MB")
            mtime = _dt.datetime.fromtimestamp(os.path.getmtime(lpath)).strftime("%m/%d %H:%M")
            # 末尾3行プレビュー
            preview = ""
            try:
                with open(lpath, "r", encoding="utf-8", errors="ignore") as pf:
                    lines = pf.readlines()
                    preview = "".join(lines[-3:]).strip()
            except Exception:
                pass
            log_files.append({"name": lname, "size": size_str, "mtime": mtime, "preview": preview})
    msg = request.args.get("msg", "")
    return render_template_string(LOGS_TEMPLATE, log_files=log_files, message=msg)


# サービス定義
SERVICES_DEF = [
    {"id": "proxy_watcher",  "name": "proxy_watcher",  "desc": "Tailscale通信監視（cron 10分）",   "kind": "cron",    "cron_key": "proxy_watcher.py"},
    {"id": "auto_recovery",  "name": "auto_recovery",  "desc": "誤検知IP自動解除（cron 5分）",     "kind": "cron",    "cron_key": "auto_recovery.py"},
    {"id": "auto_patcher",   "name": "auto_patcher",   "desc": "脆弱性自動パッチ（cron 7,37分）",  "kind": "cron",    "cron_key": "auto_patcher.py"},
    {"id": "health_check",   "name": "health_check",   "desc": "死活監視（cron 5分）",             "kind": "cron",    "cron_key": "health_check.sh"},
    {"id": "log_watcher",    "name": "log_watcher",    "desc": "攻撃ログ監視・AI起動",             "kind": "launchd", "label": "com.mythofable.logwatcher"},
]

def get_crontab():
    import subprocess as _sp
    r = _sp.run(['crontab', '-l'], capture_output=True, text=True)
    return r.stdout

def set_crontab(content):
    import subprocess as _sp
    _sp.run(['crontab', '-'], input=content, text=True)

def is_cron_active(key):
    for line in get_crontab().splitlines():
        if key in line and not line.strip().startswith('#'):
            return True
    return False

def is_launchd_active(label):
    import subprocess as _sp
    r = _sp.run(['launchctl', 'list', label], capture_output=True, text=True)
    if r.returncode != 0:
        return False
    # PIDが存在すれば稼働中
    return '"PID"' in r.stdout

def get_services_status():
    services = []
    for svc in SERVICES_DEF:
        s = dict(svc)
        if svc['kind'] == 'cron':
            s['active'] = is_cron_active(svc['cron_key'])
        else:
            s['active'] = is_launchd_active(svc['label'])
        services.append(s)
    return services

@app.route('/services')
def services_page():
    client_ip = get_client_ip()
    if client_ip in read_file_lines(BLACKLIST_FILE):
        return render_template_string(BLOCKED_TEMPLATE, ip=client_ip), 403
    msg = request.args.get('msg', '')
    return render_template_string(SERVICES_TEMPLATE,
        services=get_services_status(), message=msg)

@app.route('/service_ctrl')
def service_ctrl():
    from urllib.parse import quote
    client_ip = get_client_ip()
    if client_ip in read_file_lines(BLACKLIST_FILE):
        return render_template_string(BLOCKED_TEMPLATE, ip=client_ip), 403
    svc_id = request.args.get('svc', '')
    action = request.args.get('action', '')
    token  = request.args.get('token', '')
    if not svc_id or action not in ('start','stop') or not verify_token('service_ctrl', svc_id, token):
        return 'Forbidden', 403
    svc = next((s for s in SERVICES_DEF if s['id'] == svc_id), None)
    if not svc:
        return 'Unknown service', 400

    if svc['kind'] == 'cron':
        lines = get_crontab().splitlines()
        new_lines = []
        changed = False
        for line in lines:
            if svc['cron_key'] in line:
                if action == 'stop' and not line.strip().startswith('#'):
                    new_lines.append('# ' + line)
                    changed = True
                elif action == 'start' and line.strip().startswith('#'):
                    new_lines.append(line.lstrip('# '))
                    changed = True
                else:
                    new_lines.append(line)
            else:
                new_lines.append(line)
        set_crontab('\n'.join(new_lines) + '\n')
        label = '一時停止' if action == 'stop' else '再開'
        msg = f"{'⏸️' if action=='stop' else '▶️'} {svc['name']} を{label}しました"

    else:  # launchd
        import subprocess as _sp
        # plistパスを取得
        plist = os.path.expanduser(f"~/Library/LaunchAgents/{svc['label']}.plist")
        if action == 'stop':
            _sp.run(['launchctl', 'unload', plist], capture_output=True)
            msg = f"⏸️ {svc['name']} を一時停止しました"
        else:
            _sp.run(['launchctl', 'load', plist], capture_output=True)
            msg = f"▶️ {svc['name']} を再開しました"

    write_watcher_log(f'[SERVICE] {msg}')
    return redirect(f'/services?msg={quote(msg)}')

@app.route('/test_proxy')
def test_proxy():
    import json, datetime, random
    from urllib.parse import quote
    client_ip = get_client_ip()
    if client_ip in read_file_lines(BLACKLIST_FILE):
        return render_template_string(BLOCKED_TEMPLATE, ip=client_ip), 403
    sev   = request.args.get('sev', 'HIGH').upper()
    action = request.args.get('action', '')
    token = request.args.get('token', '')

    key = action if action else sev
    if not verify_token('test_proxy', key, token):
        return 'Forbidden', 403

    proxy_log_file = os.path.join(BASE_DIR, 'proxy.log')

    # テストデータクリア
    if action == 'clear':
        if os.path.exists(proxy_log_file):
            lines = []
            with open(proxy_log_file, 'r', encoding='utf-8') as pf:
                for line in pf:
                    try:
                        d = json.loads(line.strip())
                        if not d.get('test'):
                            lines.append(line)
                    except Exception:
                        lines.append(line)
            with open(proxy_log_file, 'w', encoding='utf-8') as pf:
                pf.writelines(lines)
        msg = '🗑️ テストデータをクリアしました'
        return redirect(f'/test_port?msg={quote(msg)}')

    # テストデータ追加
    fake_ips = ['198.51.100.10','203.0.113.50','192.0.2.100']
    suspicious = {
        'HIGH':   [('4444','C2サーバ通信の疑い'), ('1433','SQLサーバへの不審接続'), ('3389','RDP接続試行')],
        'MEDIUM': [('8080','HTTPプロキシへの接続'), ('6379','Redisへの不審接続')],
        'LOW':    [('8888','非標準ポートへの接続'), ('9999','不明ポートへの接続')],
    }
    ip = random.choice(fake_ips)
    port, reason = random.choice(suspicious.get(sev, suspicious['LOW']))
    entry = {
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'src_ip'   : '100.109.207.78',
        'dst_ip'   : ip,
        'dst_port' : int(port),
        'count'    : random.randint(1, 10),
        'host'     : f'suspicious-{ip.replace(".", "-")}.example.com',
        'reason'   : f'[TEST] {reason}',
        'severity' : sev,
        'action'   : '自動ブロック' if sev == 'HIGH' else ('要確認' if sev == 'MEDIUM' else '記録のみ'),
        'test'     : True
    }
    with open(proxy_log_file, 'a', encoding='utf-8') as pf:
        pf.write(json.dumps(entry, ensure_ascii=False) + '\n')
    msg = f'🔍 プロキシテストデータ追加: {sev} / {ip}:{port}'
    return redirect(f'/test_port?msg={quote(msg)}')

@app.route('/health')
def health():
    """死活監視用JSONエンドポイント。外部cronやTailscale越しの監視に使用"""
    blacklist = read_file_lines(BLACKLIST_FILE)
    whitelist = read_file_lines(WHITELIST_FILE)

    # log_watcher.py の死活確認
    watcher_alive = False
    try:
        result = subprocess.run(['pgrep', '-f', 'log_watcher.py'],
                                capture_output=True, timeout=3)
        watcher_alive = result.returncode == 0
    except Exception:
        pass

    # watcher_stdout.log の最終更新時刻
    last_log_ts  = None
    last_log_ago = None
    if os.path.exists(WATCHER_LOG):
        mtime = os.path.getmtime(WATCHER_LOG)
        last_log_ts  = datetime.datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')
        last_log_ago = int(time.time() - mtime)

    # agent_stdout.log の最終更新時刻
    agent_log = os.path.join(BASE_DIR, "agent_stdout.log")
    last_agent_ts = None
    if os.path.exists(agent_log):
        mtime = os.path.getmtime(agent_log)
        last_agent_ts = datetime.datetime.fromtimestamp(mtime).strftime('%Y-%m-%d %H:%M:%S')

    # pfctl の有効状態確認
    pf_enabled = False
    try:
        r = subprocess.run(['sudo', 'pfctl', '-s', 'info'],
                           capture_output=True, text=True, timeout=3)
        pf_enabled = 'Enabled' in r.stdout
    except Exception:
        pass

    status = {
        "status"          : "ok",
        "timestamp"       : datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "blacklist_count" : len(blacklist),
        "whitelist_count" : len(whitelist),
        "watcher_alive"   : watcher_alive,
        "pf_enabled"      : pf_enabled,
        "last_watcher_log": last_log_ts,
        "last_watcher_ago_sec": last_log_ago,
        "last_agent_log"  : last_agent_ts,
    }
    return Response(
        json.dumps(status, ensure_ascii=False, indent=2),
        status=200,
        mimetype='application/json'
    )

# ─────────────────────────────────────────
# ④ グラフデータAPIエンドポイント
# ─────────────────────────────────────────
@app.route('/chart_data')
def chart_data():
    """グラフ用集計データをJSONで返すエンドポイント"""
    data = get_chart_data()
    return Response(
        json.dumps(data, ensure_ascii=False),
        status=200,
        mimetype='application/json'
    )

# ─────────────────────────────────────────
# ルート: 管理画面
# ─────────────────────────────────────────
@app.route('/')
@app.route('/admin')
def admin_page():
    client_ip = get_client_ip()
    if client_ip in read_file_lines(BLACKLIST_FILE):
        return render_template_string(BLOCKED_TEMPLATE, ip=client_ip), 403
    try:
        r = subprocess.run(["/usr/bin/sudo", "/sbin/pfctl", "-a", "mythofable",
                           "-t", "mythofable_block", "-T", "show"],
                          capture_output=True, text=True, timeout=5)
        pf_block_ips = [l.strip() for l in r.stdout.splitlines() if l.strip()]
        if client_ip in pf_block_ips:
            return render_template_string(BLOCKED_TEMPLATE, ip=client_ip), 403
    except Exception:
        pass
    return render_dashboard()

# ─────────────────────────────────────────
# ルート: 通常/不正アクセスボタン
# ─────────────────────────────────────────
@app.route('/access', methods=['GET', 'OPTIONS'])
def access():
    if request.method == 'OPTIONS':
        return '', 204

    act   = request.args.get('action', '')
    ip    = request.args.get('ip', '')
    token = request.args.get('token', '')

    if not ip or not verify_token(act, ip, token):
        return "Unauthorized", 403

    req_key = f"{act}:{ip}"
    if is_duplicate_request(req_key):
        return "Duplicate request", 429

    blacklist = read_file_lines(BLACKLIST_FILE)
    whitelist = read_file_lines(WHITELIST_FILE)

    if act == 'allow':
        if ip in blacklist:
            blacklist.remove(ip)
            save_file_lines(BLACKLIST_FILE, blacklist)
        if ip not in whitelist:
            whitelist.append(ip)
            save_file_lines(WHITELIST_FILE, whitelist)
            write_log(f"[ALLOW] {ip} をホワイトリストに登録")
            write_watcher_log(f"[ALLOW] ✅ {ip} をホワイトリストに登録しました")
        _next = request.args.get("next", "")
        _msg = f"✅ {ip} を通常アクセス（whitelist）に登録しました"
        if _next == "test_port":
            from urllib.parse import quote
            return redirect(f"/test_port?msg={quote(_msg)}")
        return render_dashboard(message=_msg)

    elif act == 'deny':
        if ip in whitelist:
            whitelist.remove(ip)
            save_file_lines(WHITELIST_FILE, whitelist)
        if ip not in blacklist:
            blacklist.append(ip)
            save_file_lines(BLACKLIST_FILE, blacklist)
            write_log(f"[DENY] {ip} をブラックリストに登録")
            write_watcher_log(f"[DENY] 🚫 {ip} をブラックリストに登録しました")
        import json, datetime
        entry = {
            "timestamp"  : datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "attacker_ip": ip,
            "severity"   : "HIGH",
            "patterns"   : ["Manual Block"],
            "summary"    : f"[手動] 不正アクセスとして {ip} をブロックしました",
            "actions"    : ["ブラックリスト登録"]
        }
        reports_file = os.path.join(BASE_DIR, "agent_reports.jsonl")
        with open(reports_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        _next2 = request.args.get("next", "")
        if _next2 == "test_port":
            from urllib.parse import quote
            _msg2 = f"🚫 {ip} をブラックリストに登録しました"
            return redirect(f"/test_port?msg={quote(_msg2)}")
        return render_template_string(BLOCKED_TEMPLATE, ip=ip), 403

    return "Invalid action", 400

# ─────────────────────────────────────────
# ルート: 管理画面からのIP操作
# ─────────────────────────────────────────
@app.route('/action', methods=['GET', 'OPTIONS'])
def action():
    if request.method == 'OPTIONS':
        return '', 204

    act   = request.args.get('action', '')
    ip    = request.args.get('ip', '')
    token = request.args.get('token', '')

    if not ip or not verify_token(act, ip, token):
        return "Unauthorized", 403

    req_key = f"action:{act}:{ip}"
    if is_duplicate_request(req_key):
        return "Duplicate request", 429

    blacklist = read_file_lines(BLACKLIST_FILE)
    whitelist = read_file_lines(WHITELIST_FILE)

    if act == 'unblock':
        if ip in blacklist:
            blacklist.remove(ip)
            save_file_lines(BLACKLIST_FILE, blacklist)
            write_watcher_log(f"[UNBLOCK] 🔓 {ip} をブラックリストから解除しました")
        return render_dashboard(message=f"✅ {ip} をブラックリストから解除しました")

    elif act == 'to_whitelist':
        if ip in blacklist:
            blacklist.remove(ip)
            save_file_lines(BLACKLIST_FILE, blacklist)
        if ip not in whitelist:
            whitelist.append(ip)
            save_file_lines(WHITELIST_FILE, whitelist)
            write_watcher_log(f"[MOVE] 🔄 {ip} をブラックリストからホワイトリストへ移動しました")
        return render_dashboard(message=f"✅ {ip} をホワイトリストへ移動しました")

    elif act == 'to_blacklist':
        if ip in whitelist:
            whitelist.remove(ip)
            save_file_lines(WHITELIST_FILE, whitelist)
        if ip not in blacklist:
            blacklist.append(ip)
            save_file_lines(BLACKLIST_FILE, blacklist)
            write_watcher_log(f"[MOVE] 🚫 {ip} をホワイトリストからブラックリストへ移動しました")
        return render_template_string(BLOCKED_TEMPLATE, ip=ip), 403

    elif act == 'delete_white':
        if ip in whitelist:
            whitelist.remove(ip)
            save_file_lines(WHITELIST_FILE, whitelist)
            write_watcher_log(f"[DELETE] 🗑 {ip} をホワイトリストから削除しました")
        return render_dashboard(message=f"✅ {ip} をホワイトリストから削除しました")

    return "Invalid action", 400

# ─────────────────────────────────────────
# ルート: Rescue画面
# ─────────────────────────────────────────
@app.route('/rescue')
def rescue():
    blacklisted  = read_file_lines(BLACKLIST_FILE)
    whitelisted  = read_file_lines(WHITELIST_FILE)
    pf_blocked, pf_passed = [], []
    try:
        r = subprocess.run(["/usr/bin/sudo", "/sbin/pfctl", "-a", "mythofable",
                           "-t", "mythofable_block", "-T", "show"],
                          capture_output=True, text=True, timeout=5)
        pf_blocked = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        pass
    try:
        r = subprocess.run(["/usr/bin/sudo", "/sbin/pfctl", "-a", "mythofable",
                           "-t", "mythofable_pass", "-T", "show"],
                          capture_output=True, text=True, timeout=5)
        pf_passed = [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except Exception:
        pass
    return render_template_string(RESCUE_TEMPLATE, blacklisted=blacklisted,
                                  whitelisted=whitelisted,
                                  pf_blocked=pf_blocked, pf_passed=pf_passed, message=None)

@app.route('/rescue/action', methods=['GET', 'OPTIONS'])
def rescue_action():
    if request.method == 'OPTIONS':
        return '', 204

    act   = request.args.get('action', '')
    ip    = request.args.get('ip', '')
    token = request.args.get('token', '')

    if not ip or not verify_token(act, ip, token):
        return "Unauthorized", 403

    req_key = f"rescue:{act}:{ip}"
    if is_duplicate_request(req_key):
        return "Duplicate request", 429

    blacklist = read_file_lines(BLACKLIST_FILE)
    whitelist = read_file_lines(WHITELIST_FILE)

    def pf_add(table, target_ip):
        subprocess.run(["/usr/bin/sudo", "/sbin/pfctl", "-a", "mythofable",
                       "-t", table, "-T", "add", target_ip],
                      capture_output=True, timeout=5)

    def pf_del(table, target_ip):
        subprocess.run(["/usr/bin/sudo", "/sbin/pfctl", "-a", "mythofable",
                       "-t", table, "-T", "delete", target_ip],
                      capture_output=True, timeout=5)

    if act == 'unblock':
        if ip in blacklist:
            blacklist.remove(ip)
            save_file_lines(BLACKLIST_FILE, blacklist)
            write_watcher_log(f"[RESCUE] 🔓 {ip} をブラックリストから解除しました")
        return render_dashboard(message=f"✅ {ip} をブラックリストから解除しました")

    elif act == 'to_whitelist':
        if ip in blacklist:
            blacklist.remove(ip)
            save_file_lines(BLACKLIST_FILE, blacklist)
        if ip not in whitelist:
            whitelist.append(ip)
            save_file_lines(WHITELIST_FILE, whitelist)
            write_watcher_log(f"[RESCUE] 🔄 {ip} をホワイトリストへ移動しました")
        return render_dashboard(message=f"✅ {ip} をホワイトリストへ移動しました")

    elif act == 'unblock':
        if ip in blacklist:
            blacklist.remove(ip)
            save_file_lines(BLACKLIST_FILE, blacklist)
        write_watcher_log(f"[RESCUE] 🔓 {ip} をBLから解除")
        return redirect(f'/rescue?msg={ip}+BL解除完了')

    # BL→WL
    elif act == 'bl_to_wl':
        if ip in blacklist:
            blacklist.remove(ip)
            save_file_lines(BLACKLIST_FILE, blacklist)
        if ip not in whitelist:
            whitelist.append(ip)
            save_file_lines(WHITELIST_FILE, whitelist)
        write_watcher_log(f"[RESCUE] 🔄 {ip} BL→WL移動")
        return redirect('/rescue')

    # BL削除
    elif act == 'bl_delete':
        if ip in blacklist:
            blacklist.remove(ip)
            save_file_lines(BLACKLIST_FILE, blacklist)
        write_watcher_log(f"[RESCUE] 🗑️ {ip} BLから削除")
        return redirect('/rescue')

    # WL→BL
    elif act == 'wl_to_bl':
        if ip in whitelist:
            whitelist.remove(ip)
            save_file_lines(WHITELIST_FILE, whitelist)
        if ip not in blacklist:
            blacklist.append(ip)
            save_file_lines(BLACKLIST_FILE, blacklist)
        write_watcher_log(f"[RESCUE] 🔄 {ip} WL→BL移動")
        return redirect('/rescue')

    # WL削除
    elif act == 'wl_delete':
        if ip in whitelist:
            whitelist.remove(ip)
            save_file_lines(WHITELIST_FILE, whitelist)
        write_watcher_log(f"[RESCUE] 🗑️ {ip} WLから削除")
        return redirect('/rescue')

    # pfctl mythofable_block → mythofable_pass
    elif act == 'pf_block_to_pass':
        try:
            pf_del('mythofable_block', ip)
            pf_add('mythofable_pass', ip)
            write_watcher_log(f"[RESCUE] 🔄 {ip} pfctl block→pass移動")
        except Exception as e:
            write_watcher_log(f"[RESCUE] ⚠️ pfctl block→pass失敗: {e}")
        return redirect('/rescue')

    # pfctl mythofable_block削除
    elif act == 'pf_block_delete':
        try:
            pf_del('mythofable_block', ip)
            write_watcher_log(f"[RESCUE] 🗑️ {ip} pfctl mythofable_blockから削除")
        except Exception as e:
            write_watcher_log(f"[RESCUE] ⚠️ pfctl block削除失敗: {e}")
        return redirect('/rescue')

    # pfctl mythofable_pass → mythofable_block
    elif act == 'pf_pass_to_block':
        try:
            pf_del('mythofable_pass', ip)
            pf_add('mythofable_block', ip)
            write_watcher_log(f"[RESCUE] 🔄 {ip} pfctl pass→block移動")
        except Exception as e:
            write_watcher_log(f"[RESCUE] ⚠️ pfctl pass→block失敗: {e}")
        return redirect('/rescue')

    # pfctl mythofable_pass削除
    elif act == 'pf_pass_delete':
        try:
            pf_del('mythofable_pass', ip)
            write_watcher_log(f"[RESCUE] 🗑️ {ip} pfctl mythofable_passから削除")
        except Exception as e:
            write_watcher_log(f"[RESCUE] ⚠️ pfctl pass削除失敗: {e}")
        return redirect('/rescue')

    return "Invalid action", 400

# ─────────────────────────────────────────
# 起動
# ─────────────────────────────────────────
if __name__ == '__main__':
    cert_dir = os.path.expanduser("~/MythoFable")
    crt = os.path.join(cert_dir, "hz-k-2mba14.tailb82610.ts.net.crt")
    key = os.path.join(cert_dir, "hz-k-2mba14.tailb82610.ts.net.key")
    app.run(host='0.0.0.0', port=5000, ssl_context=(crt, key), debug=False)

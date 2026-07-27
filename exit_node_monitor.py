#!/usr/bin/env python3
"""
exit_node_monitor.py - Tailscale exit node IP監視
cron監視: */5 * * * * ~/MythoFable/.venv/bin/python3 ~/MythoFable/exit_node_monitor.py
cronクリーン: 0 * * * * ~/MythoFable/.venv/bin/python3 ~/MythoFable/exit_node_monitor.py --cleanup
"""
import os, sys, re, sqlite3, datetime, subprocess

BASE_DIR = os.path.expanduser("~/MythoFable")
DB_PATH  = os.path.join(BASE_DIR, "memory.db")
LOG_PATH = "/Users/fk/Logs/exit_node_monitor.log"

TAILSCALE_PREFIX = "100."
PRIVATE_PREFIXES = ("10.","172.16.","172.17.","172.18.","172.19.","172.20.",
                    "172.21.","172.22.","172.23.","172.24.","172.25.","172.26.",
                    "172.27.","172.28.","172.29.","172.30.","172.31.",
                    "192.168.","127.","::1","fe80")

def log(msg):
    now  = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{now}] [EXIT_NODE] {msg}"
    print(line)
    with open(LOG_PATH, "a") as f:
        f.write(line + "\n")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS exit_node_connections (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            direction   TEXT,
            local_ip    TEXT,
            local_port  INTEGER,
            remote_ip   TEXT,
            remote_port INTEGER,
            state       TEXT,
            first_seen  TEXT,
            last_seen   TEXT,
            UNIQUE(direction, remote_ip, remote_port)
        )
    """)
    conn.commit()
    return conn

def is_tailscale(ip): return ip.startswith(TAILSCALE_PREFIX)
def is_private(ip):   return any(ip.startswith(p) for p in PRIVATE_PREFIXES)
def is_public(ip):    return not is_private(ip) and not ip.startswith("0.")

def get_connections():
    try:
        r = subprocess.run(["/usr/sbin/netstat","-an","-p","tcp"],
                           capture_output=True, text=True, timeout=10)
        return r.stdout
    except Exception as e:
        log(f"netstat error: {e}")
        return ""

def parse_ip_port(addr):
    """192.168.1.1.80 → ('192.168.1.1', 80)"""
    m = re.match(r'^([\d.]+)\.(\d+)$', addr)
    if m:
        return m.group(1), int(m.group(2))
    return None, None

def parse_connections(output):
    inbound, outbound = [], []
    for line in output.splitlines():
        if not line.startswith("tcp4"):
            continue
        if "ESTABLISHED" not in line and "SYN_SENT" not in line:
            continue
        parts = line.split()
        if len(parts) < 6:
            continue
        local_ip,  local_port  = parse_ip_port(parts[3])
        remote_ip, remote_port = parse_ip_port(parts[4])
        state = parts[5]
        if not local_ip or not remote_ip:
            continue
        entry = dict(local_ip=local_ip, local_port=local_port,
                     remote_ip=remote_ip, remote_port=remote_port, state=state)
        if is_tailscale(remote_ip):
            entry["direction"] = "inbound"
            inbound.append(entry)
        elif is_public(remote_ip):
            entry["direction"] = "outbound"
            outbound.append(entry)
    return inbound, outbound

def save_connections(conn, connections):
    now, new_count = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), 0
    for c in connections:
        try:
            cur = conn.execute("""
                INSERT INTO exit_node_connections
                    (direction,local_ip,local_port,remote_ip,remote_port,state,first_seen,last_seen)
                VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(direction,remote_ip,remote_port) DO UPDATE SET
                    last_seen=excluded.last_seen, state=excluded.state
            """, (c["direction"],c["local_ip"],c["local_port"],
                  c["remote_ip"],c["remote_port"],c["state"],now,now))
            if cur.lastrowid and conn.execute(
                "SELECT first_seen=last_seen FROM exit_node_connections WHERE id=?",
                (cur.lastrowid,)).fetchone()[0]:
                new_count += 1
        except Exception:
            pass
    conn.commit()
    return new_count

def cleanup_old(conn):
    cutoff = (datetime.datetime.now()-datetime.timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    cur = conn.execute("DELETE FROM exit_node_connections WHERE last_seen < ?", (cutoff,))
    conn.commit()
    if cur.rowcount > 0:
        log(f"🗑️ cleanup: {cur.rowcount}件削除")

def main():
    conn = init_db()
    if "--cleanup" in sys.argv:
        cleanup_old(conn)
        conn.close()
        return
    output = get_connections()
    inbound, outbound = parse_connections(output)
    all_conn = inbound + outbound
    new_count = save_connections(conn, all_conn)
    if all_conn:
        log(f"📡 inbound={len(inbound)} outbound={len(outbound)} new={new_count}")
        for c in inbound:
            log(f"  ← IN  {c['remote_ip']}:{c['remote_port']} → local:{c['local_port']}")
        for c in outbound:
            log(f"  → OUT local:{c['local_port']} → {c['remote_ip']}:{c['remote_port']}")
    conn.close()

if __name__ == "__main__":
    main()

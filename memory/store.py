import os
import sqlite3

conn = sqlite3.connect("memory.db")

def save_memory(text):
    cur = conn.cursor()
    cur.execute(
        "CREATE TABLE IF NOT EXISTS memory (content TEXT)"
    )
    cur.execute(
        "INSERT INTO memory VALUES (?)",
        (text,)
    )
    conn.commit()

def load_memory(limit=5):

    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS memory (
            content TEXT
        )
        """
    )

    cur.execute(
        "SELECT content FROM memory ORDER BY rowid DESC LIMIT ?",
        (limit,)
    )

    rows = cur.fetchall()

    return "\n".join([r[0] for r in rows])



import datetime as _dt
import hashlib as _hashlib
import json as _json

TASK_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "memory.db")

def _task_conn():
    import sqlite3 as _sq
    c = _sq.connect(TASK_DB)
    c.execute("""
        CREATE TABLE IF NOT EXISTS active_tasks (
            task_id      TEXT PRIMARY KEY,
            status       TEXT DEFAULT 'pending',
            attack_log   TEXT,
            current_phase TEXT,
            ctx_snapshot TEXT,
            goal_summary TEXT,
            created_at   TEXT,
            updated_at   TEXT
        )
    """)
    c.commit()
    return c

def create_task(attack_log_path: str) -> str:
    """新しいタスクを作成してtask_idを返す"""
    task_id = _hashlib.md5(
        (attack_log_path + _dt.datetime.now().isoformat()).encode()
    ).hexdigest()[:12]
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c = _task_conn()
    c.execute(
        "INSERT OR IGNORE INTO active_tasks "
        "(task_id, status, attack_log, current_phase, created_at, updated_at) "
        "VALUES (?,?,?,?,?,?)",
        (task_id, "pending", attack_log_path, "PLAN", now, now)
    )
    c.commit(); c.close()
    return task_id

def update_task(task_id: str, phase: str, status: str,
                ctx_snapshot: str = "", goal_summary: str = ""):
    """フェーズ完了後にタスク状態を更新"""
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # ctx_snapshot は最大3000文字に圧縮
    snap = ctx_snapshot[-3000:] if len(ctx_snapshot) > 3000 else ctx_snapshot
    c = _task_conn()
    c.execute(
        "UPDATE active_tasks SET status=?, current_phase=?, "
        "ctx_snapshot=?, goal_summary=?, updated_at=? WHERE task_id=?",
        (status, phase, snap, goal_summary, now, task_id)
    )
    c.commit(); c.close()

def complete_task(task_id: str):
    """タスクを完了としてマーク"""
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c = _task_conn()
    c.execute(
        "UPDATE active_tasks SET status='complete', updated_at=? WHERE task_id=?",
        (now, task_id)
    )
    c.commit(); c.close()

def fail_task(task_id: str):
    """タスクを失敗としてマーク"""
    now = _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c = _task_conn()
    c.execute(
        "UPDATE active_tasks SET status='failed', updated_at=? WHERE task_id=?",
        (now, task_id)
    )
    c.commit(); c.close()

def get_resumable_task(attack_log_path: str):
    """再開可能な未完了タスクを取得（同じ攻撃ログ対象・24時間以内）"""
    c = _task_conn()
    row = c.execute(
        "SELECT task_id, current_phase, ctx_snapshot, goal_summary "
        "FROM active_tasks "
        "WHERE attack_log=? AND status NOT IN ('complete','failed') "
        "AND updated_at >= datetime('now','-24 hours','localtime') "
        "ORDER BY created_at DESC LIMIT 1",
        (attack_log_path,)
    ).fetchone()
    c.close()
    return row  # (task_id, phase, ctx_snapshot, goal_summary) or None

def cleanup_old_tasks(days: int = 7):
    """7日以上前の完了・失敗タスクを削除"""
    c = _task_conn()
    c.execute(
        "DELETE FROM active_tasks WHERE status IN ('complete','failed') "
        "AND updated_at < datetime('now',?,'localtime')",
        (f'-{days} days',)
    )
    c.commit(); c.close()

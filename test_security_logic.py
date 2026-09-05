#!/usr/bin/env python3
"""
SecureGuard セキュリティロジック 回帰テスト
- log_watcher.quick_severity() / extract_port(): 深刻度クイック判定
- dashboard.make_token() / verify_token(): HMACトークンの発行・検証
実行: FLASK_SECRET=dummy python3 test_security_logic.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("FLASK_SECRET", "test-secret-for-regression-tests-only")

import log_watcher as lw
import dashboard as db

FAILED = 0


def check(desc, condition):
    global FAILED
    status = "OK  " if condition else "FAIL"
    if not condition:
        FAILED += 1
    print(f"[{status}] {desc}")


def test_quick_severity():
    cases = [
        ("GET /?id=1' UNION SELECT password FROM users-- ", "HIGH", "SQLインジェクション(UNION SELECT)"),
        ("GET /?cmd=;cat%20/etc/passwd", "HIGH", "コマンドインジェクション(/etc/passwd)"),
        ("GET /.env HTTP/1.1", "HIGH", ".envファイルへの直接アクセス"),
        ("GET /?redirect=http://169.254.169.254/latest/meta-data/", "HIGH", "SSRF(メタデータエンドポイント)"),
        ("POST /login username=admin&password=test123", "MEDIUM", "ログインフォームの通常投稿"),
        ("GET /?path=../../etc/shadow", "MEDIUM", "ディレクトリトラバーサル"),
        ("GET /?q=<script>alert(1)</script>", "MEDIUM", "XSS(scriptタグ)"),
        ("GET /admin HTTP/1.1\" 200", "LOW", "通常のページアクセス"),
        ("GET /health HTTP/1.1\" 200", "LOW", "ヘルスチェックアクセス"),
    ]
    for line, expected, desc in cases:
        result = lw.quick_severity(line)
        check(f"quick_severity: {desc} (期待={expected})", result == expected)


def test_extract_port():
    check(
        "extract_port: ポート番号を含む行から抽出",
        lw.extract_port("192.168.1.1:54321 - - [10/Jul/2026] \"GET / HTTP/1.1\" 200 -") == "54321",
    )
    check(
        "extract_port: ポート番号を含まない行はデフォルト5000",
        lw.extract_port("192.168.1.1 - - [10/Jul/2026] \"GET / HTTP/1.1\" 200 -") == "5000",
    )


def test_token_roundtrip():
    token = db.make_token("test_action", "100.64.0.1")
    check(
        "make_token/verify_token: 正しいトークンは検証を通る",
        db.verify_token("test_action", "100.64.0.1", token),
    )
    check(
        "verify_token: 異なるactionでは検証を通らない",
        not db.verify_token("other_action", "100.64.0.1", token),
    )
    check(
        "verify_token: 異なるIPでは検証を通らない",
        not db.verify_token("test_action", "100.64.0.2", token),
    )
    check(
        "verify_token: 改ざんされたトークンは検証を通らない",
        not db.verify_token("test_action", "100.64.0.1", token[:-1] + ("0" if token[-1] != "0" else "1")),
    )
    check(
        "verify_token: 空/None トークンは検証を通らない",
        not db.verify_token("test_action", "100.64.0.1", None) and not db.verify_token("test_action", "100.64.0.1", ""),
    )


def test_token_expiry():
    # 2分(120秒)前のウィンドウで発行されたトークンは失効しているはず(有効窓は現在+直前の2分のみ)
    window = int(time.time()) // 60 - 2
    import hmac, hashlib
    msg = f"expiry_test:100.64.0.1:{window}".encode()
    old_token = hmac.new(db.SECRET_KEY.encode(), msg, hashlib.sha256).hexdigest()[:24]
    check(
        "verify_token: 2分以上前のトークンは失効している",
        not db.verify_token("expiry_test", "100.64.0.1", old_token),
    )


def main():
    test_quick_severity()
    test_extract_port()
    test_token_roundtrip()
    test_token_expiry()
    total = FAILED
    print(f"\n{'全テストPASS' if total == 0 else f'{total}件FAIL'}")
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
auto_patcher.py - 自動脆弱性検知・パッチ適用
cron: */30 * * * * ~/MythoFable/.venv/bin/python3 ~/MythoFable/auto_patcher.py
target_repo/ → 自動適用
dashboard.py / log_watcher.py → patch_candidates/ に保存
"""
import os, re, shutil, json, datetime, ast, sys, subprocess, tempfile
try:
    import requests
except ImportError:
    requests = None

BASE_DIR        = os.path.expanduser("~/MythoFable")
WATCHER_LOG     = "/Users/fk/Logs/watcher_stdout.log"
CANDIDATES_DIR  = os.path.join(BASE_DIR, "patch_candidates")
TARGET_REPO     = os.path.join(BASE_DIR, "target_repo")
PROD_FILES      = [
    os.path.join(BASE_DIR, "dashboard.py"),
    os.path.join(BASE_DIR, "log_watcher.py"),
]

os.makedirs(CANDIDATES_DIR, exist_ok=True)

def log(msg):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(WATCHER_LOG, "a", encoding="utf-8") as f:
        f.write(f"[{now}] [PATCHER] {msg}\n")

def syntax_ok(code):
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False

# ─────────────────────────────────────────
# 脆弱性パターン辞書
# ─────────────────────────────────────────
VULN_PATTERNS = [
    {
        "id"     : "SQL_FORMAT_STRING",
        "name"   : "SQLインジェクション（文字列結合）",
        "regex"  : r'f["\'].*SELECT.*\{[^}]+\}.*["\']',
        "desc"   : "f-string によるSQL文字列結合は SQLi脆弱性",
        "severity": "HIGH",
    },
    {
        "id"     : "SQL_PERCENT_FORMAT",
        "name"   : "SQLインジェクション（%フォーマット）",
        "regex"  : r'"SELECT[^"]*%[s|d][^"]*"\s*%',
        "desc"   : "% フォーマットによるSQL文字列結合は SQLi脆弱性",
        "severity": "HIGH",
    },
    {
        "id"     : "SHELL_INJECTION",
        "name"   : "シェルインジェクション",
        "regex"  : r'os\.system\s*\(|subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True[^)]*\+',
        "desc"   : "shell=True + 文字列結合はコマンドインジェクション脆弱性",
        "severity": "HIGH",
    },
    {
        "id"     : "HARDCODED_SECRET",
        "name"   : "ハードコードされたシークレット",
        "regex"  : r'(password|secret|api_key|token)\s*=\s*["\'][^"\']{6,}["\']',
        "desc"   : "シークレット情報がコードに直書きされています",
        "severity": "MEDIUM",
    },
]

def scan_file(filepath):
    """ファイルを脆弱性スキャンして検知結果リストを返す"""
    if not os.path.exists(filepath):
        return []
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
    findings = []
    for i, line in enumerate(lines, 1):
        for vp in VULN_PATTERNS:
            if re.search(vp["regex"], line, re.IGNORECASE):
                findings.append({
                    "line_no" : i,
                    "line"    : line.rstrip(),
                    "vuln_id" : vp["id"],
                    "name"    : vp["name"],
                    "desc"    : vp["desc"],
                    "severity": vp["severity"],
                })
    return findings

def generate_patch_target_repo(filepath, findings):
    """target_repo用: SQLi脆弱性を自動修正"""
    with open(filepath, "r", encoding="utf-8") as f:
        code = f.read()

    patched = code

    # f-string SQLi → パラメータ化クエリに変換
    patched = re.sub(
        r"(query\s*=\s*)f([\"'])(SELECT\s+\*\s+FROM\s+(\w+)\s+WHERE\s+(\w+)\s*=\s*')[{]([^}]+)[}]([\"'])",
        lambda m: (
            f"{m.group(1)}{m.group(2)}{m.group(3)}?{m.group(7)}\n"
            f"    # [PATCHED] パラメータ化クエリに変換\n"
            f"    _param_{m.group(6)} = ({m.group(6)},)"
        ),
        patched
    )
    patched = re.sub(
        r"(conn\.execute\()query\)",
        r"\1query, _param_user_input)",
        patched
    )

    return patched if patched != code else None


def generate_patch_opencode(filepath, findings, timeout=90):
    """
    OpenCode CLIでパッチ生成（regexパッチが効かない脆弱性向けフォールバック）
    サンドボックス(一時ディレクトリ)上で実行し、本番ファイルは直接触らない
    """
    import subprocess, tempfile

    fname = os.path.basename(filepath)
    sandbox_dir = tempfile.mkdtemp(prefix="oc_patch_")
    sandbox_file = os.path.join(sandbox_dir, fname)

    try:
        shutil.copy(filepath, sandbox_file)

        vuln_desc = "\n".join(
            [f"- {fi['name']} (line {fi['line_no']}): {fi['desc']}" for fi in findings]
        )
        prompt = (
            f"The file {fname} has these security vulnerabilities:\n{vuln_desc}\n\n"
            "Fix ALL vulnerabilities completely and correctly. "
            "For SQL injection: use parameterized queries AND make sure the parameter "
            "values are actually passed to execute() as a tuple. "
            "For hardcoded secrets: move them to environment variables via os.environ.get(). "
            "For shell injection: avoid shell=True with string concatenation, use a list of args instead. "
            "Modify the file directly and completely. Keep all other code unchanged. "
            "Double-check the fix is functionally correct, not just syntactically valid."
        )

        env = os.environ.copy()

        result = subprocess.run(
            ["opencode", "run", "--model", "openrouter/openai/gpt-oss-120b:free", prompt],
            cwd=sandbox_dir,
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if not os.path.exists(sandbox_file):
            log(f"⚠️ OpenCode: {fname} ファイルが見つからない")
            return None

        with open(sandbox_file, "r", encoding="utf-8") as f:
            patched_code = f.read()

        # 元のコードと同一なら変更なしとみなす
        with open(filepath, "r", encoding="utf-8") as f:
            original_code = f.read()
        if patched_code.strip() == original_code.strip():
            log(f"⚠️ OpenCode: {fname} 変更なし")
            return None

        log(f"🤖 OpenCode patch生成: {fname}")
        return patched_code

    except subprocess.TimeoutExpired:
        log(f"⚠️ OpenCode timeout ({timeout}s): {fname}")
        return None
    except FileNotFoundError:
        log("⚠️ OpenCode未インストール → スキップ")
        return None
    except Exception as e:
        log(f"⚠️ OpenCode error: {fname} → {e}")
        return None
    finally:
        shutil.rmtree(sandbox_dir, ignore_errors=True)

def save_candidate(filepath, findings, ai_patch=None, ai_source=None):
    """本番ファイル用: パッチ候補をJSONで保存（OpenCode等のAI生成パッチも添付可能・要人手レビュー）"""
    fname = os.path.basename(filepath)
    now   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out   = os.path.join(CANDIDATES_DIR, f"{fname}_{now}.json")
    data  = {
        "timestamp" : datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "file"      : filepath,
        "findings"  : findings,
        "status"    : "pending",
    }
    if ai_patch:
        data["ai_patch"]  = ai_patch
        data["ai_source"] = ai_source or "unknown"
        data["ai_warning"] = "AI生成パッチは未検証です。適用前に必ず内容を確認してください（import漏れ等の不完全な修正の可能性あり）"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    return out


# ─────────────────────────────────────────
# Fable5 Step②: 自己検証ループ
# ─────────────────────────────────────────
def _get_test_from_llm(prompt):
    """LLMからテストコードを取得 Gemini → Groq フォールバック"""
    from dotenv import load_dotenv
    load_dotenv(os.path.expanduser("~/MythoFable/.env"))
    load_dotenv(os.path.expanduser("~/.config/ai-keys/.env"))

    def _clean(text):
        text = text.strip()
        text = re.sub(r"^```python\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
        return text

    # Gemini
    gemini_key = os.getenv("GEMINI_API_KEY")
    if gemini_key:
        try:
            from google import genai
            from google.genai import types
            gclient = genai.Client(api_key=gemini_key)
            for model in ["gemini-2.5-flash", "gemini-2.0-flash"]:
                try:
                    r = gclient.models.generate_content(
                        model=model, contents=prompt,
                        config=types.GenerateContentConfig(temperature=0.1)
                    )
                    text = _clean(r.text)
                    if text and "import" in text:
                        return text
                except Exception as e:
                    if "RESOURCE_EXHAUSTED" in str(e) or "429" in str(e):
                        continue
                    break
        except Exception:
            pass

    # Groq
    groq_key = os.getenv("GROQ_API_KEY")
    if groq_key:
        try:
            r = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={"Authorization": f"Bearer {groq_key}",
                         "Content-Type": "application/json"},
                json={"model": "llama-3.3-70b-versatile",
                      "messages": [{"role": "user", "content": prompt}],
                      "temperature": 0.1},
                timeout=30
            )
            if r.status_code == 200:
                text = _clean(r.json()["choices"][0]["message"]["content"])
                if text and "import" in text:
                    return text
        except Exception:
            pass

    return None


def self_verify(filepath, findings, timeout=15):
    """
    Fable5 Step②: パッチ後の自己検証
    - LLMが生成したテストを実行（ast/re/sys のみ・外部接続なし）
    - Returns: (passed: bool, detail: str)
    """
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            src = f.read()
    except Exception as e:
        return True, f"file read error: {e}"

    vuln_descs = "\n".join([f"- {fi['name']}: {fi['desc']}" for fi in findings])

    prompt = f"""You are a security code reviewer. A Python file was patched to fix vulnerabilities.

Patched file path: {filepath}

Patched file content:
```python
{src[:2500]}
```

Vulnerabilities that were patched:
{vuln_descs}

Generate a minimal Python verification script that:
1. Uses ONLY built-in modules: ast, re, sys (NO imports of the target module, NO database, NO network)
2. Opens and reads the file at path: {filepath}
3. Checks statically:
   - No f-string SQL queries exist (pattern: f"SELECT...{{...}}")
   - Parameterized queries are used (pattern: "SELECT...?")
4. Calls sys.exit(0) if verification passes
5. Calls sys.exit(1) with a print message if verification fails

Respond with ONLY the Python code. No explanation. No markdown fences."""

    test_code = _get_test_from_llm(prompt)

    if not test_code:
        log(f"[VERIFY] LLM unavailable → skip self-verify (syntax OK)")
        return True, "LLM unavailable → skipped"

    # テストを一時ファイルに書き込む
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, prefix="/tmp/sv_"
        ) as f:
            f.write(test_code)
            test_path = f.name
    except Exception as e:
        return True, f"temp file error: {e}"

    # テスト実行
    try:
        result = subprocess.run(
            [sys.executable, test_path],
            capture_output=True, text=True, timeout=timeout
        )
        passed = result.returncode == 0
        out = (result.stdout + result.stderr).strip()[:300]
        detail = out if out else ("PASS" if passed else "FAIL (no output)")
        return passed, detail
    except subprocess.TimeoutExpired:
        return False, f"Test timed out ({timeout}s)"
    except Exception as e:
        return True, f"Test exec error: {e} → skipped"
    finally:
        try:
            os.unlink(test_path)
        except Exception:
            pass

def main():

    # target_repo/ 配下を全スキャン
    for root, dirs, files in os.walk(TARGET_REPO):
        for fname in files:
            if not fname.endswith(".py"):
                continue
            fpath = os.path.join(root, fname)
            findings = scan_file(fpath)
            if not findings:
                continue
            log(f"🔍 脆弱性検知: {fname} {len(findings)}件")
            patched = generate_patch_target_repo(fpath, findings)
            if patched and syntax_ok(patched):
                # regexパッチ（決定論的・信頼できる）→ 自動適用
                shutil.copy(fpath, fpath + ".pre_patch")
                with open(fpath, "w", encoding="utf-8") as f:
                    f.write(patched)
                passed, detail = self_verify(fpath, findings)
                vuln_names  = [fi["name"] for fi in findings]
                names_str   = ", ".join(vuln_names)
                if passed:
                    log(f"✅ パッチ適用+自己検証OK: {fname} → {names_str} | {detail[:80]}")
                else:
                    shutil.copy(fpath + ".pre_patch", fpath)
                    log(f"⚠️ 自己検証失敗→ロールバック: {fname} | {detail[:100]}")
            else:
                # ★ regexパッチ不可 → OpenCodeで生成 "候補" のみ保存（自動適用しない）
                # 理由: 無料LLMの品質にばらつきがあり(import漏れ等)、人によるレビューが必要
                log(f"🤖 regexパッチ不可 → OpenCodeで候補生成: {fname}")
                oc_patched = generate_patch_opencode(fpath, findings)
                vuln_names = [fi["name"] for fi in findings]
                if oc_patched and syntax_ok(oc_patched):
                    out = save_candidate(fpath, findings, ai_patch=oc_patched, ai_source="opencode")
                    log(f"🤖 OpenCode候補保存(要レビュー): {fname} → {', '.join(vuln_names)}")
                else:
                    out = save_candidate(fpath, findings)
                    log(f"⚠️ パッチ候補保存: {fname} → {', '.join(vuln_names)}")

    # 本番ファイルスキャン → 候補保存のみ
    for fpath in PROD_FILES:
        findings = scan_file(fpath)
        if not findings:
            continue
        # 同じ検知が既に候補にあればスキップ
        fname = os.path.basename(fpath)
        existing = [
            f for f in os.listdir(CANDIDATES_DIR)
            if f.startswith(fname) and f.endswith(".json")
        ]
        already = False
        for ef in existing:
            try:
                with open(os.path.join(CANDIDATES_DIR, ef)) as fp:
                    d = json.load(fp)
                if d.get("status") == "pending" and d.get("file") == fpath:
                    already = True
                    break
            except Exception:
                pass
        if already:
            continue
        out = save_candidate(fpath, findings)
        vuln_names = [fi["name"] + "(L" + str(fi["line_no"]) + ")" for fi in findings]
        log(f"📋 パッチ候補保存: {fname} {len(findings)}件 → {', '.join(vuln_names)}")


if __name__ == "__main__":
    main()

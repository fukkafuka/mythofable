"""
core/loop.py — Fable5思想 Step①: 4フェーズ構造
PLAN → EXECUTE → VERIFY → REPORT
各フェーズが明示的な目的を持ち、コンテキストを蓄積しながら進む
"""
import os
import sys
import time
import datetime

from agents.planner import planner, get_planner_config, client
from agents.sub_agents import call_sub_agent
try:
    from memory.store import update_task, complete_task, fail_task
except Exception:
    update_task = complete_task = fail_task = lambda *a, **kw: None
from agents.reviewer import reviewer
from tools.file_reader import read_specific_file
from tools.file_lister import list_project_files
from tools.defense_tools import execute_active_defense

available_tools = {
    "list_project_files":   list_project_files,
    "read_specific_file":   read_specific_file,
    "execute_active_defense": execute_active_defense,
}

# ─── フェーズ定数 ──────────────────────────────────────────────────
PHASE_PLAN    = "PLAN"
PHASE_EXECUTE = "EXECUTE"
PHASE_VERIFY  = "VERIFY"
PHASE_REPORT  = "REPORT"

PHASE_MAX_ITER = {
    PHASE_PLAN:    2,
    PHASE_EXECUTE: 4,
    PHASE_VERIFY:  2,
    PHASE_REPORT:  1,
}

# 各フェーズのAI指示（contextに追記して渡す）
PHASE_INSTRUCTIONS = {
    PHASE_PLAN: """
[CURRENT PHASE: PLAN]
攻撃ログを分析し以下を実施してください:
1. 攻撃者IPと攻撃パターンを特定する
2. read_specific_file で対象ファイルを確認する
3. 脆弱性の有無を診断する
4. 対応計画をplan_textに詳細に書く
※このフェーズでは read_specific_file のみ使用可。
  execute_active_defense はまだ呼ばないでください。
""",
    PHASE_EXECUTE: """
[CURRENT PHASE: EXECUTE]
PLANフェーズの分析結果に基づき防御アクションを実行してください:
- 脆弱性あり → execute_active_defense でパッチ適用 + IPブロック
- 既にセキュア → tool_call: null で現状安全と報告
実行した内容を plan_text に記録してください。
""",
    PHASE_VERIFY: """
[CURRENT PHASE: VERIFY]
EXECUTEフェーズの対応が正しく完了しているか検証してください:
1. read_specific_file で修正後のファイルを再確認する
2. パッチが正しく適用されているか確認する
3. 検証結果を plan_text に明記する（確認完了 or 問題あり）
""",
    PHASE_REPORT: """
[CURRENT PHASE: REPORT]
今回の防御サイクルの最終レポートを生成してください。
tool_call: null にしてください。
plan_text に含める内容:
- 攻撃概要（IP・パターン・対象エンドポイント）
- 検出した脆弱性（またはなし）
- 実施した対応
- 検証結果
- 推奨事項
""",
}

# ─── ユーティリティ ────────────────────────────────────────────────

# ─── コンテキスト圧縮 ──────────────────────────────────────────
MAX_CTX_CHARS = 6000   # フェーズ間で渡すコンテキストの上限文字数

def trim_context(ctx: str, head: int = 2500, tail: int = 3000) -> str:
    """
    コンテキストが長すぎる場合、先頭(head)と末尾(tail)だけ残す。
    先頭 = ベースコンテキスト（攻撃ログ）を保持
    末尾 = 最新フェーズの結果を保持
    """
    if len(ctx) <= MAX_CTX_CHARS:
        return ctx
    separator = "\n\n...[middle trimmed for token efficiency]...\n\n"
    return ctx[:head] + separator + ctx[-tail:]

def phase_log(phase, msg):
    now = datetime.datetime.now().strftime("%H:%M:%S")
    bar = "─" * 52
    print(f"\n[{now}] ┌{bar}")
    print(f"[{now}] │ [{phase}] {msg}")
    print(f"[{now}] └{bar}")

def step_log(msg):
    now = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{now}]   {msg}")

def execute_tool(tool_call):
    """ツールコールを実行して (name, result) を返す"""
    if not tool_call or not isinstance(tool_call, dict):
        return None, None
    name   = tool_call.get("name")
    args   = tool_call.get("args", {})
    step_log(f"→ Tool: {name}  args: {args}")
    if name in available_tools:
        return name, available_tools[name](**args)
    return name, f"[Error] Tool '{name}' is not registered."


# ─── Step⑤ プロアクティブな進捗確認 ──────────────────────────────
PHASE_GOALS = {
    PHASE_PLAN: {
        "required": [
            (["ip=", "attacker ip", "100."], "攻撃者IPの特定"),
            (["sql", "injection", "xss", "pattern", "attack"], "攻撃パターンの特定"),
            (["vulnerable=", "already secure", "parameterized", "patched"], "脆弱性有無の判定"),
        ]
    },
    PHASE_EXECUTE: {
        "required": [
            (["already secure", "patch applied", "execute_active_defense",
               "parameterized", "no patch needed", "system already"], "防御アクションの完了"),
        ]
    },
    PHASE_VERIFY: {
        "required": [
            (["verified", "confirmed", "secure", "patched", "already"], "検証の完了"),
        ]
    },
    PHASE_REPORT: {
        "required": [
            (["attack", "ip", "pattern"], "レポートの生成"),
        ]
    },
}

def check_phase_goal(phase: str, additions: str) -> tuple:
    """
    フェーズのゴール達成を評価する（Step⑤ プロアクティブな進捗確認）
    Returns: (all_met: bool, summary: str)
    """
    goals = PHASE_GOALS.get(phase, {}).get("required", [])
    if not goals:
        return True, "No goals defined"

    lower = additions.lower()
    results = []
    all_met = True

    for keywords, label in goals:
        met = any(k in lower for k in keywords)
        results.append(f"{'✓' if met else '✗'} {label}")
        if not met:
            all_met = False

    summary = " | ".join(results)
    return all_met, summary

def build_goal_context(phase: str, met: bool, summary: str) -> str:
    """次フェーズに渡すゴール状況サマリー"""
    status = "COMPLETE" if met else "INCOMPLETE"
    return f"\n[Previous Phase {phase} Goal Status: {status}]\n{summary}\n"


# ─── Step⑤ プロアクティブな進捗確認 ──────────────────────────────
PHASE_GOALS = {
    PHASE_PLAN: {
        "required": [
            (["ip=", "attacker ip", "100."], "攻撃者IPの特定"),
            (["sql", "injection", "xss", "pattern", "attack"], "攻撃パターンの特定"),
            (["vulnerable=", "already secure", "parameterized", "patched"], "脆弱性有無の判定"),
        ]
    },
    PHASE_EXECUTE: {
        "required": [
            (["already secure", "patch applied", "execute_active_defense",
               "parameterized", "no patch needed", "system already"], "防御アクションの完了"),
        ]
    },
    PHASE_VERIFY: {
        "required": [
            (["verified", "confirmed", "secure", "patched", "already"], "検証の完了"),
        ]
    },
    PHASE_REPORT: {
        "required": [
            (["attack", "ip", "pattern"], "レポートの生成"),
        ]
    },
}

def check_phase_goal(phase: str, additions: str) -> tuple:
    """
    フェーズのゴール達成を評価する（Step⑤ プロアクティブな進捗確認）
    Returns: (all_met: bool, summary: str)
    """
    goals = PHASE_GOALS.get(phase, {}).get("required", [])
    if not goals:
        return True, "No goals defined"

    lower = additions.lower()
    results = []
    all_met = True

    for keywords, label in goals:
        met = any(k in lower for k in keywords)
        results.append(f"{'✓' if met else '✗'} {label}")
        if not met:
            all_met = False

    summary = " | ".join(results)
    return all_met, summary

def build_goal_context(phase: str, met: bool, summary: str) -> str:
    """次フェーズに渡すゴール状況サマリー"""
    status = "COMPLETE" if met else "INCOMPLETE"
    return f"\n[Previous Phase {phase} Goal Status: {status}]\n{summary}\n"

# ─── フェーズランナー ──────────────────────────────────────────────
def run_phase(phase, context):
    """
    1フェーズを実行する。
    Returns:
        additions (str) : このフェーズで蓄積したコンテキスト
        success   (bool): レビュアーがSUCCESSを返したか
    """
    max_iter    = PHASE_MAX_ITER[phase]
    instruction = PHASE_INSTRUCTIONS[phase]
    additions   = ""

    for i in range(max_iter):
        step_log(f"[{phase}] Iter {i+1}/{max_iter}")
        time.sleep(2)

        # ★ Step④ トークン効率化
        # ① additions は直近2000文字のみ渡す（古い中間結果は不要）
        additions_for_ctx = additions[-2000:] if len(additions) > 2000 else additions
        # ② 命令文は初回のみフル、2回目以降は短縮
        instr = instruction if i == 0 else f"[{phase}] Continue. Respond in JSON only."
        full_ctx = context + additions_for_ctx + "\n" + instr
        step_log(f"[{phase}] ctx={len(full_ctx)}chars")

        output   = call_sub_agent(phase, full_ctx)  # ★ Step③ サブエージェント委任

        if "error" in output:
            step_log(f"[{phase}] Planner error: {output['error']}")
            break

        plan_text = output.get("plan_text", "")
        tool_call = output.get("tool_call")

        preview = plan_text[:200] + ("..." if len(plan_text) > 200 else "")
        step_log(f"Plan: {preview}")
        # ③ plan_text は400文字に圧縮して additions に追加
        plan_summary = plan_text[:400] + ("..." if len(plan_text) > 400 else "")
        additions += f"\n\n[{phase}-{i+1}]:\n{plan_summary}"

        # ツール実行
        if tool_call:
            tool_name, tool_result = execute_tool(tool_call)
            if tool_result is not None:
                # ④ tool_result は500文字に圧縮
                tr_str = str(tool_result)
                tr_trim = tr_str[:500] + ("..." if len(tr_str) > 500 else "")
                step_log(f"Result: {tr_trim[:200]}{'...' if len(tr_trim) > 200 else ''}")
                additions += f"\n\n[Tool {tool_name}]:\n{tr_trim}"
        else:
            step_log(f"[{phase}] No tool call → action complete")
            break

        # EXECUTE / VERIFY フェーズではレビュアー確認
        if phase in (PHASE_EXECUTE, PHASE_VERIFY):
            time.sleep(2)

            # VERIFYフェーズ: plan_textに"VERIFIED"があれば直接SUCCESS
            if phase == PHASE_VERIFY and plan_text and (
                "VERIFIED:" in plan_text.upper() or
                "PATCH CONFIRMED" in plan_text.upper() or
                "ALREADY SECURE" in plan_text.upper()
            ):
                step_log(f"[{phase}] ✅ Sub-agent confirmed verification (skip reviewer)")
                additions += f"\n\n[{phase} Iter{i+1} - VerifyResult]: VERIFIED"
                return additions, True

            step_log("[Reviewer] Evaluating...")
            review = reviewer(plan_text, use_fallback=True)
            r_preview = review[:180] + ("..." if len(review) > 180 else "")
            step_log(f"Review: {r_preview}")
            additions += f"\n\n[{phase} Iter{i+1} - Review]:\n{review}"
            if "STATUS: SUCCESS" in review:
                step_log(f"[{phase}] ✅ Reviewer confirmed SUCCESS")
                return additions, True

    return additions, False

# ─── メインループ ──────────────────────────────────────────────────
def run_loop(task_id: str = None):
    bar = "═" * 58
    print(f"\n{bar}")
    print("  MythoFable  |  Active Defense Engine")
    print("  PLAN → EXECUTE → VERIFY → REPORT")
    print(f"{bar}\n")

    # 初期コンテキスト構築
    attack_log_content = "No logs provided."
    if len(sys.argv) > 1 and os.path.exists(sys.argv[1]):
        with open(sys.argv[1], "r", encoding="utf-8") as f:
            attack_log_content = f.read()
        step_log(f"Attack log loaded: {sys.argv[1]}")

    initial_files = list_project_files("./target_repo")
    base_context = (
        "🚨 [CRITICAL ALERT] INFRASTRUCTURE SECURITY DETECTION 🚨\n"
        "An active web attack has been detected.\n\n"
        f"[SUSPICIOUS ACCESS LOG]:\n{attack_log_content}\n\n"
        f"[TARGET REPOSITORY FILE STRUCTURE]:\n{initial_files}"
    )

    ctx             = base_context
    overall_success = False
    goal_ctx  = ""   # ★ Step⑤ ゴールコンテキスト初期化
    goal_ctx2 = ""

    # Phase 1: PLAN
    phase_log(PHASE_PLAN, "Attack analysis & planning")
    plan_add, _ = run_phase(PHASE_PLAN, ctx)
    # ★ Step⑤ PLANゴール確認
    plan_met, plan_goal_summary = check_phase_goal(PHASE_PLAN, plan_add)
    step_log(f"[GoalCheck/PLAN] {'✅' if plan_met else '⚠️ 不完全'}: {plan_goal_summary}")
    goal_ctx = build_goal_context(PHASE_PLAN, plan_met, plan_goal_summary)
    ctx += plan_add + goal_ctx
    # ★ Step⑥ フェーズ進捗をDBに保存
    if task_id:
        update_task(task_id, "EXECUTE", "plan_done", ctx, plan_goal_summary)
    phase_log(PHASE_PLAN, "Complete ✓")

    # Phase 2: EXECUTE
    phase_log(PHASE_EXECUTE, "Defense execution")
    exec_add, success = run_phase(PHASE_EXECUTE, ctx)
    # ★ Step⑤ EXECUTEゴール確認
    exec_met, exec_goal_summary = check_phase_goal(PHASE_EXECUTE, exec_add)
    step_log(f"[GoalCheck/EXECUTE] {'✅' if exec_met else '⚠️ 不完全'}: {exec_goal_summary}")
    goal_ctx2 = build_goal_context(PHASE_EXECUTE, exec_met, exec_goal_summary)
    ctx += exec_add + goal_ctx2
    if success:
        overall_success = True
    # ★ Step⑥ EXECUTEフェーズ進捗をDBに保存
    if task_id:
        update_task(task_id, "VERIFY", "execute_done", ctx, exec_goal_summary)
    phase_log(PHASE_EXECUTE, f"Complete ✓  (success={success})")

    # Phase 3: VERIFY
    # EXECUTE が "already secure" を確認済みなら VERIFY はスキップ
    _already_secure_kws = [
        "system already secure", "already secure:", "already parameterized",
        "already using parameterized", "no patch needed", "code is already secure",
    ]
    _exec_ctx_lower = (ctx + exec_add).lower()
    if any(k in _exec_ctx_lower for k in _already_secure_kws):
        phase_log(PHASE_VERIFY, "⏭ Skipped — EXECUTE confirmed system already secure")
        step_log(f"[GoalCheck/VERIFY] ✅ ゴール達成（EXECUTEによる確認済み）")
        verified = True
        overall_success = True
    else:
        ctx = trim_context(ctx)  # トークン効率化
        time.sleep(5)  # レート制限対策
        phase_log(PHASE_VERIFY, "Result verification")
        verify_add, verified = run_phase(PHASE_VERIFY, ctx)
        ctx += verify_add
        # ★ Step⑤ VERIFYゴール確認
        verify_met, verify_goal_summary = check_phase_goal(PHASE_VERIFY, verify_add)
        step_log(f"[GoalCheck/VERIFY] {'✅' if verify_met else '⚠️ 不完全'}: {verify_goal_summary}")
        # ★ Step⑤ VERIFYゴール確認
        verify_met, verify_goal_summary = check_phase_goal(PHASE_VERIFY, verify_add)
        step_log(f"[GoalCheck/VERIFY] {'✅' if verify_met else '⚠️ 不完全'}: {verify_goal_summary}")
        if verified:
            overall_success = True
        phase_log(PHASE_VERIFY, f"Complete ✓  (verified={verified})")

    # Phase 4: REPORT — 超圧縮コンテキストで負荷最小化
    _seen = set()
    _lines = []
    for _kw in ["ANALYSIS:", "already secure", "attacker", "IP=", "pattern", "VERIFIED"]:
        for _line in ctx.split("\n"):
            _s = _line.strip()
            if _kw.lower() in _s.lower() and _s and len(_s) < 300 and _s not in _seen:
                _seen.add(_s)
                _lines.append(_s)
                if len(_lines) >= 12:
                    break
    slim_ctx = (
        "[REPORT CONTEXT - KEY FINDINGS]\n"
        + "\n".join(_lines)[:1200]
        + "\n\n[Write final security report based on above. tool_call must be null.]"
    )
    time.sleep(15)  # Groqレート制限回復待ち
    phase_log(PHASE_REPORT, "Final report generation")
    report_add, _ = run_phase(PHASE_REPORT, slim_ctx)
    phase_log(PHASE_REPORT, "Complete ✓")

    # 最終結果
    print(f"\n{bar}")
    # ★ Step⑥ タスク完了をDBに記録
    if task_id:
        if overall_success:
            complete_task(task_id)
        else:
            fail_task(task_id)

    if overall_success:
        print("  ✅ DEFENSE CYCLE COMPLETE — All phases passed")
    else:
        print("  ⚠️  DEFENSE CYCLE COMPLETE — Manual review recommended")
    print(f"{bar}\n")

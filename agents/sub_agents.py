"""
agents/sub_agents.py — Fable5 Step③: サブエージェント委任
各フェーズに特化したエージェントが専用プロンプトで動作する
"""
from agents.planner import call_llm_chain

# ─────────────────────────────────────────
# 各フェーズ専用エージェント定義
# ─────────────────────────────────────────
_AGENTS = {
    "PLAN": {
        "name": "AttackAnalyzer",
        "prompt": (
            "You are AttackAnalyzer, a specialized security log analysis agent.\n"
            "Your ONLY job is analysis — do NOT patch anything.\n\n"
            "Tasks:\n"
            "1. Identify attacker IP and attack pattern from the log\n"
            "2. Use read_specific_file to inspect the target file\n"
            "3. Determine if the vulnerability exists in the code\n\n"
            'Output JSON: {"tool_call": {"name": "read_specific_file", "args": {"file_path": "..."}}, "plan_text": "Analysis..."}\n'
            'Or when done: {"tool_call": null, "plan_text": "ANALYSIS: IP=..., Pattern=..., Vulnerable=yes/no"}'
        ),
    },
    "EXECUTE": {
        "name": "PatchGenerator",
        "prompt": (
            "You are PatchGenerator, a specialized code patching agent.\n"
            "Based on AttackAnalyzer findings in context:\n"
            "- If vulnerability found → call execute_active_defense\n"
            "- If already secure → tool_call: null\n\n"
            'Output JSON: {"tool_call": {"name": "execute_active_defense", "args": {"file_path": "...", "old_text": "...", "new_text": "...", "attacker_ip": "..."}}, "plan_text": "..."}\n'
            'Or: {"tool_call": null, "plan_text": "System already secure: ..."}'
        ),
    },
    "VERIFY": {
        "name": "VerificationAgent",
        "prompt": (
            "You are VerificationAgent, a specialized patch verification agent.\n"
            "Confirm the patch from PatchGenerator was correctly applied.\n\n"
            "Tasks:\n"
            "1. Use read_specific_file to re-read the patched file\n"
            "2. Confirm parameterized queries used (? placeholders)\n"
            "3. Confirm no f-string SQL remains\n\n"
            'Output JSON: {"tool_call": {"name": "read_specific_file", "args": {"file_path": "..."}}, "plan_text": "Verifying..."}\n'
            'Or: {"tool_call": null, "plan_text": "VERIFIED: patch confirmed / ISSUE: description"}'
        ),
    },
    "REPORT": {
        "name": "ReportWriter",
        "prompt": (
            "You are ReportWriter, a specialized security incident report agent.\n"
            "Generate a comprehensive final report. tool_call MUST be null.\n\n"
            'Output JSON: {"tool_call": null, "plan_text": "FINAL SECURITY REPORT:\\n1. Attack Summary:...\\n2. Vulnerability:...\\n3. Action:...\\n4. Verification:...\\n5. Recommendations:..."}'
        ),
    },
}


# ★ Step④ サブエージェントへのコンテキスト上限
MAX_SUBAGENT_CTX = 4000

def call_sub_agent(phase: str, context: str) -> dict:
    """
    指定フェーズのサブエージェントを呼び出す
    Fable5 Step③: 役割を明確に分離してLLMを呼ぶ
    Fable5 Step④: コンテキストを4000文字に制限してトークン効率化
    """
    agent = _AGENTS.get(phase)
    if not agent:
        from agents.planner import planner
        return planner(None, context, None, use_fallback=True)

    # ★ Step④ コンテキスト圧縮（先頭1800+末尾1800）
    if len(context) > MAX_SUBAGENT_CTX:
        context = (
            context[:1800]
            + "\n...[context trimmed for token efficiency]...\n"
            + context[-1800:]
        )

    full_prompt = (
        f"[AGENT ROLE: {agent['name']}]\n"
        f"{agent['prompt']}\n\n"
        f"--- CURRENT CONTEXT ---\n{context}\n--- END CONTEXT ---\n\n"
        "Respond ONLY with valid raw JSON. No markdown fences."
    )
    return call_llm_chain(full_prompt)

import os
import re
import json
import time
import requests
from google import genai
from google.genai import types
from dotenv import load_dotenv
from model_status import filter_alive_models

from tools.file_reader import read_specific_file
from tools.file_lister import list_project_files
from tools.defense_tools import execute_active_defense

# キーを両方のenvから読み込む
load_dotenv(os.path.expanduser("~/.config/ai-keys/.env"))
load_dotenv(os.path.expanduser("~/gemini_mythos_m/.env"))

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

SYSTEM_PROMPT = """
You are an expert autonomous Active Defense Security Agent (MythoFable).

Your task is to protect the repository from external web attacks based on the provided attack log.

[STRATEGY & WORKFLOW]:
1. First, look at the attack log and identify the targeted endpoint (e.g., /login) and the attacker\'s IP.
2. Read the corresponding source file (e.g., app.py) using `read_specific_file` to inspect its current implementation.
3. Check if the vulnerability described in the log actually exists in the code:
   - IF THE CODE IS ALREADY SECURE (e.g., already using ? placeholders or parameterized queries), do NOT call `execute_active_defense`. Instead, realize that the patch is already applied, and immediately output a final report with `tool_call: null` stating that the system is safe.
   - IF THE CODE IS VULNERABLE (e.g., using string interpolation like f"SELECT..."), call `execute_active_defense` to patch it and block the IP.
4. When writing your "plan_text", you MUST provide a detailed, comprehensive engineering report to satisfy the Senior Reviewer. Include:
   - Root cause analysis of the attack log.
   - Specific vulnerability type found (or state if it\'s already secured).
   - Detailed justification of the mitigation taken.

Available Tools:
- list_project_files: Check repository structure.
- read_specific_file: Inspect the target code file.
- execute_active_defense: Fix code AND block IP simultaneously.

[OUTPUT FORMAT]:
You MUST respond in raw JSON format matching this exact schema:
{
  "tool_call": {
    "name": "execute_active_defense",
    "args": {"file_path": "./target_repo/app.py", "old_text": "...", "new_text": "...", "attacker_ip": "..."}
  },
  "plan_text": "Detailed security report containing: 1) Attack Log Analysis, 2) Vulnerability Identification, 3) Action taken."
}
If no tool call is needed:
{
  "tool_call": null,
  "plan_text": "FINAL SECURITY REPORT: ..."
}
"""

def get_planner_config():
    return types.GenerateContentConfig(
        system_instruction=SYSTEM_PROMPT,
        tools=[list_project_files, read_specific_file, execute_active_defense],
        temperature=0.2
    )

def _extract_json(text: str) -> dict:
    text = text.strip()
    text = re.sub(r"^```json\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        return json.loads(match.group())
    return json.loads(text)

def _build_prompt(context: str) -> str:
    return (
        f"{SYSTEM_PROMPT}\n\n"
        f"Current Context & Memory:\n{context}\n\n"
        "Response MUST be valid raw JSON only. No markdown."
    )

# ── モデルチェーン ① Gemini ────────────────────────────────────────
def planner_gemini(context: str) -> dict:
    prompt = _build_prompt(context)
    # 2.5-flash → 2.0-flash の順に試す（別クォータ）
    for model in ["gemini-2.5-flash", "gemini-2.0-flash"]:
        try:
            response = client.models.generate_content(
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(temperature=0.2)
            )
            return _extract_json(response.text)
        except Exception as e:
            err = str(e)
            if "RESOURCE_EXHAUSTED" in err or "429" in err:
                print(f"[Gemini] {model} quota exhausted → try next")
                continue
            print(f"[Gemini Error] {type(e).__name__}: {e}")
            break
    return {"error": "Gemini: quota exhausted"}

# ── モデルチェーン ② Groq ─────────────────────────────────────────
def planner_groq(context: str) -> dict:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return {"error": "GROQ_API_KEY not found"}
    prompt = _build_prompt(context)
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        for attempt in range(2):
            res = requests.post(url, headers=headers, json={
                "model": "openai/gpt-oss-120b",  # 2026-08-01: llama-3.3-70b-versatile廃止(2026-08-16)のため移行
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
                "response_format": {"type": "json_object"}
            }, timeout=30)
            if res.status_code == 200:
                return _extract_json(res.json()["choices"][0]["message"]["content"])
            if res.status_code == 429 and attempt == 0:
                print(f"[Groq] Rate limited → wait 20s and retry")
                time.sleep(20)
                continue
            print(f"[Groq] HTTP {res.status_code}: {res.text[:150]}")
            break
        return {"error": f"Groq: rate limited"}
    except Exception as e:
        print(f"[Groq Error] {e}")
        return {"error": f"Groq: {e}"}

# ── モデルチェーン ③ OpenRouter 無料モデル ────────────────────────
def planner_openrouter(context: str) -> dict:
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        return {"error": "OPENROUTER_API_KEY is missing"}
    prompt = _build_prompt(context)
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/vllm-project/vllm",
        "X-Title": "MythoFable",
    }
    # Moltbookエージェントで稼働確認済みのモデル
    models = filter_alive_models([
        "nousresearch/hermes-3-llama-3.1-405b:free",
        "qwen/qwen3-235b-a22b:free",
        "microsoft/mai-ds-r1:free",
    ], provider="openrouter")
    for model in models:
        try:
            res = requests.post(url, headers=headers, json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
            }, timeout=30)
            if res.status_code == 200:
                text = res.json()["choices"][0]["message"]["content"].strip()
                if not text:
                    print(f"[OpenRouter] {model} → empty response, skip")
                    continue
                return _extract_json(text)
            print(f"[OpenRouter] {model} → HTTP {res.status_code}")
        except Exception as e:
            print(f"[OpenRouter] {model} → {e}")
    return {"error": "All models failed."}

# ── メイン呼び出し（Gemini→Groq→OpenRouter の順）──────────────────
def planner(chat_session, context: str, config, use_fallback=False):
    for fn, name in [
        (planner_gemini,     "Gemini"),
        (planner_groq,       "Groq"),
        (planner_openrouter, "OpenRouter"),
    ]:
        result = fn(context)
        if "error" not in result:
            print(f"[Planner] ✓ {name}")
            return result
        print(f"[Planner] {name} failed → next")
    return {"error": "All models failed."}


# ─────────────────────────────────────────
# Fable5 Step③: サブエージェント用汎用LLM呼び出し
# ─────────────────────────────────────────
def call_llm_chain(full_prompt: str) -> dict:
    """
    完成済みプロンプトを受け取り Gemini→Groq→OpenRouter で実行
    サブエージェントから呼び出される共有関数
    """
    import time as _time

    # Gemini
    for model in ["gemini-2.5-flash", "gemini-2.0-flash"]:
        try:
            response = client.models.generate_content(
                model=model,
                contents=full_prompt,
                config=types.GenerateContentConfig(temperature=0.2)
            )
            result = _extract_json(response.text)
            print(f"[SubAgent] ✓ Gemini/{model}")
            return result
        except Exception as e:
            err = str(e)
            if "RESOURCE_EXHAUSTED" in err or "429" in err:
                print(f"[SubAgent/Gemini] {model} quota → next")
                continue
            print(f"[SubAgent/Gemini] error: {e}")
            break

    # Groq
    groq_key = os.getenv("GROQ_API_KEY")
    if groq_key:
        for attempt in range(2):
            try:
                res = requests.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={"Authorization": f"Bearer {groq_key}",
                             "Content-Type": "application/json"},
                    json={"model": "openai/gpt-oss-120b",  # 2026-08-01: llama-3.3-70b-versatile廃止(2026-08-16)のため移行
                          "messages": [{"role": "user", "content": full_prompt}],
                          "temperature": 0.2,
                          "response_format": {"type": "json_object"}},
                    timeout=30
                )
                if res.status_code == 200:
                    result = _extract_json(res.json()["choices"][0]["message"]["content"])
                    print(f"[SubAgent] ✓ Groq")
                    return result
                if res.status_code == 429 and attempt == 0:
                    print(f"[SubAgent/Groq] rate limit → wait 20s")
                    _time.sleep(20)
                    continue
                print(f"[SubAgent/Groq] HTTP {res.status_code}")
                break
            except Exception as e:
                print(f"[SubAgent/Groq] error: {e}")
                break

    # OpenRouter
    or_key = os.getenv("OPENROUTER_API_KEY")
    if or_key:
        or_models = filter_alive_models([
            "nousresearch/hermes-3-llama-3.1-405b:free",
            "qwen/qwen3-235b-a22b:free",
            "microsoft/mai-ds-r1:free",
        ], provider="openrouter")
        for model in or_models:
            try:
                res = requests.post(
                    "https://openrouter.ai/api/v1/chat/completions",
                    headers={"Authorization": f"Bearer {or_key}",
                             "Content-Type": "application/json",
                             "HTTP-Referer": "https://github.com/vllm-project/vllm",
                             "X-Title": "MythoFable"},
                    json={"model": model,
                          "messages": [{"role": "user", "content": full_prompt}],
                          "temperature": 0.2},
                    timeout=30
                )
                if res.status_code == 200:
                    text = res.json()["choices"][0]["message"]["content"].strip()
                    if not text:
                        continue
                    result = _extract_json(text)
                    print(f"[SubAgent] ✓ OpenRouter/{model}")
                    return result
                print(f"[SubAgent/OpenRouter] {model} → HTTP {res.status_code}")
            except Exception as e:
                print(f"[SubAgent/OpenRouter] {model} → {e}")

    return {"error": "All models failed."}

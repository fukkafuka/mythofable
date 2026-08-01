import os
import requests
from google import genai
from google.genai import types
from dotenv import load_dotenv
from model_status import filter_alive_models

load_dotenv(os.path.expanduser("~/.config/ai-keys/.env"))
load_dotenv(os.path.expanduser("~/gemini_mythos_m/.env"))

client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

REVIEWER_SYSTEM_PROMPT = """
You are an expert Senior Security Reviewer. Your role is to critically evaluate the vulnerability investigation plan or findings provided by the Planner agent.

Output Format:
Your response MUST end with one of these clear status indicators:
- If the plan is incomplete or missing evidence:
  [STATUS: FAILURE]
  Reason: (Provide feedback on what to check next)

- If the planner has successfully identified a valid, proven vulnerability:
  [STATUS: SUCCESS]
  Summary: (Provide a brief summary of the confirmed bug)
"""

def _review_gemini(plan_text: str) -> str:
    prompt = f"Please review the following Security Agent findings/plan:\n\n{plan_text}"
    for model in ["gemini-2.5-flash", "gemini-2.0-flash"]:
        try:
            response = client.models.generate_content(
                model=model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=REVIEWER_SYSTEM_PROMPT,
                    temperature=0.1
                )
            )
            return response.text
        except Exception as e:
            err = str(e)
            if "RESOURCE_EXHAUSTED" in err or "429" in err:
                print(f"[Reviewer/Gemini] {model} quota exhausted → next")
                continue
            print(f"[Reviewer/Gemini Error] {e}")
            break
    return ""

def _review_groq(plan_text: str) -> str:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        return ""
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    prompt = f"{REVIEWER_SYSTEM_PROMPT}\n\nPlease review:\n\n{plan_text}"
    try:
        res = requests.post(url, headers=headers, json={
            "model": "openai/gpt-oss-120b",  # 2026-08-01: llama-3.3-70b-versatile廃止(2026-08-16)のため移行
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
        }, timeout=30)
        if res.status_code == 200:
            return res.json()["choices"][0]["message"]["content"]
        print(f"[Reviewer/Groq] HTTP {res.status_code}")
    except Exception as e:
        print(f"[Reviewer/Groq Error] {e}")
    return ""

def _review_openrouter(plan_text: str) -> str:
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        return ""
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/vllm-project/vllm",
        "X-Title": "MythoFable",
    }
    prompt = f"{REVIEWER_SYSTEM_PROMPT}\n\nPlease review:\n\n{plan_text}"
    models = filter_alive_models([
        "minimax/minimax-m2.5:free",
        "google/gemma-3-27b-it:free",
    ], provider="openrouter")
    for model in models:
        try:
            res = requests.post(url, headers=headers, json={
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,
            }, timeout=30)
            if res.status_code == 200:
                return res.json()["choices"][0]["message"]["content"]
            print(f"[Reviewer/OpenRouter] {model} → HTTP {res.status_code}")
        except Exception as e:
            print(f"[Reviewer/OpenRouter] {model} → {e}")
    return ""

def reviewer(plan_text: str, use_fallback=False) -> str:
    for fn, name in [
        (_review_gemini,     "Gemini"),
        (_review_groq,       "Groq"),
        (_review_openrouter, "OpenRouter"),
    ]:
        result = fn(plan_text)
        if result.strip():
            print(f"[Reviewer] ✓ {name}")
            return result
        print(f"[Reviewer] {name} failed → next")
    return "All reviewer models failed.\n[STATUS: FAILURE]"

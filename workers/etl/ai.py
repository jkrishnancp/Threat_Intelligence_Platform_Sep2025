import os, requests

BASE = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")
MODEL = os.getenv("OPENROUTER_MODEL", "meta-llama/llama-3.1-8b-instruct:free")
KEY   = os.getenv("OPENROUTER_API_KEY", "")

HEADERS = {
    "Authorization": f"Bearer {KEY}",
    "Content-Type": "application/json",
    "HTTP-Referer": "http://localhost",        # optional, recommended by OpenRouter
    "X-Title": "TIP Phase1 Summarizer"         # optional
}

EXEC_SYS = "You summarize security advisories for executives. Be concise (<=80 words)."
TECH_SYS = "You summarize security advisories for security engineers. Return 3–5 terse bullets (affected products, CVEs, mitigations)."

def _chat(system_prompt: str, user_text: str) -> str | None:
    if not KEY:
        return None
    try:
        r = requests.post(
            f"{BASE}/chat/completions",
            headers=HEADERS,
            json={
                "model": MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_text}
                ],
                "temperature": 0.2,
                "max_tokens": 320
            },
            timeout=40
        )
        r.raise_for_status()
        data = r.json()
        return data["choices"][0]["message"]["content"].strip()
    except Exception:
        return None

def summarize(text: str):
    """
    Returns {"exec": str, "tech": str} or None.
    If OPENROUTER_API_KEY is not set or a call fails, returns None (pipeline continues).
    """
    if not text:
        return None
    exec_sum = _chat(EXEC_SYS, text)
    tech_sum = _chat(TECH_SYS, text)
    if exec_sum or tech_sum:
        return {"exec": exec_sum or "", "tech": tech_sum or ""}
    return None
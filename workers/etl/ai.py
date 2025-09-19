import os
from anthropic import Anthropic
client = Anthropic(api_key=os.getenv('CLAUDE_API_KEY'))
def summarize(text: str):
    try:
        m1 = client.messages.create(model="claude-3-5-sonnet-20240620", max_tokens=300,
            messages=[{"role":"user","content":"Summarize this security advisory in <=80 words for executives:\\n\\n"+text}])
        m2 = client.messages.create(model="claude-3-5-sonnet-20240620", max_tokens=300,
            messages=[{"role":"user","content":"Now summarize as 3-5 technical bullets (affected products, CVEs, mitigations):\\n\\n"+text}])
        return {"exec": m1.content[0].text, "tech": m2.content[0].text}
    except Exception:
        return None
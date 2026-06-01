import os
import json
import requests


creds_path = os.path.expanduser("~/.claude/.credentials.json")
with open(creds_path) as f:
    creds = json.load(f)
    token = creds.get("claudeAiOauth", {}).get("accessToken")

print("token :", token)

response = requests.post(
    "https://api.anthropic.com/v1/messages",
    headers={
        "Authorization": f"Bearer {token}",
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    },
    json={
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "say hello"}],
    },
)

print(f"Status: {response.status_code}")
print(response.json())

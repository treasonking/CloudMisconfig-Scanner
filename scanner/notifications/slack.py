from __future__ import annotations

import json
import urllib.request


def send_slack_message(webhook_url: str, text: str) -> None:
    payload = {"text": text}
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10):
        return

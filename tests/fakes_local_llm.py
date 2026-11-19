"""A scripted, loopback-only OpenAI-compatible server for tests (ADR 0015).

Real HTTP on 127.0.0.1 (stdlib only), so the local provider is exercised end to
end without any model: each POST /v1/chat/completions pops the next scripted
reply and records the request body; GET /v1/models lists ``models``.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def completion(text: str = "", tool_calls=None, finish: str = "stop",
               prompt_tokens: int = 100, completion_tokens: int = 50) -> dict:
    msg: dict = {"role": "assistant", "content": text}
    if tool_calls:
        msg["tool_calls"] = tool_calls
    return {"id": "chatcmpl-test", "object": "chat.completion", "model": "fake-model",
            "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens}}


def tool_call(name: str, args: dict | str, call_id: str = "call_1") -> dict:
    return {"id": call_id, "type": "function",
            "function": {"name": name, "arguments": args if isinstance(args, str) else json.dumps(args)}}


class FakeOpenAIServer:
    def __init__(self, script: list, models=("fake-model",)) -> None:
        self.script, self.models, self.requests = list(script), list(models), []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):  # quiet
                pass

            def _send(self, code: int, body: dict | str) -> None:
                data = (body if isinstance(body, str) else json.dumps(body)).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path == "/v1/models":
                    self._send(200, {"object": "list", "data": [{"id": m} for m in outer.models]})
                else:
                    self._send(404, {"error": "not found"})

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                outer.requests.append({"path": self.path, "body": body})
                if self.path != "/v1/chat/completions" or not outer.script:
                    self._send(404, {"error": "model not found"})
                    return
                item = outer.script.pop(0)
                if isinstance(item, tuple):  # (status, body) for error replies
                    self._send(*item)
                else:
                    self._send(200, item)

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._server.shutdown()
        self._server.server_close()

"""
GTI MCP health check.

Connects to your deployed GTI MCP server the same way Copilot Studio does
(streamable HTTP + X-API-Key), runs the full MCP handshake, lists the tools,
and calls one. Prints a clear PASS/FAIL for every step.

Configuration (any of these works):
    1. environment variables MCP_URL and MCP_KEY
    2. a local .env file with MCP_URL=... and MCP_KEY=...

Setup:
    python -m venv .venv
    # Windows:        .venv\\Scripts\\activate
    # macOS / Linux:  source .venv/bin/activate
    pip install -r requirements-test.txt

Run:
    python test_mcp.py
"""

import asyncio
import os
from pathlib import Path

import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


# --------------------------------------------------------------------------- #
# Minimal .env loader (no extra dependency)
# --------------------------------------------------------------------------- #
def load_dotenv(path: str = ".env") -> None:
    p = Path(path)
    if not p.exists():
        return
    for raw in p.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        os.environ.setdefault(key.strip(), val.strip().strip('"').strip("'"))


load_dotenv()

MCP_URL = os.environ.get("MCP_URL", "")
MCP_KEY = os.environ.get("MCP_KEY", "")

# Harmless test indicator that always exists in GTI (EICAR test file).
TEST_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

OK = "\033[92mPASS\033[0m"
NO = "\033[91mFAIL\033[0m"


def line(label: str, ok: bool, detail: str = "") -> None:
    print(f"  [{OK if ok else NO}] {label}" + (f"  ->  {detail}" if detail else ""))


async def main() -> None:
    if not MCP_URL or not MCP_KEY:
        print("Set MCP_URL and MCP_KEY (env vars or a .env file). See .env.example.")
        return

    base = MCP_URL.rsplit("/mcp", 1)[0]
    headers = {"X-API-Key": MCP_KEY}
    passed = True

    print(f"\nTesting GTI MCP at: {MCP_URL}\n")

    # --- Step 1: health endpoint (no auth) --------------------------------- #
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{base}/health")
        ok = r.status_code == 200
        line("Health endpoint reachable", ok, f"HTTP {r.status_code} {r.text[:60]}")
        passed &= ok
    except Exception as exc:
        line("Health endpoint reachable", False, str(exc))
        print("\n  Server not responding. Check the container logs:")
        print("    az containerapp logs show -g <rg> -n gti-mcp --tail 50\n")
        return

    # --- Step 2: wrong key must be rejected -------------------------------- #
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                MCP_URL,
                headers={
                    "X-API-Key": "definitely-wrong",
                    "Accept": "application/json, text/event-stream",
                    "Content-Type": "application/json",
                },
                json={"jsonrpc": "2.0", "id": 1, "method": "initialize",
                      "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                                 "clientInfo": {"name": "t", "version": "1"}}},
            )
        ok = r.status_code == 401
        line("Wrong X-API-Key is rejected (401)", ok, f"HTTP {r.status_code}")
        passed &= ok
    except Exception as exc:
        line("Wrong X-API-Key is rejected (401)", False, str(exc))

    # --- Step 3: full MCP handshake + list tools + call one ---------------- #
    try:
        async with streamablehttp_client(MCP_URL, headers=headers) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                line("MCP handshake (initialize)", True, "connected, no 421/401")

                tools = (await session.list_tools()).tools
                names = [t.name for t in tools]
                ok_tools = len(names) >= 1
                line("List tools", ok_tools, f"{len(names)} tools: {', '.join(names)}")
                passed &= ok_tools

                result = await session.call_tool("get_file_report", {"file_hash": TEST_HASH})
                text = "".join(getattr(b, "text", "") for b in result.content)
                if '"error"' in text and ("unauthorized" in text or "forbidden" in text):
                    line("Call get_file_report", False,
                         "MCP works, but VT_APIKEY is invalid/insufficient "
                         "(fix the vt-apikey secret)")
                    passed = False
                else:
                    line("Call get_file_report (live GTI lookup)", True, text[:120] + "...")
    except Exception as exc:
        line("MCP handshake / tool call", False, f"{type(exc).__name__}: {exc}")
        passed = False

    print()
    print("=" * 56)
    print("  RESULT:", "ALL CHECKS PASSED — ready for Copilot Studio"
          if passed else "SOME CHECKS FAILED — see above")
    print("=" * 56, "\n")


if __name__ == "__main__":
    asyncio.run(main())

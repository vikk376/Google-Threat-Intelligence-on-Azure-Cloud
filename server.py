"""
Google Threat Intelligence (GTI) MCP server.

Streamable-HTTP transport, designed to run on Azure Container Apps behind
ingress and be consumed by Microsoft Copilot Studio.

Two-layer security:
  1. EDGE_API_KEY  -> validated as the "X-API-Key" header by edge middleware.
                      This is the gate Copilot Studio authenticates with.
  2. VT_APIKEY     -> your Google Threat Intelligence / VirusTotal API key,
                      never exposed outside the container; used server-side only.

Why no 421 (Misdirected Request):
  The MCP SDK auto-enables DNS-rebinding protection when it thinks the bind host
  is localhost, then rejects the real ingress Host header with HTTP 421. We build
  the FastMCP instance ourselves with transport_security explicitly set, so that
  decision is never left to auto-detection. Host validation is handled by the
  X-API-Key edge layer instead.
"""

import base64
import os

import httpx
import uvicorn
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

# --------------------------------------------------------------------------- #
# Configuration (from environment / Container App secrets)
# --------------------------------------------------------------------------- #
VT_APIKEY = os.environ.get("VT_APIKEY", "").strip()
EDGE_API_KEY = os.environ.get("EDGE_API_KEY", "").strip()
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "8080"))

GTI_BASE = "https://www.virustotal.com/api/v3"

if not VT_APIKEY:
    raise RuntimeError("VT_APIKEY is not set. Provide your GTI/VirusTotal API key.")

# --------------------------------------------------------------------------- #
# FastMCP instance -- transport security set EXPLICITLY (this prevents the 421)
# --------------------------------------------------------------------------- #
mcp = FastMCP(
    "gti-mcp",
    host=HOST,
    port=PORT,
    stateless_http=True,  # no sticky sessions -> safe across Container App replicas
    transport_security=TransportSecuritySettings(
        # Host validation is done by the X-API-Key edge layer below, so we turn
        # off the SDK's localhost-oriented DNS-rebinding check that would 421 us.
        enable_dns_rebinding_protection=False,
    ),
)


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
async def _gti_get(path: str, params: dict | None = None) -> dict:
    """GET a GTI/VT v3 endpoint and return parsed JSON or a normalized error."""
    headers = {"x-apikey": VT_APIKEY, "accept": "application/json"}
    url = f"{GTI_BASE}{path}"
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            r = await client.get(url, headers=headers, params=params)
    except httpx.RequestError as exc:
        return {"error": f"request_failed: {exc}"}

    if r.status_code == 200:
        return r.json()
    if r.status_code == 404:
        return {"error": "not_found", "detail": "No GTI record for that indicator."}
    if r.status_code == 401:
        return {"error": "unauthorized", "detail": "VT_APIKEY invalid or expired."}
    if r.status_code == 403:
        return {"error": "forbidden", "detail": "Your GTI key lacks privilege for this endpoint."}
    if r.status_code == 429:
        return {"error": "rate_limited", "detail": "GTI/VT quota exceeded."}
    return {"error": f"http_{r.status_code}", "detail": r.text[:500]}


def _common(attrs: dict) -> dict:
    """Fields shared across files / urls / ips / domains."""
    out = {
        "last_analysis_stats": attrs.get("last_analysis_stats"),
        "reputation": attrs.get("reputation"),
    }
    # GTI enterprise verdict block (the actual GTI value-add over plain VT)
    if attrs.get("gti_assessment"):
        gti = attrs["gti_assessment"]
        out["gti_assessment"] = {
            "verdict": (gti.get("verdict") or {}).get("value"),
            "severity": (gti.get("severity") or {}).get("value"),
            "threat_score": (gti.get("threat_score") or {}).get("value"),
        }
    return out


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #
@mcp.tool()
async def get_file_report(file_hash: str) -> dict:
    """Get the GTI report for a file by MD5, SHA-1, or SHA-256 hash.

    Returns detection stats, reputation, threat classification, common names,
    and the GTI verdict/severity/threat score when available.
    """
    data = await _gti_get(f"/files/{file_hash.strip()}")
    if "error" in data:
        return data
    a = data.get("data", {}).get("attributes", {})
    result = _common(a)
    result.update(
        {
            "sha256": a.get("sha256"),
            "meaningful_name": a.get("meaningful_name"),
            "type_description": a.get("type_description"),
            "size": a.get("size"),
            "names": (a.get("names") or [])[:5],
            "popular_threat_classification": a.get("popular_threat_classification"),
            "times_submitted": a.get("times_submitted"),
        }
    )
    return result


@mcp.tool()
async def get_file_behavior(file_hash: str) -> dict:
    """Get the sandbox behavior summary for a file hash (processes, network,
    registry, MITRE technique IDs). Useful for triage of an unknown sample."""
    data = await _gti_get(f"/files/{file_hash.strip()}/behaviour_summary")
    if "error" in data:
        return data
    a = data.get("data", {})
    return {
        "processes_created": (a.get("processes_created") or [])[:15],
        "files_written": (a.get("files_written") or [])[:15],
        "dns_lookups": (a.get("dns_lookups") or [])[:15],
        "ip_traffic": (a.get("ip_traffic") or [])[:15],
        "mitre_attack_techniques": [
            t.get("id") for t in (a.get("mitre_attack_techniques") or [])
        ][:25],
        "verdicts": a.get("verdicts"),
    }


@mcp.tool()
async def get_url_report(url: str) -> dict:
    """Get the GTI report for a URL. Pass the raw URL; the server encodes it."""
    url_id = base64.urlsafe_b64encode(url.strip().encode()).decode().rstrip("=")
    data = await _gti_get(f"/urls/{url_id}")
    if "error" in data:
        return data
    a = data.get("data", {}).get("attributes", {})
    result = _common(a)
    result.update(
        {
            "url": a.get("url"),
            "final_url": a.get("last_final_url"),
            "title": a.get("title"),
            "categories": a.get("categories"),
        }
    )
    return result


@mcp.tool()
async def get_ip_report(ip: str) -> dict:
    """Get the GTI report for an IPv4/IPv6 address (reputation, ASN, geo)."""
    data = await _gti_get(f"/ip_addresses/{ip.strip()}")
    if "error" in data:
        return data
    a = data.get("data", {}).get("attributes", {})
    result = _common(a)
    result.update(
        {
            "as_owner": a.get("as_owner"),
            "asn": a.get("asn"),
            "country": a.get("country"),
            "network": a.get("network"),
        }
    )
    return result


@mcp.tool()
async def get_domain_report(domain: str) -> dict:
    """Get the GTI report for a domain (reputation, categories, registrar)."""
    data = await _gti_get(f"/domains/{domain.strip()}")
    if "error" in data:
        return data
    a = data.get("data", {}).get("attributes", {})
    result = _common(a)
    result.update(
        {
            "categories": a.get("categories"),
            "registrar": a.get("registrar"),
            "creation_date": a.get("creation_date"),
            "last_dns_records": (a.get("last_dns_records") or [])[:10],
        }
    )
    return result


@mcp.tool()
async def search_gti(query: str, limit: int = 10) -> dict:
    """Run a GTI Intelligence search (requires an enterprise/GTI key).
    Example queries: 'entity:file p:5+ tag:cobaltstrike', a hash, IP, or domain.
    """
    limit = max(1, min(limit, 40))
    data = await _gti_get("/search", params={"query": query, "limit": limit})
    if "error" in data:
        return data
    items = []
    for obj in data.get("data", []):
        a = obj.get("attributes", {})
        items.append(
            {
                "id": obj.get("id"),
                "type": obj.get("type"),
                "reputation": a.get("reputation"),
                "last_analysis_stats": a.get("last_analysis_stats"),
                "meaningful_name": a.get("meaningful_name"),
            }
        )
    return {"count": len(items), "results": items}


# --------------------------------------------------------------------------- #
# Health endpoint (unauthenticated) for Container Apps probes / smoke tests
# --------------------------------------------------------------------------- #
@mcp.custom_route("/health", methods=["GET"])
async def health(_request: Request) -> JSONResponse:
    return JSONResponse({"status": "ok", "service": "gti-mcp"})


# --------------------------------------------------------------------------- #
# X-API-Key edge middleware
# --------------------------------------------------------------------------- #
class ApiKeyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, api_key: str):
        super().__init__(app)
        self.api_key = api_key

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)
        if self.api_key:
            if request.headers.get("x-api-key") != self.api_key:
                return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)


# --------------------------------------------------------------------------- #
# Build the ASGI app and run
# --------------------------------------------------------------------------- #
app = mcp.streamable_http_app()  # serves the MCP endpoint at /mcp
app.add_middleware(ApiKeyMiddleware, api_key=EDGE_API_KEY)

if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)

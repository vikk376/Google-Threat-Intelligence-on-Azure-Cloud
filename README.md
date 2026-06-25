# GTI MCP Server for Microsoft Copilot Studio

A production-ready [Model Context Protocol](https://modelcontextprotocol.io) (MCP)
server that exposes **Google Threat Intelligence** (GTI / VirusTotal) as tools, runs
on **Azure Container Apps**, and plugs directly into **Microsoft Copilot Studio** as
an agent tool.

Built with FastMCP over **streamable HTTP**, with two-layer authentication and DNS
rebinding protection handled correctly so you never hit the classic `HTTP 421`
(Misdirected Request) error.

---

## Table of contents

1. [What this gives you](#what-this-gives-you)
2. [Architecture](#architecture)
3. [Prerequisites](#prerequisites)
4. [Step 1 — Clone the repository](#step-1--clone-the-repository)
5. [Step 2 — Provide your inputs (RG, region, API key)](#step-2--provide-your-inputs-rg-region-api-key)
6. [Step 3 — Deploy to Azure](#step-3--deploy-to-azure)
7. [Step 4 — Test the deployed server](#step-4--test-the-deployed-server)
8. [Step 5 — Connect to Microsoft Copilot Studio](#step-5--connect-to-microsoft-copilot-studio)
9. [Step 6 — Test inside Copilot Studio](#step-6--test-inside-copilot-studio)
10. [Day-2 operations](#day-2-operations)
11. [Troubleshooting](#troubleshooting)
12. [Project structure](#project-structure)
13. [Security notes](#security-notes)
14. [License](#license)

---

## What this gives you

**Six GTI tools** available to your Copilot Studio agent:

| Tool | Description |
|------|-------------|
| `get_file_report` | File verdict by MD5 / SHA-1 / SHA-256 |
| `get_file_behavior` | Sandbox behavior (processes, network, MITRE ATT&CK techniques) |
| `get_url_report` | URL verdict, categories, final URL |
| `get_ip_report` | IP reputation, ASN, geolocation |
| `get_domain_report` | Domain reputation, categories, registrar, DNS records |
| `search_gti` | GTI Intelligence search (enterprise / GTI-tier key required) |

---

## Architecture

```
Microsoft Copilot Studio
        │  streamable HTTP + X-API-Key
        ▼
Azure Container Apps (ingress, HTTPS)
        │
        ▼
gti-mcp container (FastMCP)
   ├─ X-API-Key edge middleware   ← validates Copilot's request
   └─ GTI tools  ──────────────►  Google Threat Intelligence / VirusTotal API v3
                                   (uses VT_APIKEY, server-side only)
```

**Two-layer security:**
- `VT_APIKEY` — your GTI / VirusTotal key. Stored as an Azure Container App secret;
  never leaves the container.
- `X-API-Key` (a.k.a. `EDGE_API_KEY`) — what Copilot Studio sends in the header.
  Auto-generated at deploy time if you don't provide one.

---

## Prerequisites

| Requirement | How to verify |
|-------------|---------------|
| Azure subscription with an existing resource group | `az group list -o table` |
| Azure CLI installed and logged in | `az --version` then `az login` |
| A Google Threat Intelligence / VirusTotal API key | [virustotal.com](https://www.virustotal.com) → your profile → API key |
| Bash shell (Linux, macOS, WSL, Git Bash, or **Azure Cloud Shell**) | `bash --version` |
| Python 3.11+ (only for the local test script) | `python --version` |
| Microsoft Copilot Studio access | [copilotstudio.microsoft.com](https://copilotstudio.microsoft.com) |

> **No Docker required** — the image is built server-side by `az acr build`.

> **No bash? Use Azure Cloud Shell** — open [shell.azure.com](https://shell.azure.com)
> or click the `>_` icon in the Azure portal. It has bash, `az`, `openssl`, and a
> file upload button built in.

---

## Step 1 — Clone the repository

```bash
git clone https://github.com/<your-user>/gti-mcp-copilot-studio.git
cd gti-mcp-copilot-studio
chmod +x deploy.sh
```

Or, if you downloaded the files manually, just `cd` into the folder and run the
`chmod` line.

---

## Step 2 — Provide your inputs (RG, region, API key)

You have **three ways** to provide configuration. Pick whichever is most convenient
— they can be combined.

### Method A — `.env` file (recommended)

This is the cleanest for repeat deploys. Copy the template and fill it in:

```bash
cp .env.example .env
nano .env        # or: code .env  /  vim .env  /  notepad .env
```

Fill in **at minimum** these three values:

```ini
RG=my-resource-group
LOCATION=centralindia
VT_APIKEY=paste-your-gti-or-virustotal-key-here
```

Save and exit. `.env` is in `.gitignore` so it can never be pushed.

Then run:

```bash
./deploy.sh
```

### Method B — Environment variables in your shell

Useful for CI or quick one-shot deploys:

```bash
export RG="my-resource-group"
export LOCATION="centralindia"
export VT_APIKEY="paste-your-gti-key"
./deploy.sh
```

### Method C — Interactive prompts (no files, no exports)

Just run it. The script will ask for anything missing:

```bash
./deploy.sh
```

You will see:

```
Azure resource group name: my-resource-group
Azure region (e.g. centralindia, eastus, canadacentral): centralindia
Google Threat Intelligence / VirusTotal API key:         ← typed but hidden
```

The API key prompt is hidden (like a password). Press **Enter** after each value.

### What the script needs vs. what's optional

| Variable | Required | Default if blank |
|----------|:--------:|------------------|
| `RG` | ✅ | _prompts you_ |
| `LOCATION` | ✅ | _prompts you_ |
| `VT_APIKEY` | ✅ | _prompts you (hidden)_ |
| `ACR` | ➖ | `acrgtimcp` + random suffix (must be globally unique) |
| `ENV_NAME` | ➖ | `env-gti-mcp` |
| `APP` | ➖ | `gti-mcp` |
| `IMAGE_TAG` | ➖ | `1.0.0` |
| `CREATE_RG` | ➖ | `false` — script fails if `RG` doesn't exist. Set `true` to create it. |
| `EDGE_API_KEY` | ➖ | Auto-generated random 64-char hex (your `X-API-Key`) |

---

## Step 3 — Deploy to Azure

Once your inputs are in place, run:

```bash
./deploy.sh
```

Expected runtime: **3–5 minutes** (the ACR image build is the slow part).

You will see progress like:

```
>> Using existing resource group: my-resource-group
>> ACR: acrgtimcp17284
>> Building image gti-mcp:1.0.0 in ACR (no local Docker needed)
>> Container Apps environment: env-gti-mcp
>> Container App: gti-mcp
```

When it finishes, the script prints a results block. **This is the most important
output of the whole deploy — copy these three values somewhere safe:**

```
============================================================
  GTI MCP deployed successfully.

  Resource group: my-resource-group
  Region:         centralindia
  ACR:            acrgtimcp17284

  MCP URL:    https://gti-mcp.<unique-suffix>.centralindia.azurecontainerapps.io/mcp
  Health:     https://gti-mcp.<unique-suffix>.centralindia.azurecontainerapps.io/health
  X-API-Key:  <64-char-hex-string-shown-only-here>

  >> Save the X-API-Key now. You enter it in Copilot Studio
     and it is not shown again. To read it back later:
     az containerapp secret show -g my-resource-group -n gti-mcp \
       --secret-name edge-api-key --query value -o tsv
============================================================
```

> If you lose the **X-API-Key**, run the `az containerapp secret show` command from
> the output block to read it back.

---

## Step 4 — Test the deployed server

Before going to Copilot Studio, run the local health check so you know the server
side is solid. Add the two new values to your `.env`:

```ini
# at the bottom of .env
MCP_URL=https://gti-mcp.<unique-suffix>.centralindia.azurecontainerapps.io/mcp
MCP_KEY=paste-the-X-API-Key-from-the-deploy-output
```

Then in your terminal:

```bash
python -m venv .venv

# Windows:
.venv\Scripts\activate
# macOS / Linux:
source .venv/bin/activate

pip install -r requirements-test.txt
python test_mcp.py
```

You should see five `PASS` lines:

```
Testing GTI MCP at: https://gti-mcp.<...>.azurecontainerapps.io/mcp

  [PASS] Health endpoint reachable                ->  HTTP 200 {"status":"ok",...}
  [PASS] Wrong X-API-Key is rejected (401)        ->  HTTP 401
  [PASS] MCP handshake (initialize)               ->  connected, no 421/401
  [PASS] List tools                               ->  6 tools: get_file_report, ...
  [PASS] Call get_file_report (live GTI lookup)   ->  {"sha256":"...", ...}

========================================================
  RESULT: ALL CHECKS PASSED — ready for Copilot Studio
========================================================
```

If any check fails, the message tells you which layer is broken. See
[Troubleshooting](#troubleshooting).

---

## Step 5 — Connect to Microsoft Copilot Studio

You will need:
- Your **MCP URL** (from Step 3 — ends in `/mcp`)
- Your **X-API-Key** (from Step 3)

### 5.1 — Open your agent and enable generative orchestration

1. Go to **[copilotstudio.microsoft.com](https://copilotstudio.microsoft.com)** and sign in.
2. **Top-right** — confirm you're in the right **environment**. The connection you
   create will live in this environment.
3. Open your agent, or click **Create → New agent** and give it a name.
4. Click the **gear / Settings** (top-right inside the agent) → **Generative AI**
   (or the orchestration section) → confirm **orchestration is Generative** → **Save**.
   *MCP tools are ignored under classic orchestration — this step is mandatory.*

### 5.2 — Add the MCP server as a tool

5. In the agent's left nav, click **Tools**.
6. Click **+ Add a tool**.
7. In the panel that appears, click **+ New tool** at the top.
8. Choose **Model Context Protocol**.
9. Fill in the form:
   - **Server name:** `GTI`
   - **Description:** `Google Threat Intelligence lookups (file, URL, IP, domain, sandbox, search)`
   - **Server URL / Endpoint:** *paste your* `https://<...>/mcp` *URL*
   - **Authentication:** select **API key**
10. API key details appear:
    - **Parameter / Header name:** `X-API-Key`
    - **Location:** **Header**
    - Click **Create**.

### 5.3 — Create the connection

11. Copilot prompts you to **Create a connection**. A dialog asks for the API key value.
12. Paste your **X-API-Key** → click **Create**.
13. Back on the tool, click **Add to agent** (or **Add and configure**).

### 5.4 — Confirm the connection

14. Click the **GTI** tool to open its detail page.
15. Look at the **Tools** section — it queries your server **live** and lists all
    six tools (`get_file_report`, `get_file_behavior`, `get_url_report`,
    `get_ip_report`, `get_domain_report`, `search_gti`). If they appear, the wiring
    is correct.
16. *(Optional)* On each tool, flip the **completion / confirmation** setting so the
    agent runs it automatically without asking the user — smoother SOC chat UX.

---

## Step 6 — Test inside Copilot Studio

1. Open the **Test your agent** panel on the right.
2. Send a prompt that forces a tool call. For example:

   > Use GTI to get the file report for SHA256
   > `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`

3. You should see the agent invoke the `get_file_report` tool and return a verdict.
4. Try an IP or domain next to confirm tool selection works across the set:

   > Get the GTI report for IP `8.8.8.8`.

### Publish so other channels can use it

5. **Top-right → Publish**.
6. **Channels / Settings** → add Teams, web, or wherever you want the agent
   reachable.

---

## Day-2 operations

### Push a code change and redeploy

```bash
az acr build -r <your-ACR> -t gti-mcp:1.0.1 .
az containerapp update -g <your-RG> -n gti-mcp \
  --image <your-ACR>.azurecr.io/gti-mcp:1.0.1
```

### Read the X-API-Key back

```bash
az containerapp secret show -g <your-RG> -n gti-mcp \
  --secret-name edge-api-key --query value -o tsv
```

### Rotate the X-API-Key

```bash
az containerapp secret set -g <your-RG> -n gti-mcp \
  --secrets edge-api-key=$(openssl rand -hex 32)
```
Then update the value in your Copilot Studio connection (Tools → GTI → connection).

### Tail the live logs

```bash
az containerapp logs show -g <your-RG> -n gti-mcp --tail 100 --follow
```

### Tear it down

```bash
az containerapp delete -g <your-RG> -n gti-mcp --yes
az containerapp env delete -g <your-RG> -n env-gti-mcp --yes
az acr delete -g <your-RG> -n <your-ACR> --yes
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|--------|------|-----|
| `test_mcp.py` step 1 fails / times out | Container not running, or wrong URL | `az containerapp logs show -g <RG> -n gti-mcp --tail 50` |
| Returns HTTP `421` Misdirected Request | Stale image without the transport-security fix | Rebuild + redeploy with a new tag |
| Returns HTTP `401` with the correct key | The `edge-api-key` secret in Azure doesn't match what you're sending | Read it back with `az containerapp secret show ...` |
| Step 5 (live GTI lookup) returns `unauthorized` / `forbidden` | The `VT_APIKEY` secret is wrong or your key lacks privilege | Update with `az containerapp secret set ... --secrets vt-apikey=<new-key>` |
| Copilot Studio "Tools" section shows 0 tools | Wrong URL (must end in `/mcp`) or wrong X-API-Key | Re-run `test_mcp.py` first; fix what fails there |
| `search_gti` returns `forbidden` but others work | `search_gti` needs an enterprise / GTI-tier key | Use a GTI Enterprise key, or remove `search_gti` from your agent |
| `deploy.sh` says "resource group not found" | RG name typo, or wrong subscription | `az group list -o table`, or set `CREATE_RG=true` to create it |

---

## Project structure

```
.
├── server.py              # GTI MCP server (FastMCP, streamable HTTP, X-API-Key)
├── Dockerfile             # container image build
├── requirements.txt       # server runtime dependencies
├── deploy.sh              # one-command Azure deploy (.env / env / interactive)
├── test_mcp.py            # local health check (full MCP handshake)
├── requirements-test.txt  # test-only dependencies
├── .env.example           # config template — copy to .env, fill in, never commit
├── .gitignore             # keeps .env, .venv, logs, __pycache__ out of git
├── .dockerignore          # keeps secrets and dev files out of the image
├── LICENSE                # MIT
└── README.md              # this file
```

---

## Security notes

- **Never commit `.env`** — it holds your real keys. It is gitignored, but verify
  with `git status` before every commit.
- `VT_APIKEY` and `EDGE_API_KEY` are stored as **Azure Container App secrets**, not
  in the image or in source code.
- Treat the **X-API-Key** like a password. Rotate it whenever it may have been
  exposed (chat logs, screenshots, support tickets).
- The endpoint is **public HTTPS** by design — Copilot must reach it. The X-API-Key
  edge layer is what protects it from unauthenticated callers.
- For extra hardening you can put Azure API Management or Front Door in front of the
  Container App and add WAF / IP allowlists.

---

## License

MIT — see [LICENSE](LICENSE).

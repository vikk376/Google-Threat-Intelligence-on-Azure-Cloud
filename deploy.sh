#!/usr/bin/env bash
#
# Deploy the GTI MCP server to Azure Container Apps.
#
# Reads configuration from (in order of precedence):
#   1. environment variables already set in your shell
#   2. a local .env file (copy .env.example -> .env and fill it in)
#   3. interactive prompts for anything still missing
#
# Prereqs: az CLI logged in (`az login`). Docker NOT required (uses `az acr build`).
#
# Usage:
#   cp .env.example .env      # then edit .env
#   ./deploy.sh
#
set -euo pipefail

# ---- Load .env if present ------------------------------------------------- #
if [[ -f .env ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env
  set +a
fi

# ---- Prompt for any required value still missing -------------------------- #
prompt_if_empty() {
  local var="$1" msg="$2" mode="${3:-}"
  if [[ -z "${!var:-}" ]]; then
    if [[ "$mode" == "secret" ]]; then
      read -rsp "$msg: " val; echo
    else
      read -rp "$msg: " val
    fi
    printf -v "$var" '%s' "$val"
  fi
}

prompt_if_empty RG        "Azure resource group name"
prompt_if_empty LOCATION  "Azure region (e.g. centralindia, eastus, canadacentral)"
prompt_if_empty VT_APIKEY "Google Threat Intelligence / VirusTotal API key" secret

# ---- Optional values with sensible defaults ------------------------------- #
ACR="${ACR:-acrgtimcp$RANDOM}"          # globally unique, lowercase alnum
ENV_NAME="${ENV_NAME:-env-gti-mcp}"
APP="${APP:-gti-mcp}"
IMAGE_TAG="${IMAGE_TAG:-1.0.0}"
CREATE_RG="${CREATE_RG:-false}"         # set to true to create the RG if missing

# Auto-generate the edge key (X-API-Key) if not supplied
EDGE_API_KEY="${EDGE_API_KEY:-$(openssl rand -hex 32)}"

# ---- Resource group: use existing, or create only if explicitly allowed --- #
if az group show -n "$RG" -o none 2>/dev/null; then
  echo ">> Using existing resource group: $RG"
elif [[ "$CREATE_RG" == "true" ]]; then
  echo ">> Creating resource group: $RG ($LOCATION)"
  az group create -n "$RG" -l "$LOCATION" -o none
else
  echo "ERROR: resource group '$RG' not found." >&2
  echo "       Set CREATE_RG=true to create it, or fix RG in .env." >&2
  exit 1
fi

echo ">> ACR: $ACR"
az acr create -n "$ACR" -g "$RG" -l "$LOCATION" --sku Basic --admin-enabled true -o none

echo ">> Building image gti-mcp:$IMAGE_TAG in ACR (no local Docker needed)"
az acr build -r "$ACR" -t "gti-mcp:$IMAGE_TAG" . -o none

ACR_SERVER=$(az acr show -n "$ACR" -g "$RG" --query loginServer -o tsv)
ACR_USER=$(az acr credential show -n "$ACR" --query username -o tsv)
ACR_PASS=$(az acr credential show -n "$ACR" --query "passwords[0].value" -o tsv)

echo ">> Container Apps environment: $ENV_NAME"
az containerapp env create -n "$ENV_NAME" -g "$RG" -l "$LOCATION" -o none

echo ">> Container App: $APP"
az containerapp create \
  -n "$APP" -g "$RG" --environment "$ENV_NAME" \
  --image "$ACR_SERVER/gti-mcp:$IMAGE_TAG" \
  --registry-server "$ACR_SERVER" \
  --registry-username "$ACR_USER" \
  --registry-password "$ACR_PASS" \
  --target-port 8080 \
  --ingress external \
  --transport http \
  --min-replicas 1 \
  --max-replicas 3 \
  --cpu 0.5 --memory 1.0Gi \
  --secrets vt-apikey="$VT_APIKEY" edge-api-key="$EDGE_API_KEY" \
  --env-vars VT_APIKEY=secretref:vt-apikey EDGE_API_KEY=secretref:edge-api-key \
  -o none

FQDN=$(az containerapp show -n "$APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)

cat <<MSG

============================================================
  GTI MCP deployed successfully.

  Resource group: $RG
  Region:         $LOCATION
  ACR:            $ACR

  MCP URL:    https://$FQDN/mcp
  Health:     https://$FQDN/health
  X-API-Key:  $EDGE_API_KEY

  >> Save the X-API-Key now. You enter it in Copilot Studio
     and it is not shown again. To read it back later:
     az containerapp secret show -g $RG -n $APP \\
       --secret-name edge-api-key --query value -o tsv
============================================================
MSG

#!/usr/bin/env bash
#
# Deploy the GTI MCP server to Azure Container Apps from scratch.
#
# Prereqs: az CLI logged in (`az login`), Docker not required (uses `az acr build`).
# Usage:
#   export VT_APIKEY="your-gti-key"
#   ./deploy.sh
#
# Override any default by exporting it first, e.g. export LOCATION=eastus
#
set -euo pipefail

# ---- Config -------------------------------------------------------------- #
RG="${RG:-rg-gti-mcp}"
LOCATION="${LOCATION:-canadacentral}"
ACR="${ACR:-acrgtimcp$RANDOM}"          # must be globally unique, lowercase alnum
ENV_NAME="${ENV_NAME:-env-gti-mcp}"
APP="${APP:-gti-mcp}"
IMAGE_TAG="${IMAGE_TAG:-1.0.0}"

VT_APIKEY="${VT_APIKEY:?Set VT_APIKEY to your GTI/VirusTotal API key}"
# Auto-generate the edge key if not supplied
EDGE_API_KEY="${EDGE_API_KEY:-$(openssl rand -hex 32)}"

echo ">> Resource group: $RG ($LOCATION)"
az group create -n "$RG" -l "$LOCATION" -o none

echo ">> ACR: $ACR"
az acr create -n "$ACR" -g "$RG" --sku Basic --admin-enabled true -o none

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

cat <<EOF

============================================================
  GTI MCP deployed successfully.

  MCP URL:    https://$FQDN/mcp
  Health:     https://$FQDN/health
  X-API-Key:  $EDGE_API_KEY

  Save the X-API-Key — you enter it in Copilot Studio.
============================================================
EOF

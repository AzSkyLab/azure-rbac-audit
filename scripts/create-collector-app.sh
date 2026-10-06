#!/usr/bin/env bash
# Creates the read-only "rbac-audit-collector" app registration in the CURRENT az login tenant.
# Run signed in as an admin who can grant admin consent and assign roles at the tenant root MG.
set -euo pipefail

NAME="rbac-audit-collector"
CERT_DIR="$HOME/.config/rbac-audit"          # outside the repo, never committed
GRAPH_API="00000003-0000-0000-c000-000000000000"
PERMS=(Directory.Read.All RoleManagement.Read.Directory PrivilegedAccess.Read.AzureADGroup AccessReview.Read.All)

TENANT_ID=$(az account show --query tenantId -o tsv)
echo "Tenant: $TENANT_ID"
read -r -p "Create $NAME in this tenant? [y/N] " ok; [[ "$ok" == "y" ]] || exit 1

APP_ID=$(az ad app create --display-name "$NAME" --sign-in-audience AzureADMyOrg --query appId -o tsv)
az ad sp create --id "$APP_ID" >/dev/null
echo "App (client) ID: $APP_ID"

mkdir -p "$CERT_DIR"; chmod 700 "$CERT_DIR"
openssl req -x509 -newkey rsa:4096 -nodes -days 365 -subj "/CN=$NAME" \
  -keyout "$CERT_DIR/$NAME.key" -out "$CERT_DIR/$NAME.crt" 2>/dev/null
cat "$CERT_DIR/$NAME.key" "$CERT_DIR/$NAME.crt" > "$CERT_DIR/$NAME.pem"
chmod 600 "$CERT_DIR"/*
rm "$CERT_DIR/$NAME.key"
az ad app credential reset --id "$APP_ID" --cert "@$CERT_DIR/$NAME.crt" --append >/dev/null

for p in "${PERMS[@]}"; do
  ROLE_ID=$(az ad sp show --id "$GRAPH_API" --query "appRoles[?value=='$p'].id | [0]" -o tsv)
  [[ -n "$ROLE_ID" ]] || { echo "Graph permission $p not found"; exit 1; }
  az ad app permission add --id "$APP_ID" --api "$GRAPH_API" --api-permissions "$ROLE_ID=Role" 2>/dev/null
  echo "Added $p"
done
sleep 20
az ad app permission admin-consent --id "$APP_ID"

az role assignment create --assignee "$APP_ID" --role Reader \
  --scope "/providers/Microsoft.Management/managementGroups/$TENANT_ID" >/dev/null

cat <<EOF

Done. Add this to config.local.yaml:

auth:
  mode: certificate
  client_id: "$APP_ID"
  certificate_path: "$CERT_DIR/$NAME.pem"
EOF

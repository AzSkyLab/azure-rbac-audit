#!/usr/bin/env bash
# Creates, or repairs, the read-only "rbac-audit-collector" app registration in the CURRENT az login tenant.
# Run signed in as an admin who can grant admin consent and assign roles at the tenant root MG.
# Safe to re-run: every step checks the current state first and only adds what is missing.
#   --rotate-cert   generate a new certificate and append it to the app (the old one keeps working until removed)
set -euo pipefail

NAME="rbac-audit-collector"
CERT_DIR="$HOME/.config/rbac-audit"          # outside the repo, never committed
PEM="$CERT_DIR/$NAME.pem"
GRAPH_API="00000003-0000-0000-c000-000000000000"
PERMS=(Directory.Read.All RoleManagement.Read.Directory PrivilegedAccess.Read.AzureADGroup AccessReview.Read.All AuditLog.Read.All)
ROTATE=false
case "${1:-}" in
  --rotate-cert) ROTATE=true ;;
  "") ;;
  *) echo "usage: $0 [--rotate-cert]" >&2; exit 2 ;;
esac

TENANT_ID=$(az account show --query tenantId -o tsv)
echo "Tenant: $TENANT_ID"
read -r -p "Create or repair $NAME in this tenant? [y/N] " ok; [[ "$ok" == "y" ]] || exit 1

# App registration and service principal
APP_IDS=$(az ad app list --filter "displayName eq '$NAME'" --query "[].appId" -o tsv)
if [[ $(wc -w <<<"$APP_IDS") -gt 1 ]]; then
  echo "More than one app named $NAME ($APP_IDS); resolve that by hand first." >&2; exit 1
elif [[ -n "$APP_IDS" ]]; then
  APP_ID=$APP_IDS; echo "App exists: $APP_ID"
else
  APP_ID=$(az ad app create --display-name "$NAME" --sign-in-audience AzureADMyOrg --query appId -o tsv)
  echo "App created: $APP_ID"
fi
if SP_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv 2>/dev/null); then
  echo "Service principal exists: $SP_ID"
else
  SP_ID=$(az ad sp create --id "$APP_ID" --query id -o tsv)
  echo "Service principal created: $SP_ID"
fi

# Certificate: reuse the local one unless rotating; make sure the app trusts it
mkdir -p "$CERT_DIR"; chmod 700 "$CERT_DIR"
if [[ -f "$PEM" && "$ROTATE" == false ]]; then
  echo "Certificate exists: $PEM ($(openssl x509 -in "$PEM" -noout -enddate))"
else
  [[ -f "$PEM" ]] && mv "$PEM" "$PEM.$(date -u +%Y%m%dT%H%M%SZ).old" && echo "Old certificate kept as $PEM.*.old"
  openssl req -x509 -newkey rsa:4096 -nodes -days 365 -subj "/CN=$NAME" \
    -keyout "$CERT_DIR/$NAME.key" -out "$CERT_DIR/$NAME.crt" 2>/dev/null
  cat "$CERT_DIR/$NAME.key" "$CERT_DIR/$NAME.crt" > "$PEM"
  rm "$CERT_DIR/$NAME.key"
  echo "Certificate generated: $PEM"
fi
chmod 600 "$CERT_DIR"/*
openssl x509 -in "$PEM" -out "$CERT_DIR/$NAME.crt"
THUMB=$(openssl x509 -in "$PEM" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :)
if az ad app credential list --id "$APP_ID" --cert --query "[].customKeyIdentifier" -o tsv | grep -qix "$THUMB"; then
  echo "Certificate already registered on the app ($THUMB)"
else
  az ad app credential reset --id "$APP_ID" --cert "@$CERT_DIR/$NAME.crt" --append >/dev/null
  echo "Certificate registered on the app ($THUMB)"
fi

# Graph application permissions and admin consent
REQUESTED=$(az ad app show --id "$APP_ID" --query "requiredResourceAccess[?resourceAppId=='$GRAPH_API'].resourceAccess[].id" -o tsv)
GRANTED=$(az rest --url "https://graph.microsoft.com/v1.0/servicePrincipals/$SP_ID/appRoleAssignments" --query "value[].appRoleId" -o tsv)
NEED_CONSENT=false
for p in "${PERMS[@]}"; do
  ROLE_ID=$(az ad sp show --id "$GRAPH_API" --query "appRoles[?value=='$p'].id | [0]" -o tsv)
  [[ -n "$ROLE_ID" ]] || { echo "Graph permission $p not found"; exit 1; }
  if grep -qx "$ROLE_ID" <<<"$REQUESTED"; then
    echo "Permission requested: $p"
  else
    az ad app permission add --id "$APP_ID" --api "$GRAPH_API" --api-permissions "$ROLE_ID=Role" 2>/dev/null
    echo "Permission added: $p"
  fi
  grep -qx "$ROLE_ID" <<<"$GRANTED" || NEED_CONSENT=true
done
if [[ "$NEED_CONSENT" == true ]]; then
  sleep 20   # let the new permission requests replicate before consenting
  az ad app permission admin-consent --id "$APP_ID"
  echo "Admin consent granted"
else
  echo "Admin consent already granted for all permissions"
fi

# Azure Reader at the tenant root management group
MG_SCOPE="/providers/Microsoft.Management/managementGroups/$TENANT_ID"
if [[ -n $(az role assignment list --assignee "$SP_ID" --role Reader --scope "$MG_SCOPE" --query "[].id" -o tsv) ]]; then
  echo "Reader at the tenant root management group: exists"
else
  az role assignment create --assignee-object-id "$SP_ID" --assignee-principal-type ServicePrincipal \
    --role Reader --scope "$MG_SCOPE" >/dev/null
  echo "Reader at the tenant root management group: assigned"
fi

cat <<EOF

Done. config.local.yaml needs:

auth:
  mode: certificate
  client_id: "$APP_ID"
  certificate_path: "$PEM"
EOF

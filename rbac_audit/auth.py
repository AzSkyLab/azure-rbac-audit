"""Credential setup. Uses the existing `az login` session; stores nothing."""
from __future__ import annotations

import base64
import json

from azure.core.exceptions import ClientAuthenticationError
from azure.identity import AzureCliCredential, DefaultAzureCredential

ARM_SCOPE = "https://management.azure.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


def get_credential():
    """AzureCliCredential first, DefaultAzureCredential as fallback."""
    cli = AzureCliCredential()
    try:
        cli.get_token(ARM_SCOPE)
        return cli
    except ClientAuthenticationError:
        return DefaultAzureCredential(exclude_interactive_browser_credential=True)


def token_claims(token: str) -> dict:
    """Decode (not verify) a JWT payload to read who we are signed in as."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def identity_from_claims(claims: dict) -> dict:
    return {
        "tenant_id": claims.get("tid"),
        "object_id": claims.get("oid"),
        "upn": claims.get("upn") or claims.get("unique_name") or claims.get("preferred_username"),
        "name": claims.get("name"),
        "app_id": claims.get("appid") or claims.get("azp"),
        "identity_type": claims.get("idtyp") or ("user" if claims.get("upn") else "app"),
    }

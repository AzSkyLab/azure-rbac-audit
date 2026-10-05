"""Credential setup. Uses the existing `az login` session; stores nothing."""
from __future__ import annotations

import base64
import json
import os
import threading
import time
from pathlib import Path

from azure.core.exceptions import ClientAuthenticationError
from azure.identity import AzureCliCredential, CertificateCredential, DefaultAzureCredential

from .config import AuthConfig, ConfigError

ARM_SCOPE = "https://management.azure.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"


def build_credential(auth: AuthConfig, tenant_id: str):
    """Credential for the configured auth mode. Returns (credential, warnings). No secret is stored or logged."""
    if auth.mode != "certificate":
        return get_credential(), []
    path = Path(os.path.expanduser(auth.certificate_path))
    if not path.is_file():
        raise ConfigError(f"auth.certificate_path does not exist: {path}")
    warnings = []
    mode = path.stat().st_mode & 0o777
    if mode & 0o177:  # anything beyond owner read/write
        warnings.append(f"certificate file {path} has mode {mode:o}; it holds a private key, chmod 600 it")
    return CertificateCredential(tenant_id=tenant_id, client_id=auth.client_id, certificate_path=str(path)), warnings


def get_credential():
    """AzureCliCredential first, DefaultAzureCredential as fallback."""
    cli = AzureCliCredential()
    try:
        cli.get_token(ARM_SCOPE)
        return cli
    except ClientAuthenticationError:
        return DefaultAzureCredential(exclude_interactive_browser_credential=True)


class TokenCache:
    """Thread-safe per-scope token cache; AzureCliCredential would otherwise spawn `az` per request."""

    def __init__(self, credential, skew: int = 300, clock=time.time):
        self._cred, self._skew, self._clock = credential, skew, clock
        self._tokens: dict[str, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def get(self, scope: str) -> str:
        with self._lock:
            cached = self._tokens.get(scope)
            if cached and cached[1] - self._skew > self._clock():
                return cached[0]
            tok = self._cred.get_token(scope)
            self._tokens[scope] = (tok.token, float(tok.expires_on))
            return tok.token


def token_claims(token: str) -> dict:
    """Decode (not verify) a JWT payload to read who we are signed in as."""
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


def describe_identity(cred) -> dict:
    """Who the collector is: ARM token identity plus the Graph token's app roles / delegated scopes, and whether
    any of those grant write access (the collector must be read-only)."""
    ident = identity_from_claims(token_claims(cred.get_token(ARM_SCOPE).token))
    graph = token_claims(cred.get_token(GRAPH_SCOPE).token)
    roles, scopes = list(graph.get("roles") or []), (graph.get("scp") or "").split()
    ident["graph_token"] = {"roles": sorted(roles), "scp": sorted(scopes)}
    ident["read_only"] = not any("write" in p.lower() for p in roles + scopes)
    return ident


def identity_from_claims(claims: dict) -> dict:
    return {
        "tenant_id": claims.get("tid"),
        "object_id": claims.get("oid"),
        "upn": claims.get("upn") or claims.get("unique_name") or claims.get("preferred_username"),
        "name": claims.get("name"),
        "app_id": claims.get("appid") or claims.get("azp"),
        "identity_type": claims.get("idtyp") or ("user" if claims.get("upn") else "app"),
    }

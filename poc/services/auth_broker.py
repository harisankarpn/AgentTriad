"""
Pluggable Cloud Identity & Auth Broker (`poc/services/auth_broker.py`).

Replaces GCP-coupled authentication with a cloud-agnostic `CloudAuthBroker` supporting:
  1. Standard OIDC JWT verification (Google ID tokens, RS256/ES256 via OIDC JWKS
     `AAAS_OIDC_JWKS_URL`, or configured HS256 secrets) + OAuth 2.0 UserInfo lookup.
  2. Service-to-service OIDC Identity Token minting (GCP ADC / `gcloud` / OIDC JWT).
  3. 15-minute ephemeral HITL JIT token minting (`jit-wif-...` + OIDC `web_identity_token`),
     single-action validation/revocation, and multi-cloud Workload Identity exchange for:
       - GCP Workload Identity Federation (STS `urn:ietf:params:oauth:grant-type:token-exchange`)
       - AWS STS (`AssumeRoleWithWebIdentity`)
       - Azure / Microsoft Entra ID Federated Credentials (`jwt-bearer` client assertion)
  4. Backward-compatible `get_gcp_credentials()` resolution for GCP Cloud Run and local dev VMs.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import os
import re
import subprocess
import uuid
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import httpx
import jwt

CLOUD_PLATFORM_SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]
DEFAULT_JIT_SECRET = os.getenv("AAAS_JIT_SECRET", "aaas-triad-jit-ephemeral-secret-2026")
GOOGLE_ISSUERS = ("accounts.google.com", "https://accounts.google.com")


class AuthVerificationError(ValueError):
    """Raised when OIDC JWT, OAuth2 access token, or JIT token verification fails."""


class IdentityBrokerProvider(ABC):
    """Port interface for cloud-agnostic OIDC verification and multi-cloud JIT federation."""

    @abstractmethod
    def verify_oidc_jwt(
        self,
        token: str,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
        jwks_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cryptographically validates an OIDC JWT and returns normalized identity claims."""

    @abstractmethod
    async def verify_oauth2_access_token(
        self,
        access_token: str,
        userinfo_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validates an OAuth 2.0 access token against the configured UserInfo endpoint."""

    @abstractmethod
    def mint_oidc_id_token(
        self,
        audience: str,
        subject: Optional[str] = None,
        claims: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 900,
    ) -> str:
        """Mints a service-to-service OIDC Identity Token for Zero-Trust A2A calls."""

    @abstractmethod
    def mint_jit_token(
        self,
        incident_id: str,
        approved_by: str,
        scope: str,
        ttl_seconds: int = 900,
        target_cloud: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Mints a short-lived JIT token and OIDC web identity assertion exchangeable across clouds."""

    @abstractmethod
    def validate_jit_token(self, token_id: str, incident_id: str) -> bool:
        """Verifies a JIT token's HMAC signature, expiry, and revocation status."""

    @abstractmethod
    def revoke_jit_token(self, token_id: str) -> None:
        """Immediately revokes a single-action JIT token after execution."""

    @abstractmethod
    def exchange_jit_token(
        self,
        jit_token_record: Dict[str, Any],
        target_cloud: Optional[str] = None,
        execute_live: bool = False,
    ) -> Dict[str, Any]:
        """Builds or executes a federated credential exchange (GCP WIF, AWS STS, or Azure)."""


class CloudAuthBroker(IdentityBrokerProvider):
    """
    Pluggable OIDC & Multi-Cloud Workload Identity Broker (`AAAS_AUTH_PROVIDER=gcp|oidc|aws|azure`).
    """

    def __init__(
        self,
        jit_secret: Optional[str] = None,
        auth_provider: Optional[str] = None,
        default_cloud: Optional[str] = None,
        oidc_issuer: Optional[str] = None,
        oidc_jwks_url: Optional[str] = None,
        oidc_hs256_secret: Optional[str] = None,
        oidc_userinfo_url: Optional[str] = None,
    ) -> None:
        self.auth_provider = (
            auth_provider or os.getenv("AAAS_AUTH_PROVIDER") or "gcp"
        ).strip().lower()
        self.default_cloud = (
            default_cloud or os.getenv("CLOUD_PROVIDER") or "gcp"
        ).strip().lower()
        self.oidc_issuer = (
            oidc_issuer or os.getenv("AAAS_OIDC_ISSUER") or "https://accounts.google.com"
        ).strip()
        self.oidc_jwks_url = (
            oidc_jwks_url or os.getenv("AAAS_OIDC_JWKS_URL") or ""
        ).strip()
        self.oidc_userinfo_url = (
            oidc_userinfo_url
            or os.getenv("AAAS_OIDC_USERINFO_URL")
            or "https://www.googleapis.com/oauth2/v3/userinfo"
        ).strip()
        self._oidc_hs256_secret = (
            oidc_hs256_secret
            if oidc_hs256_secret is not None
            else os.getenv("AAAS_OIDC_HS256_SECRET", "").strip()
        )
        self._jit_secret_str = jit_secret or os.getenv("AAAS_JIT_SECRET") or DEFAULT_JIT_SECRET
        self._jit_secret = self._jit_secret_str.encode("utf-8")
        self._oidc_signing_private_key = os.getenv("AAAS_OIDC_SIGNING_PRIVATE_KEY", "").strip()
        self._oidc_signing_kid = os.getenv("AAAS_OIDC_SIGNING_KID", "aaas-jit-key-1").strip()
        self.jit_issuer = os.getenv("AAAS_JIT_OIDC_ISSUER", "https://aaas.agent-triad.internal").strip()

        self._active_tokens: Dict[str, Dict[str, Any]] = {}
        self._revoked_tokens: set[str] = set()
        self._jwks_clients: Dict[str, Any] = {}

    # ------------------------------------------------------------------
    # 1. Backward-Compatible GCP Credentials Resolution
    # ------------------------------------------------------------------

    def get_gcp_credentials(self) -> Optional[Any]:
        """Returns credentials with `cloud-platform` scope for Vertex AI and Cloud Logging."""
        try:
            import google.auth
            import google.oauth2.credentials
        except ImportError:
            return None

        # On Cloud Run or when an explicit key file is configured, prefer standard ADC first
        if os.getenv("K_SERVICE") or os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
            try:
                creds, _ = google.auth.default(scopes=CLOUD_PLATFORM_SCOPES)
                return creds
            except Exception:
                pass

        # Local dev VM fallback: active gcloud CLI account access token
        try:
            token = (
                subprocess.check_output(
                    ["gcloud", "auth", "print-access-token"],
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                )
                .decode("utf-8")
                .strip()
            )
            if token:
                return google.oauth2.credentials.Credentials(token=token)
        except Exception:
            pass

        try:
            creds, _ = google.auth.default(scopes=CLOUD_PLATFORM_SCOPES)
            return creds
        except Exception:
            return None

    # ------------------------------------------------------------------
    # 2. Standard OIDC JWT & OAuth 2.0 Verification
    # ------------------------------------------------------------------

    def _get_jwks_client(self, jwks_url: str) -> Any:
        client = self._jwks_clients.get(jwks_url)
        if client is None:
            client = jwt.PyJWKClient(jwks_url)
            self._jwks_clients[jwks_url] = client
        return client

    def _discover_jwks_url(self, issuer_url: str) -> Optional[str]:
        well_known = f"{issuer_url.rstrip('/')}/.well-known/openid-configuration"
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(well_known)
                if resp.status_code == 200:
                    return resp.json().get("jwks_uri")
        except Exception:
            return None
        return None

    def verify_oidc_jwt(
        self,
        token: str,
        audience: Optional[str] = None,
        issuer: Optional[str] = None,
        jwks_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Cryptographically validates an OIDC ID Token (JWT):
          - Strictly rejects malformed, unsigned (`alg=none`), expired, or forged JWTs.
          - Supports standard OIDC providers (Okta, Auth0, Entra ID, Keycloak) via JWKS
            (`AAAS_OIDC_JWKS_URL` or OIDC discovery), configured HS256 secrets, and
            Google Identity Services ID tokens (`google.oauth2.id_token.verify_oauth2_token`).
        """
        raw_token = (token or "").strip()
        if not raw_token or raw_token.count(".") != 2:
            raise AuthVerificationError("Malformed OIDC JWT: expected 3 dot-separated segments.")

        try:
            header = jwt.get_unverified_header(raw_token)
            unverified_claims = jwt.decode(
                raw_token,
                options={"verify_signature": False, "verify_exp": False, "verify_aud": False},
            )
        except Exception as exc:
            raise AuthVerificationError(f"OIDC JWT header/payload parsing failed: {exc}") from exc

        alg = str(header.get("alg") or "").strip()
        if not alg or alg.lower() == "none":
            raise AuthVerificationError("OIDC JWT rejected: unsigned (`alg=none`) tokens are forbidden.")

        token_iss = str(unverified_claims.get("iss") or "").strip()
        effective_jwks_url = (jwks_url or self.oidc_jwks_url).strip()
        expected_issuer = (issuer or "").strip() or None
        is_google_token = token_iss in GOOGLE_ISSUERS

        # Route A: Configured HS256/HS384/HS512 OIDC secret (explicitly enabled only)
        if alg in ("HS256", "HS384", "HS512"):
            if not self._oidc_hs256_secret:
                raise AuthVerificationError(
                    f"OIDC JWT uses {alg}, but AAAS_OIDC_HS256_SECRET is not configured."
                )
            try:
                decode_kwargs: Dict[str, Any] = {
                    "algorithms": [alg],
                    "options": {"verify_aud": bool(audience)},
                }
                if audience:
                    decode_kwargs["audience"] = audience
                if expected_issuer:
                    decode_kwargs["issuer"] = expected_issuer
                decoded = jwt.decode(raw_token, self._oidc_hs256_secret, **decode_kwargs)
                decoded.setdefault("provider", "oidc-hs256-verified")
                return decoded
            except Exception as exc:
                raise AuthVerificationError(f"OIDC HS256 JWT cryptographic verification failed: {exc}") from exc

        # Route B: Standard OIDC Asymmetric JWKS Verification (non-Google or explicit JWKS URL)
        if effective_jwks_url and (not is_google_token or self.auth_provider == "oidc"):
            try:
                signing_key = self._get_jwks_client(effective_jwks_url).get_signing_key_from_jwt(raw_token)
                decode_kwargs = {
                    "algorithms": ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"],
                    "options": {"verify_aud": bool(audience)},
                }
                if audience:
                    decode_kwargs["audience"] = audience
                if expected_issuer:
                    decode_kwargs["issuer"] = expected_issuer
                decoded = jwt.decode(raw_token, signing_key.key, **decode_kwargs)
                decoded.setdefault("provider", "oidc-jwks-verified")
                return decoded
            except Exception as exc:
                raise AuthVerificationError(f"OIDC JWKS cryptographic verification failed: {exc}") from exc

        # Route C: Google Identity Services ID Token Verification
        if is_google_token or (self.auth_provider == "gcp" and not effective_jwks_url):
            try:
                from google.auth.transport import requests as google_requests
                from google.oauth2 import id_token

                decoded = id_token.verify_oauth2_token(
                    raw_token,
                    google_requests.Request(),
                    audience or None,
                )
                if expected_issuer and decoded.get("iss") != expected_issuer:
                    raise AuthVerificationError(
                        f"OIDC issuer mismatch: expected {expected_issuer!r}, got {decoded.get('iss')!r}."
                    )
                decoded["provider"] = "google-id-token-verified"
                return dict(decoded)
            except AuthVerificationError:
                raise
            except Exception as exc:
                raise AuthVerificationError(f"Google ID token cryptographic verification failed: {exc}") from exc

        # Route D: Optional OIDC Discovery via `{iss}/.well-known/openid-configuration`
        if token_iss.startswith("https://") and os.getenv("AAAS_OIDC_ALLOW_DISCOVERY", "").lower() == "true":
            discovered_jwks = self._discover_jwks_url(token_iss)
            if discovered_jwks:
                return self.verify_oidc_jwt(
                    raw_token,
                    audience=audience,
                    issuer=expected_issuer or token_iss,
                    jwks_url=discovered_jwks,
                )

        raise AuthVerificationError(
            f"Unsupported OIDC issuer {token_iss!r}: configure AAAS_OIDC_JWKS_URL or use Google ID token."
        )

    async def verify_oauth2_access_token(
        self,
        access_token: str,
        userinfo_url: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Validates an OAuth 2.0 Bearer access token against the configured OIDC UserInfo endpoint."""
        token_clean = (access_token or "").strip()
        if not token_clean:
            raise AuthVerificationError("OAuth 2.0 access token is empty.")

        endpoint = (userinfo_url or self.oidc_userinfo_url).strip()
        try:
            async with httpx.AsyncClient(timeout=10.0) as http_client:
                resp = await http_client.get(
                    endpoint,
                    headers={"Authorization": f"Bearer {token_clean}"},
                )
        except Exception as exc:
            raise AuthVerificationError(f"OIDC UserInfo verification request failed: {exc}") from exc

        if resp.status_code != 200:
            raise AuthVerificationError(
                f"OAuth 2.0 token verification failed against {endpoint} (HTTP {resp.status_code})."
            )
        uinfo = resp.json()
        uinfo.setdefault(
            "provider",
            "google-oauth2-verified" if "googleapis.com" in endpoint else "oidc-oauth2-verified",
        )
        return uinfo

    # ------------------------------------------------------------------
    # 3. Service-to-Service OIDC Identity Token Minting
    # ------------------------------------------------------------------

    def _mint_internal_oidc_jwt(
        self,
        audience: str,
        subject: str,
        ttl_seconds: int = 900,
        extra_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        now = datetime.datetime.now(datetime.timezone.utc)
        now_epoch = int(now.timestamp())
        payload: Dict[str, Any] = {
            "iss": self.jit_issuer,
            "sub": subject,
            "aud": audience,
            "iat": now_epoch,
            "nbf": now_epoch,
            "exp": now_epoch + int(ttl_seconds),
            "jti": f"oidc-{uuid.uuid4().hex[:12]}",
        }
        if extra_claims:
            payload.update(extra_claims)

        if self._oidc_signing_private_key:
            return jwt.encode(
                payload,
                self._oidc_signing_private_key,
                algorithm="RS256",
                headers={"kid": self._oidc_signing_kid, "typ": "JWT"},
            )
        signing_secret = self._oidc_hs256_secret or self._jit_secret_str
        return jwt.encode(
            payload,
            signing_secret,
            algorithm="HS256",
            headers={"kid": self._oidc_signing_kid, "typ": "JWT"},
        )

    def mint_oidc_id_token(
        self,
        audience: str,
        subject: Optional[str] = None,
        claims: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 900,
    ) -> str:
        """
        Mints a service-to-service OIDC Identity Token:
          1. On GCP / `AAAS_AUTH_PROVIDER=gcp`: fetches Google OIDC ID token via ADC or `gcloud`.
          2. Off-GCP / `AAAS_AUTH_PROVIDER=oidc|aws|azure` (or when GCP token fetch is unavailable
             and an explicit signing key/secret is configured): mints a signed OIDC JWT assertion.
        """
        if self.auth_provider == "gcp":
            try:
                from google.auth.transport.requests import Request as GoogleAuthRequest
                from google.oauth2 import id_token as google_id_token

                token = google_id_token.fetch_id_token(GoogleAuthRequest(), audience)
                if token:
                    return token
            except Exception:
                pass

            try:
                proc = subprocess.run(
                    ["gcloud", "auth", "print-identity-token"],
                    capture_output=True,
                    text=True,
                    timeout=6,
                    check=False,
                )
                if proc.returncode == 0 and proc.stdout.strip():
                    return proc.stdout.strip()
            except Exception:
                pass

            # Only emit local JWT fallback on GCP mode if explicitly configured
            if not (self._oidc_signing_private_key or self._oidc_hs256_secret):
                return ""

        return self._mint_internal_oidc_jwt(
            audience=audience,
            subject=subject or os.getenv("K_SERVICE") or "aaas-control-plane",
            ttl_seconds=ttl_seconds,
            extra_claims=claims,
        )

    # ------------------------------------------------------------------
    # 4. 15-Minute JIT Token Minting, Validation & Multi-Cloud Exchange
    # ------------------------------------------------------------------

    def _compute_jit_sig(self, incident_id: str, expires_epoch: int, nonce: str) -> str:
        raw_msg = f"{incident_id}:{expires_epoch}:{nonce}".encode("utf-8")
        return hmac.new(self._jit_secret, raw_msg, hashlib.sha256).hexdigest()[:24]

    def _resolve_cloud_audience(self, target_cloud: str) -> str:
        cloud = target_cloud.strip().lower()
        if cloud == "aws":
            return os.getenv("AAAS_AWS_OIDC_AUDIENCE", "sts.amazonaws.com")
        if cloud == "azure":
            return os.getenv("AAAS_AZURE_OIDC_AUDIENCE", "api://AzureADTokenExchange")
        # Default: GCP Workload Identity Federation audience
        return os.getenv(
            "AAAS_GCP_WIF_AUDIENCE",
            f"//iam.googleapis.com/projects/{os.getenv('GCP_PROJECT_NUMBER', '000000000000')}"
            f"/locations/global/workloadIdentityPools/aaas-pool/providers/aaas-oidc",
        )

    def build_federation_exchange_request(
        self,
        jit_token_record: Dict[str, Any],
        target_cloud: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Constructs the exact protocol-compliant Workload Identity Federation token exchange
        payload for GCP WIF (STS), AWS STS (`AssumeRoleWithWebIdentity`), or Azure Federated
        Credentials (`jwt-bearer` client assertion).
        """
        cloud = (target_cloud or jit_token_record.get("target_cloud") or self.default_cloud or "gcp").strip().lower()
        web_identity_token = jit_token_record.get("web_identity_token", "")
        incident_id = str(jit_token_record.get("incident_id", "incident"))
        ttl_seconds = int(jit_token_record.get("ttl_seconds", 900))

        if cloud == "aws":
            aws_region = os.getenv("AAAS_AWS_REGION") or os.getenv("AWS_REGION") or "us-east-1"
            role_arn = os.getenv(
                "AAAS_AWS_ROLE_ARN",
                "arn:aws:iam::000000000000:role/aaas-jit-remediator",
            )
            safe_session = re.sub(r"[^A-Za-z0-9+=,.@_-]", "-", f"aaas-{incident_id}")[:64]
            # AWS STS AssumeRoleWithWebIdentity enforces DurationSeconds in [900, 43200]
            duration_seconds = max(900, min(ttl_seconds, 43200))
            return {
                "target_cloud": "aws",
                "protocol": "AWS STS AssumeRoleWithWebIdentity",
                "method": "POST",
                "endpoint": f"https://sts.{aws_region}.amazonaws.com/",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "payload": {
                    "Action": "AssumeRoleWithWebIdentity",
                    "Version": "2011-06-15",
                    "RoleArn": role_arn,
                    "RoleSessionName": safe_session,
                    "WebIdentityToken": web_identity_token,
                    "DurationSeconds": duration_seconds,
                },
            }

        if cloud == "azure":
            tenant_id = os.getenv("AAAS_AZURE_TENANT_ID", "common")
            client_id = os.getenv("AAAS_AZURE_CLIENT_ID", "00000000-0000-0000-0000-000000000000")
            azure_scope = os.getenv("AAAS_AZURE_SCOPE", "https://management.azure.com/.default")
            return {
                "target_cloud": "azure",
                "protocol": "Azure Entra ID Federated Identity Credential (JWT Bearer)",
                "method": "POST",
                "endpoint": f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "payload": {
                    "grant_type": "client_credentials",
                    "client_id": client_id,
                    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                    "client_assertion": web_identity_token,
                    "scope": azure_scope,
                },
            }

        # Default: GCP Workload Identity Federation STS
        wif_audience = self._resolve_cloud_audience("gcp")
        return {
            "target_cloud": "gcp",
            "protocol": "GCP Workload Identity Federation (STS RFC 8693)",
            "method": "POST",
            "endpoint": "https://sts.googleapis.com/v1/token",
            "headers": {"Content-Type": "application/json"},
            "payload": {
                "grantType": "urn:ietf:params:oauth:grant-type:token-exchange",
                "audience": wif_audience,
                "scope": "https://www.googleapis.com/auth/cloud-platform",
                "requestedTokenType": "urn:ietf:params:oauth:token-type:access_token",
                "subjectToken": web_identity_token,
                "subjectTokenType": "urn:ietf:params:oauth:token-type:jwt",
            },
        }

    def mint_jit_token(
        self,
        incident_id: str,
        approved_by: str,
        scope: str,
        ttl_seconds: int = 900,
        target_cloud: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Mints a 15-minute ephemeral HITL JIT authorization token preserving the exact
        `jit-wif-{expires_epoch}-{nonce}-{sig}` identifier alongside an OIDC JWT
        (`web_identity_token`) and federation exchange descriptors for GCP WIF, AWS STS,
        and Azure Federated Credentials.
        """
        issued_at = datetime.datetime.now(datetime.timezone.utc)
        expires_at = issued_at + datetime.timedelta(seconds=ttl_seconds)
        expires_epoch = int(expires_at.timestamp())
        nonce = uuid.uuid4().hex[:10]
        signature = self._compute_jit_sig(incident_id, expires_epoch, nonce)
        token_id = f"jit-wif-{expires_epoch}-{nonce}-{signature}"

        resolved_cloud = (target_cloud or self.default_cloud or "gcp").strip().lower()
        web_identity_token = self._mint_internal_oidc_jwt(
            audience=self._resolve_cloud_audience(resolved_cloud),
            subject=f"aaas:incident:{incident_id}:approver:{approved_by}",
            ttl_seconds=ttl_seconds,
            extra_claims={
                "jti": token_id,
                "aaas_incident_id": incident_id,
                "aaas_approved_by": approved_by,
                "aaas_scope": scope,
                "aaas_target_cloud": resolved_cloud,
            },
        )

        token_record: Dict[str, Any] = {
            "token_id": token_id,
            "incident_id": incident_id,
            "approved_by": approved_by,
            "scope": scope,
            "ttl_seconds": ttl_seconds,
            "issued_at": issued_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "expires_epoch": expires_epoch,
            "revoked": False,
            "target_cloud": resolved_cloud,
            "web_identity_token": web_identity_token,
            "federation_protocols": ["gcp_wif", "aws_sts", "azure_federated_credentials"],
        }
        token_record["federation_exchange"] = self.build_federation_exchange_request(
            token_record, target_cloud=resolved_cloud
        )
        self._active_tokens[token_id] = token_record
        return token_record

    def validate_jit_token(self, token_id: str, incident_id: str) -> bool:
        if not token_id or token_id in self._revoked_tokens:
            return False
        parts = token_id.split("-")
        # Expected format: jit-wif-{expires_epoch}-{nonce}-{signature}
        if len(parts) != 5 or parts[0] != "jit" or parts[1] != "wif":
            return False
        try:
            expires_epoch = int(parts[2])
        except ValueError:
            return False
        nonce = parts[3]
        sig = parts[4]
        now_epoch = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
        if now_epoch > expires_epoch:
            return False
        expected_sig = self._compute_jit_sig(incident_id, expires_epoch, nonce)
        return hmac.compare_digest(sig, expected_sig)

    def revoke_jit_token(self, token_id: str) -> None:
        self._revoked_tokens.add(token_id)
        if token_id in self._active_tokens:
            self._active_tokens[token_id]["revoked"] = True
            self._active_tokens[token_id]["revoked_at"] = (
                datetime.datetime.now(datetime.timezone.utc).isoformat()
            )

    def exchange_jit_token(
        self,
        jit_token_record: Dict[str, Any],
        target_cloud: Optional[str] = None,
        execute_live: bool = False,
    ) -> Dict[str, Any]:
        """
        Validates a minted JIT token and prepares (or executes when `execute_live=True`)
        short-lived credential exchange with GCP WIF, AWS STS, or Azure Federated Credentials.
        """
        token_id = str(jit_token_record.get("token_id") or "")
        incident_id = str(jit_token_record.get("incident_id") or "")
        if not self.validate_jit_token(token_id, incident_id):
            raise AuthVerificationError(
                f"Cannot exchange JIT token {token_id!r}: token is invalid, expired, or revoked."
            )

        cloud = (target_cloud or jit_token_record.get("target_cloud") or self.default_cloud or "gcp").strip().lower()
        # Re-mint audience-scoped web identity token if target_cloud differs from mint cloud
        record_for_exchange = dict(jit_token_record)
        if cloud != jit_token_record.get("target_cloud") or not record_for_exchange.get("web_identity_token"):
            remaining_ttl = max(
                60,
                int(jit_token_record.get("expires_epoch", 0))
                - int(datetime.datetime.now(datetime.timezone.utc).timestamp()),
            )
            record_for_exchange["web_identity_token"] = self._mint_internal_oidc_jwt(
                audience=self._resolve_cloud_audience(cloud),
                subject=f"aaas:incident:{incident_id}:approver:{jit_token_record.get('approved_by', 'operator')}",
                ttl_seconds=remaining_ttl,
                extra_claims={
                    "jti": token_id,
                    "aaas_incident_id": incident_id,
                    "aaas_scope": jit_token_record.get("scope", ""),
                    "aaas_target_cloud": cloud,
                },
            )

        exchange_req = self.build_federation_exchange_request(record_for_exchange, target_cloud=cloud)
        if not execute_live:
            return {
                "status": "EXCHANGE_READY",
                "executed_live": False,
                "token_id": token_id,
                **exchange_req,
            }

        # Live STS / Token Exchange Execution
        if cloud == "aws":
            try:
                import boto3  # type: ignore

                sts = boto3.client("sts", region_name=os.getenv("AAAS_AWS_REGION") or os.getenv("AWS_REGION") or "us-east-1")
                p = exchange_req["payload"]
                resp = sts.assume_role_with_web_identity(
                    RoleArn=p["RoleArn"],
                    RoleSessionName=p["RoleSessionName"],
                    WebIdentityToken=p["WebIdentityToken"],
                    DurationSeconds=int(p["DurationSeconds"]),
                )
                return {
                    "status": "EXCHANGED_LIVE",
                    "executed_live": True,
                    "target_cloud": "aws",
                    "protocol": exchange_req["protocol"],
                    "credentials": resp.get("Credentials", {}),
                }
            except ImportError:
                pass

        with httpx.Client(timeout=10.0) as client:
            if exchange_req["headers"].get("Content-Type") == "application/json":
                http_res = client.post(
                    exchange_req["endpoint"],
                    json=exchange_req["payload"],
                    headers=exchange_req["headers"],
                )
            else:
                http_res = client.post(
                    exchange_req["endpoint"],
                    data=exchange_req["payload"],
                    headers=exchange_req["headers"],
                )
        if http_res.status_code >= 400:
            raise AuthVerificationError(
                f"{exchange_req['protocol']} exchange failed (HTTP {http_res.status_code}): {http_res.text[:300]}"
            )
        try:
            body: Any = http_res.json()
        except Exception:
            body = http_res.text
        return {
            "status": "EXCHANGED_LIVE",
            "executed_live": True,
            "target_cloud": cloud,
            "protocol": exchange_req["protocol"],
            "response": body,
        }

    def get_status(self) -> Dict[str, Any]:
        return {
            "auth_provider": self.auth_provider,
            "default_cloud": self.default_cloud,
            "oidc_issuer": self.oidc_issuer,
            "oidc_jwks_configured": bool(self.oidc_jwks_url),
            "supported_federation_targets": [
                "gcp_wif",
                "aws_sts",
                "azure_federated_credentials",
            ],
            "active_jit_tokens": sum(1 for t in self._active_tokens.values() if not t.get("revoked")),
            "revoked_jit_tokens": len(self._revoked_tokens),
        }


# Singleton broker shared across API routes, A2A protocol, and GCP adapters
auth_broker = CloudAuthBroker()

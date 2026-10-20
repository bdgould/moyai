"""Organization sign-in through OpenID Connect; no provider API access is retained.

SignInFlow owns the browser-bound authorization code flow every provider shares:
single-use state, PKCE, nonce, return paths and the workspace session. Google
keeps its fixed endpoints and hosted-domain rules (app.google_sso). OidcSignIn
reads a standards-compliant provider's endpoints from its discovery document.
"""
import asyncio
import base64
import hashlib
import hmac
import re
import secrets
import time
from urllib.parse import urlencode

import httpx
import jwt
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, ConfigDict, Field

from .config import oidc_endpoint_allowed
from .file_links import valid_file_return_path
from .security import Throttle, digest

RETURN_PATH = re.compile(r"/#(?:tasks|connections|runtime|spend|users|run=[a-f0-9]{32}"
                         r"(?:&credential=[a-f0-9]{32}&generation=(?:0|[1-9][0-9]{0,14}))?)")
EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+")


def sign_in_return_path(value: str) -> str:
    """Return only a known in-app destination; anything else lands on tasks."""
    return value if RETURN_PATH.fullmatch(value) or valid_file_return_path(value) else "/#tasks"


class ProviderUnavailable(Exception):
    pass


class SignInStart(BaseModel):
    return_to: str = Field(default="/#tasks", max_length=1600)


class SignInRedirect(BaseModel):
    """Where the browser goes next: the provider's authorization page, or a local path."""
    model_config = ConfigDict(json_schema_serialization_defaults_required=True)
    url: str


class SignInFlow:
    # The route segment, session method and account kind are the same name.
    name = ""
    # Google keeps unprefixed state hashes so sign-ins started before OIDC finish.
    state_prefix = ""
    unconfigured = "Sign-in is not configured yet."
    client_id = ""
    scope = "openid email profile"

    def __init__(self, settings, security, store):
        self.settings, self.security, self.store = settings, security, store
        self.keys = {}
        self.keys_expire = 0
        self.last_key_fetch = 0
        self.key_lock = asyncio.Lock()
        self.attempts = Throttle(30)

    @property
    def callback(self):
        return self.security.origin + f"/auth/{self.name}/callback"

    @property
    def cookie(self):
        return f"{self.name}_login"

    @property
    def cookie_path(self):
        return f"/auth/{self.name}"

    def enabled(self) -> bool:
        raise NotImplementedError

    async def authorization_url(self, params: dict) -> str:
        raise NotImplementedError

    async def exchange(self, code, verifier, nonce) -> dict:
        raise NotImplementedError

    def usable_key(self, item) -> bool:
        return item.get("alg") == "RS256" and item.get("use") == "sig"

    async def signing_key(self, kid, keys_url):
        async with self.key_lock:
            now = time.monotonic()
            if now >= self.keys_expire or (kid not in self.keys and now - self.last_key_fetch > 60):
                async with httpx.AsyncClient(timeout=15) as client:
                    response = await client.get(keys_url)
                    response.raise_for_status()
                self.keys = {item["kid"]: jwt.PyJWK.from_dict(item).key
                             for item in response.json()["keys"] if self.usable_key(item)}
                self.keys_expire = now + 3600
                self.last_key_fetch = now
            if kid not in self.keys:
                raise ValueError("Unknown signing key")
            return self.keys[kid]

    def state_hash(self, state):
        return digest(self.state_prefix + state)

    def routes(self):
        router = APIRouter()
        operation = "start" + self.name.capitalize() + "SignIn"

        @router.post(f"/api/auth/{self.name}/start", operation_id=operation)
        async def start(body: SignInStart, request: Request, response: Response) -> SignInRedirect:
            self.security.check_origin(request)
            if self.settings.cloudflare_access_login:
                self.security.require(request)
                return SignInRedirect(url='/#tasks')
            if not self.enabled():
                raise HTTPException(409, self.unconfigured)
            client = self.security.client_key(request)
            if self.attempts.blocked(client):
                raise HTTPException(429, "Too many sign-in attempts. Wait a minute.")
            self.attempts.record(client)
            state, browser, nonce, verifier = (secrets.token_urlsafe(32) for _ in range(4))
            return_to = sign_in_return_path(body.return_to)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            try:
                url = await self.authorization_url({
                    "client_id": self.client_id, "redirect_uri": self.callback,
                    "response_type": "code", "scope": self.scope, "state": state,
                    "nonce": nonce, "code_challenge": challenge, "code_challenge_method": "S256",
                })
            except ProviderUnavailable:
                raise HTTPException(503, "Sign-in is temporarily unavailable. Try again shortly.") from None
            self.store.execute("DELETE FROM login_states WHERE expires<?", (time.time(),))
            # Keep each client's newest few unfinished sign-ins, so no client can fill the table for others.
            self.store.execute("DELETE FROM login_states WHERE client=? AND state_hash NOT IN "
                               "(SELECT state_hash FROM login_states WHERE client=? ORDER BY expires DESC LIMIT 4)", (client, client))
            self.store.execute("INSERT INTO login_states(state_hash, browser_hash, nonce, verifier, return_path, expires, client) "
                               "VALUES(?,?,?,?,?,?,?)", (self.state_hash(state), digest(browser), nonce, verifier, return_to, time.time() + 600, client))
            response.set_cookie(self.cookie, browser, max_age=600, httponly=True,
                                secure=not self.security.local, samesite="lax", path=self.cookie_path)
            return SignInRedirect(url=url)

        @router.get(f"/auth/{self.name}/callback")
        async def callback(request: Request, state: str = "", code: str = "", error: str = ""):
            if self.settings.cloudflare_access_login:
                self.security.require(request)
                response = RedirectResponse('/#tasks', status_code=303)
                response.delete_cookie(self.cookie, path=self.cookie_path)
                return response
            if not self.enabled():
                raise HTTPException(409, self.unconfigured)
            if len(state) > 200 or len(code) > 4096:
                raise HTTPException(400, "Invalid sign-in request.")
            browser = request.cookies.get(self.cookie, "")
            with self.store.connect() as conn:
                row = conn.execute("DELETE FROM login_states WHERE state_hash=? AND browser_hash=? AND expires>? RETURNING *",
                                   (self.state_hash(state), digest(browser), time.time())).fetchone()
            result = "cancelled" if error else "failed"
            return_hash = row["return_path"][1:] if row else "#tasks"
            failed = RedirectResponse(f"/?signin={result}{return_hash}", status_code=303)
            failed.delete_cookie(self.cookie, path=self.cookie_path)
            if not row or not browser or error or not code:
                return failed
            try:
                identity = await self.exchange(code, row["verifier"], row["nonce"])
            except (httpx.HTTPError, jwt.PyJWTError, ValueError, KeyError, TypeError, ProviderUnavailable):
                # Never echo provider errors, codes, tokens, or claims into the UI/logs.
                return failed
            role = self.security.google_role(identity['email'])
            try:
                self.store.identity({'method': self.name, 'identity': identity, 'role': role})
            except ValueError:
                # An email already held by another kind of account needs administrator review.
                return failed
            response = RedirectResponse(row["return_path"], status_code=303)
            response.delete_cookie(self.cookie, path=self.cookie_path)
            self.security.new_session(response, role, identity=identity, method=self.name)
            return response

        return router


class OidcSignIn(SignInFlow):
    name = "oidc"
    state_prefix = "oidc:"
    unconfigured = "Single sign-on is not configured yet."

    def __init__(self, settings, security, store):
        super().__init__(settings, security, store)
        self.metadata = None
        self.metadata_expire = 0
        self.last_metadata_fetch = float("-inf")
        self.metadata_lock = asyncio.Lock()

    @property
    def client_id(self):
        return self.settings.oidc_client_id

    @property
    def scope(self):
        return self.settings.oidc_scopes

    def enabled(self) -> bool:
        return self.settings.oidc_enabled()

    def usable_key(self, item) -> bool:
        # Many providers omit alg/use from published keys; never accept another type.
        return (item.get("kty") == "RSA" and item.get("use", "sig") == "sig" and item.get("alg", "RS256") == "RS256"
                and isinstance(item.get("kid"), str))

    async def provider(self):
        """The provider's verified discovery document, refreshed hourly."""
        async with self.metadata_lock:
            now = time.monotonic()
            if self.metadata is not None and now < self.metadata_expire:
                return self.metadata
            # A failing provider must not turn each sign-in attempt into a new request.
            if now - self.last_metadata_fetch < 10:
                raise ProviderUnavailable()
            self.last_metadata_fetch = now
            try:
                async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
                    response = await client.get(self.settings.oidc_discovery())
                    response.raise_for_status()
                if len(response.content) > 65536:
                    raise ValueError()
                value = response.json()
                endpoints = {
                    "authorization_endpoint": False, "token_endpoint": True, "jwks_uri": True,
                }
                if (not isinstance(value, dict) or value.get("issuer") != self.settings.oidc_issuer
                        or any(not isinstance(value.get(name), str)
                               or not oidc_endpoint_allowed(value[name], back_channel=back_channel)
                               for name, back_channel in endpoints.items())):
                    raise ValueError()
                methods = value.get("token_endpoint_auth_methods_supported", ["client_secret_basic"])
                if not isinstance(methods, list):
                    raise ValueError()
            except (httpx.HTTPError, ValueError, TypeError):
                raise ProviderUnavailable() from None
            # Basic is the OIDC default; use the form body only when it is the sole option.
            post = "client_secret_post" in methods and "client_secret_basic" not in methods
            self.metadata = {name: value[name] for name in endpoints} | {"client_secret_post": post}
            self.metadata_expire = now + 3600
            return self.metadata

    async def authorization_url(self, params):
        endpoint = (await self.provider())["authorization_endpoint"]
        return endpoint + ("&" if "?" in endpoint else "?") + urlencode(params)

    async def verify(self, token, nonce):
        if not isinstance(token, str) or len(token) > 16000:
            raise ValueError("Invalid ID token")
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise ValueError("Invalid signing algorithm")
        provider = await self.provider()
        client_id = self.settings.oidc_client_id
        claims = jwt.decode(token, await self.signing_key(header["kid"], provider["jwks_uri"]), algorithms=["RS256"],
                            audience=client_id, issuer=self.settings.oidc_issuer, leeway=30,
                            options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce", "email", "email_verified"]})
        if not isinstance(claims["nonce"], str) or not hmac.compare_digest(claims["nonce"], nonce):
            raise ValueError("Invalid nonce")
        if claims.get("azp", client_id) != client_id:
            raise ValueError("Invalid authorized party")
        if isinstance(claims["aud"], list) and len(claims["aud"]) > 1 and "azp" not in claims:
            raise ValueError("Missing authorized party")
        email, subject = claims["email"], claims["sub"]
        if (claims["email_verified"] is not True or not isinstance(email, str) or len(email) > 254
                or not EMAIL.fullmatch(email) or not isinstance(subject, str) or not subject or len(subject) > 255
                or email.lower().rpartition("@")[2] not in self.settings.google_domains()):
            raise ValueError("Not an allowed organization identity")
        email = email.lower()
        name = claims.get("name") or claims.get("preferred_username") or email
        return {"sub": subject, "issuer": self.settings.oidc_issuer, "email": email,
                "domain": email.rpartition("@")[2], "name": str(name)[:160]}

    async def exchange(self, code, verifier, nonce):
        provider = await self.provider()
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": self.callback,
                "code_verifier": verifier}
        credentials = {"client_id": self.settings.oidc_client_id, "client_secret": self.settings.oidc_client_secret}
        async with httpx.AsyncClient(timeout=20, follow_redirects=False) as client:
            if provider["client_secret_post"]:
                response = await client.post(provider["token_endpoint"], data=form | credentials)
            else:
                response = await client.post(provider["token_endpoint"], data=form, auth=httpx.BasicAuth(
                    *(_form_encode(credentials[name]) for name in ("client_id", "client_secret"))))
            response.raise_for_status()
            token = response.json().get("id_token")
        return await self.verify(token, nonce)


def _form_encode(value):
    # RFC 6749 2.3.1: Basic credentials are form-urlencoded before base64.
    return urlencode({"": value})[1:]

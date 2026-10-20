"""Google OpenID Connect for organization sign-in; no Google API access is retained."""
import hmac
from urllib.parse import urlencode

import httpx
import jwt

from .oidc import SignInFlow

AUTHORIZE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
KEYS_URL = "https://www.googleapis.com/oauth2/v3/certs"


class GoogleSignIn(SignInFlow):
    name = "google"
    unconfigured = "Google sign-in is not configured yet."

    @property
    def client_id(self):
        return self.settings.google_client_id

    def enabled(self) -> bool:
        return self.settings.google_enabled()

    async def authorization_url(self, params):
        domains = sorted(self.settings.google_domains())
        params = params | {"prompt": "select_account", "hd": domains[0] if len(domains) == 1 else "*"}
        return AUTHORIZE_URL + "?" + urlencode(params)

    async def verify(self, token, nonce):
        if not isinstance(token, str) or len(token) > 16000:
            raise ValueError("Invalid ID token")
        header = jwt.get_unverified_header(token)
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise ValueError("Invalid signing algorithm")
        claims = jwt.decode(token, await self.signing_key(header["kid"], KEYS_URL), algorithms=["RS256"],
                            audience=self.settings.google_client_id,
                            issuer=["https://accounts.google.com", "accounts.google.com"], leeway=30,
                            options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce", "email", "email_verified", "hd"]})
        if not isinstance(claims["nonce"], str) or not hmac.compare_digest(claims["nonce"], nonce):
            raise ValueError("Invalid nonce")
        if claims.get("azp", self.settings.google_client_id) != self.settings.google_client_id:
            raise ValueError("Invalid authorized party")
        if isinstance(claims["aud"], list) and len(claims["aud"]) > 1 and "azp" not in claims:
            raise ValueError("Missing authorized party")
        email, domain = claims["email"], claims["hd"]
        if (claims["email_verified"] is not True or not isinstance(email, str)
                or not isinstance(domain, str) or not claims["sub"]
                or domain.lower() not in self.settings.google_domains()
                or email.lower().rpartition("@")[2] != domain.lower()):
            raise ValueError("Not an allowed Google Workspace identity")
        return {"sub": claims["sub"], "email": email.lower(), "domain": domain.lower(),
                "name": str(claims.get("name", email))[:160]}

    async def exchange(self, code, verifier, nonce):
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(TOKEN_URL, data={
                "grant_type": "authorization_code", "code": code,
                "client_id": self.settings.google_client_id, "client_secret": self.settings.google_client_secret,
                "redirect_uri": self.callback, "code_verifier": verifier,
            })
            response.raise_for_status()
            token = response.json().get("id_token")
        return await self.verify(token, nonce)

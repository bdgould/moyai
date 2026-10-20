# Sign-in and user roles

Local trials use native accounts. Set `WORKSPACE_PASSWORD` before first start,
sign in as `admin`, and manage users in Settings. Passwords are hashed; role and
enabled-state changes invalidate prior authorization. The final enabled
administrator cannot be removed or demoted.

Existing-product mode uses the canonical Moyai identity directory, signing
secret, cookie and role records. It cannot bootstrap a replacement native admin.
Historical private ownership, personal credentials and Slack identity links keep
their original account IDs. Native projections are created only after canonical
authentication succeeds.

## Google

Keep existing Google OIDC settings and `PUBLIC_URL/auth/google/callback` registered
at the provider. Google verifies issuer, audience, signature, expiry, nonce,
verified email and allowed hosted domain. `GOOGLE_ADMIN_EMAILS` supplies defaults
for identities without an explicit saved role; stored role assignments win.
Use the canonical Users page for role changes, which checks optimistic revisions,
last-admin protection and the current actor within the write transaction.

`ALLOWED_EMAIL_DOMAINS` and `ADMIN_EMAILS` are the generic names for
`GOOGLE_ALLOWED_DOMAINS` and `GOOGLE_ADMIN_EMAILS`, and apply to every individual
sign-in method. Existing names keep working; when one source sets both, the
generic name wins.

## Generic OIDC

One standards-compliant OpenID Connect provider, such as Keycloak, Okta or
Entra ID, can sit beside Google. Register a confidential client with the
redirect URI `PUBLIC_URL/auth/oidc/callback`, then set `OIDC_ISSUER`,
`OIDC_CLIENT_ID` and `OIDC_CLIENT_SECRET`. `OIDC_DISPLAY_NAME` completes the
"Continue with …" button (default `SSO`) and `OIDC_SCOPES` defaults to
`openid email profile`. Endpoints come from
the issuer's discovery document, whose `issuer` must match `OIDC_ISSUER` exactly.

Moyai verifies the RS256 signature, issuer, audience, authorized party, expiry,
nonce and PKCE exchange, and requires `email_verified`. The email domain must be
in `ALLOWED_EMAIL_DOMAINS`; roles come from `ADMIN_EMAILS` and the Users page, not
provider groups. Accounts are keyed by issuer and subject, so changing
`OIDC_ISSUER` or `OIDC_CLIENT_ID` signs everyone out and a new issuer creates new
accounts. An email already held by a Google or Cloudflare account, or by another
OIDC subject, is refused until an administrator reviews it. A remote workspace
needs an HTTPS issuer.

### Local Keycloak

`deploy/keycloak` runs a development realm with synthetic users. Never expose it
beyond your machine. To try the whole application, `local-product.sh` runs the
[local existing-product rehearsal](pydantic-deployment.md#local-existing-product-rehearsal)
with Keycloak, PostgreSQL and an S3 server, after `uv sync --frozen` and `npm ci`:

```sh
cd deploy/keycloak
sh local-product.sh up    # services, canonical schema, native provisioning
sh local-product.sh dev   # serves http://127.0.0.1:8787 in the foreground
```

The first run writes `.local/local-product.env` (ignored by Git) from
`local-product.env.example`; change ports or add a LiteLLM gateway, model and
sandbox credentials there. Sign-in, roles and Settings work without them; agent
turns do not. `up` is safe to repeat, `down` keeps the database, and `reset`
deletes it. The S3 server keeps objects in memory only, so after restarting it
run `reset` before relying on stored files. Open `127.0.0.1`, not `localhost`:
the sign-in request must come from `MOYAI_PUBLIC_URL`.

For Keycloak alone, `MOYAI_KEYCLOAK_PORT=8080 docker compose up -d` in that
directory, then configure an existing-mode Moyai with:

```sh
OIDC_ISSUER=http://localhost:8080/realms/moyai
OIDC_CLIENT_ID=moyai
OIDC_CLIENT_SECRET=moyai-local-oidc-secret
ALLOWED_EMAIL_DOMAINS=example.test
ADMIN_EMAILS=admin@example.test
```

Sign in as `admin` / `moyai-local-admin` or `member` / `moyai-local-member`; the
`unverified` user demonstrates a refused unverified email. When Moyai itself runs
in a container on the same Compose network, also set
`OIDC_DISCOVERY_URL=http://keycloak:8080/realms/moyai/.well-known/openid-configuration`.
The issuer stays the browser-facing `localhost` URL while server calls use the
service name. Plain HTTP is accepted only for loopback, single-label and
`.internal` hosts. Set `MOYAI_TEST_KEYCLOAK_ISSUER` to the issuer to run
`tests/test_oidc_keycloak.py` against the realm.

## Cloudflare Access

If Cloudflare Access is enabled, retain its existing audience, team and identity
policy. With `CLOUDFLARE_ACCESS_LOGIN=true`, Moyai verifies the employee assertion
on each request and maps it to the canonical identity. A plain forwarded-email
header or machine token cannot establish an employee session. See
[the edge boundary](cloudflare-access.md).

After confirming a real administrator login, an operator may disable shared
password login with `PASSWORD_LOGIN_ENABLED=false`. Preserve `SESSION_SECRET`,
`ENCRYPTION_KEY` and existing data; do not rotate them as part of consolidation.
Shared passwords do not identify an individual for personal data access.

Authorization is checked at admission and again at model/tool boundaries.
Approval does not override revoked permissions. Personal memory and credentials
remain private to their owner even when a viewer is an administrator. UI tests
use synthetic accounts; validate the actual identity provider during deployment.

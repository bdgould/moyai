"""Account kinds that each identify one verified person.

A user id is '<kind>:<provider subject>', and a person's session method uses the
same name as their account kind. Slack accounts are accounting links, never
sign-in identities: callers that also accept them add 'slack' explicitly.
"""
import hashlib

# Ordered so generated SQL stays stable for exact-text query allowlists.
INDIVIDUAL_KINDS = ('google', 'cloudflare', 'oidc')
INDIVIDUAL_PREFIXES = tuple(kind + ':' for kind in INDIVIDUAL_KINDS)
# Fixed code constants, never request input, so inlining them into SQL is safe.
INDIVIDUAL_KINDS_SQL = '(' + ','.join(f"'{kind}'" for kind in INDIVIDUAL_KINDS) + ')'
# Kinds that sign in through Moyai's own authorization code flow and session.
# Cloudflare identities come from a verified Access assertion on every request.
CODE_FLOW_KINDS = ('google', 'oidc')


def oidc_user_id(issuer: str, subject: str) -> str:
    # Subjects are unique only within an issuer; a new issuer means new accounts.
    return 'oidc:' + hashlib.sha256((issuer + '\0' + subject).encode()).hexdigest()

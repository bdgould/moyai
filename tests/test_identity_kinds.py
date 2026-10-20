import ast
import hashlib
from pathlib import Path

from app.identity_kinds import INDIVIDUAL_KINDS, INDIVIDUAL_KINDS_SQL, INDIVIDUAL_PREFIXES, oidc_user_id

ROOT = Path(__file__).resolve().parents[1]


def test_individual_kinds_render_stable_sql_and_id_prefixes():
    # Exact-text query allowlists (native product_connection_store) depend on this spelling.
    assert INDIVIDUAL_KINDS_SQL == "('google','cloudflare','oidc')"
    assert INDIVIDUAL_PREFIXES == ('google:', 'cloudflare:', 'oidc:')
    assert 'google:subject'.startswith(INDIVIDUAL_PREFIXES)
    assert oidc_user_id('https://issuer.example', 'subject').startswith(INDIVIDUAL_PREFIXES)
    assert not 'shared:password:admin'.startswith(INDIVIDUAL_PREFIXES)
    assert not 'slack:T1:U1'.startswith(INDIVIDUAL_PREFIXES)


def test_oidc_account_ids_are_scoped_to_their_issuer():
    account = oidc_user_id('http://localhost:8080/realms/moyai', 'subject')
    assert account == 'oidc:' + hashlib.sha256(b'http://localhost:8080/realms/moyai\0subject').hexdigest()
    assert oidc_user_id('https://other.example/realms/moyai', 'subject') != account
    # The separator keeps issuer/subject boundaries from colliding.
    assert oidc_user_id('https://issuer.example/a', 'b') != oidc_user_id('https://issuer.example/', 'ab')


def spelled_out_kinds(path):
    """Collections or SQL that list individual kinds instead of the shared constant."""
    found = []
    tree = ast.parse(path.read_text())
    # Literal[...] annotations must spell their values for type checkers; they are schemas, not checks.
    annotations = {id(node.slice) for node in ast.walk(tree)
                   if isinstance(node, ast.Subscript) and getattr(node.value, 'id', None) == 'Literal'}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Set, ast.Tuple, ast.List)) and id(node) not in annotations:
            values = {item.value for item in node.elts if isinstance(item, ast.Constant)}
            if len(values & set(INDIVIDUAL_KINDS)) > 1 or len(values & set(INDIVIDUAL_PREFIXES)) > 1:
                found.append(node.lineno)
        elif (isinstance(node, ast.Constant) and isinstance(node.value, str)
              and sum(f"'{kind}'" in node.value for kind in INDIVIDUAL_KINDS) > 1 and 'kind' in node.value):
            found.append(node.lineno)
    return found


def test_individual_kind_checks_use_the_shared_constant():
    # A missed site fails silently for a new sign-in method, so keep one definition.
    offenders = [f'{path.relative_to(ROOT)}:{line}'
                 for base in ('app', 'native/src') for path in sorted((ROOT / base).rglob('*.py'))
                 if path.name != 'identity_kinds.py' for line in spelled_out_kinds(path)]
    assert offenders == []

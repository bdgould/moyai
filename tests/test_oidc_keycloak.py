"""Real OIDC sign-in through the local Keycloak in deploy/keycloak (synthetic realm only).

Opt in with MOYAI_TEST_KEYCLOAK_ISSUER, e.g. http://localhost:8080/realms/moyai.
"""
import html
import os
import re
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.config import Settings
from app.db import Store
from app.identity_kinds import oidc_user_id
from app.oidc import OidcSignIn
from app.security import Security

ORIGIN = 'http://127.0.0.1:8787'
ISSUER = os.environ.get('MOYAI_TEST_KEYCLOAK_ISSUER', '')
pytestmark = pytest.mark.skipif(not ISSUER, reason='Set MOYAI_TEST_KEYCLOAK_ISSUER to the local Keycloak realm.')


def sign_in(tmp_path, username, password, discovery_url=''):
    tmp_path.mkdir(exist_ok=True)
    settings = Settings(_env_file=None, data_dir=tmp_path, public_url=ORIGIN, oidc_issuer=ISSUER,
                        oidc_client_id='moyai', oidc_client_secret='moyai-local-oidc-secret',
                        oidc_discovery_url=discovery_url,
                        google_allowed_domains='example.test', google_admin_emails='admin@example.test')
    security, store = Security(settings), Store(tmp_path)
    app = FastAPI()
    app.include_router(OidcSignIn(settings, security, store).routes())
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as workspace, \
            httpx.Client(follow_redirects=False, timeout=20) as browser:
        start = workspace.post('/api/auth/oidc/start', json={'return_to': '/#spend'}, headers={'origin': ORIGIN})
        page = browser.get(start.json()['url'])
        action = html.unescape(re.search(r'<form[^>]+action="([^"]+)"', page.text)[1])
        # Keycloak marks its login cookies Secure even over http. Browsers still send
        # them to localhost, a secure context; httpx's cookie jar does not.
        cookies = '; '.join(value.split(';', 1)[0] for value in page.headers.get_list('set-cookie'))
        login = browser.post(action, data={'username': username, 'password': password, 'credentialId': ''},
                             headers={'cookie': cookies})
        assert login.status_code == 302 and login.headers['location'].startswith(ORIGIN + '/auth/oidc/callback?')
        query = {key: values[0] for key, values in parse_qs(urlsplit(login.headers['location']).query).items()}
        result = workspace.get('/auth/oidc/callback', params={'state': query['state'], 'code': query['code']})
        cookie = result.cookies.get('workspace_session')
        return result.headers['location'], security.signer.loads(cookie) if cookie else None, store


def test_keycloak_admin_and_member_sign_in_with_issuer_scoped_accounts(tmp_path):
    location, info, store = sign_in(tmp_path / 'admin', 'admin', 'moyai-local-admin')
    assert location == '/#spend' and info['method'] == 'oidc' and info['role'] == 'admin'
    assert info['identity']['issuer'] == ISSUER and info['identity']['email'] == 'admin@example.test'
    assert store.rows("SELECT id FROM users WHERE kind='oidc'") == [
        {'id': oidc_user_id(ISSUER, info['identity']['sub'])}]
    location, info, _ = sign_in(tmp_path / 'member', 'member', 'moyai-local-member')
    assert location == '/#spend' and info['role'] == 'member'


def test_keycloak_unverified_email_is_refused(tmp_path):
    location, info, store = sign_in(tmp_path, 'unverified', 'moyai-local-unverified')
    assert location == '/?signin=failed#spend' and info is None
    assert store.rows("SELECT id FROM users WHERE kind='oidc'") == []


def test_keycloak_back_channel_discovery_keeps_the_public_issuer(tmp_path):
    # 127.0.0.1 stands in for a Compose service name: endpoints follow this host.
    discovery = ISSUER.replace('localhost', '127.0.0.1', 1) + '/.well-known/openid-configuration'
    location, info, _ = sign_in(tmp_path, 'admin', 'moyai-local-admin', discovery_url=discovery)
    assert location == '/#spend' and info['identity']['issuer'] == ISSUER

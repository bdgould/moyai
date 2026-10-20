"""Google sign-in flow against a local Store; provider HTTP is a synthetic transport."""
import base64
import hashlib
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app import google_sso
from app.config import Settings
from app.db import Store
from app.google_sso import AUTHORIZE_URL, KEYS_URL, TOKEN_URL, GoogleSignIn
from app.oidc import sign_in_return_path
from app.security import Security

RUN = 'a' * 32
ORIGIN = 'http://127.0.0.1:8787'


@pytest.mark.parametrize('value', [
    '/#tasks', '/#connections', '/#runtime', '/#spend', '/#users', f'/#run={RUN}',
    f'/#run={RUN}&credential={"b" * 32}&generation=0', f'/#run={RUN}&credential={"b" * 32}&generation=12',
    f'/#run={RUN}&file=notes.md',
])
def test_sign_in_returns_to_known_app_destinations(value):
    assert sign_in_return_path(value) == value


@pytest.mark.parametrize('value', [
    '', '/', 'https://attacker.example/', '//attacker.example/#tasks', '/#tasks/extra', '/#TASKS',
    f'/#run={RUN[:-1]}', f'/#run={RUN}&credential={"b" * 32}&generation=01', '/#run=' + 'g' * 32,
    f'/#run={RUN}&file=', '/#tasks\n',
])
def test_sign_in_sends_unknown_destinations_to_tasks(value):
    assert sign_in_return_path(value) == '/#tasks'


@pytest.fixture
def google(tmp_path, monkeypatch):
    settings = Settings(_env_file=None, data_dir=tmp_path, public_url=ORIGIN,
                        google_client_id='synthetic-client', google_client_secret='synthetic-secret',
                        google_allowed_domains='example.test', google_admin_emails='admin@example.test')
    store = Store(tmp_path)
    security = Security(settings)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = {**jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True),
           'kid': 'local-key', 'alg': 'RS256', 'use': 'sig'}
    provider = SimpleNamespace(claims={}, token_requests=[])

    def respond(request):
        if request.url == KEYS_URL:
            return httpx.Response(200, json={'keys': [jwk]})
        assert request.method == 'POST' and request.url == TOKEN_URL
        provider.token_requests.append(parse_qs(request.content.decode()))
        token = jwt.encode(provider.claims, key, algorithm='RS256', headers={'kid': 'local-key'})
        return httpx.Response(200, json={'id_token': token})

    client = httpx.AsyncClient
    transport = httpx.MockTransport(respond)
    monkeypatch.setattr(google_sso.httpx, 'AsyncClient', lambda **kwargs: client(**kwargs, transport=transport))
    app = FastAPI()
    app.include_router(GoogleSignIn(settings, security, store).routes())
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as browser:
        yield SimpleNamespace(browser=browser, store=store, security=security, provider=provider)


def start(google, return_to='/#spend'):
    response = google.browser.post('/api/auth/google/start', json={'return_to': return_to},
                                   headers={'origin': ORIGIN})
    assert response.status_code == 200
    url = response.json()['url']
    assert url.startswith(AUTHORIZE_URL + '?')
    return {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}


def claims(google, expected_nonce, **changes):
    now = int(time.time())
    google.provider.claims = {
        'iss': 'https://accounts.google.com', 'aud': 'synthetic-client', 'sub': 'google-subject',
        'email': 'Admin@Example.test', 'email_verified': True, 'hd': 'example.test', 'name': 'Synthetic admin',
        'nonce': expected_nonce, 'iat': now, 'exp': now + 300, **changes,
    }


def session(google, response):
    cookie = response.cookies.get('workspace_session')
    return google.security.signer.loads(cookie) if cookie else None


def test_start_requests_pkce_code_flow_and_binds_state_to_this_browser(google):
    params = start(google)
    assert params['client_id'] == 'synthetic-client'
    assert params['redirect_uri'] == ORIGIN + '/auth/google/callback'
    assert params['response_type'] == 'code' and params['scope'] == 'openid email profile'
    assert params['code_challenge_method'] == 'S256' and params['prompt'] == 'select_account'
    assert params['hd'] == 'example.test'
    cookie = google.browser.cookies.jar
    assert [(item.name, item.path) for item in cookie] == [('google_login', '/auth/google')]
    rows = google.store.rows('SELECT state_hash,browser_hash,nonce,verifier,return_path FROM login_states')
    assert len(rows) == 1 and rows[0]['return_path'] == '/#spend'
    assert rows[0]['state_hash'] == hashlib.sha256(params['state'].encode()).hexdigest()
    assert rows[0]['nonce'] == params['nonce']
    challenge = base64.urlsafe_b64encode(hashlib.sha256(rows[0]['verifier'].encode()).digest()).rstrip(b'=').decode()
    assert params['code_challenge'] == challenge


def test_start_requires_the_workspace_origin(google):
    assert google.browser.post('/api/auth/google/start', json={}).status_code == 403


def test_callback_signs_in_a_verified_workspace_identity_once(google):
    params = start(google)
    claims(google, params['nonce'])
    response = google.browser.get('/auth/google/callback', params={'state': params['state'], 'code': 'one-time'})
    assert response.status_code == 303 and response.headers['location'] == '/#spend'
    info = session(google, response)
    assert info['method'] == 'google' and info['role'] == 'admin' and info['client_id'] == 'synthetic-client'
    assert info['identity'] == {'sub': 'google-subject', 'email': 'admin@example.test',
                                'domain': 'example.test', 'name': 'Synthetic admin'}
    [token_request] = google.provider.token_requests
    assert token_request['code'] == ['one-time'] and token_request['redirect_uri'] == [ORIGIN + '/auth/google/callback']
    assert google.store.rows("SELECT id,kind,email FROM users WHERE kind='google'") == [
        {'id': 'google:google-subject', 'kind': 'google', 'email': 'admin@example.test'}]
    replay = google.browser.get('/auth/google/callback', params={'state': params['state'], 'code': 'one-time'})
    assert replay.headers['location'] == '/?signin=failed#tasks' and session(google, replay) is None


def test_callback_rejects_another_browser_and_reports_cancellation(google):
    params = start(google)
    claims(google, params['nonce'])
    google.browser.cookies.clear()
    stolen = google.browser.get('/auth/google/callback', params={'state': params['state'], 'code': 'one-time'})
    assert stolen.headers['location'] == '/?signin=failed#tasks' and session(google, stolen) is None
    params = start(google)
    cancelled = google.browser.get('/auth/google/callback', params={'state': params['state'], 'error': 'access_denied'})
    assert cancelled.headers['location'] == '/?signin=cancelled#spend' and session(google, cancelled) is None
    assert google.provider.token_requests == []


@pytest.mark.parametrize('changes', [
    {'hd': 'other.test', 'email': 'admin@other.test'}, {'email_verified': False}, {'aud': 'other-client'},
    {'iss': 'https://issuer.example'}, {'nonce': 'replayed-nonce'}, {'exp': int(time.time()) - 300},
])
def test_callback_rejects_unverified_or_foreign_identities(google, changes):
    params = start(google)
    claims(google, params['nonce'], **changes)
    response = google.browser.get('/auth/google/callback', params={'state': params['state'], 'code': 'one-time'})
    assert response.headers['location'] == '/?signin=failed#spend' and session(google, response) is None
    assert google.store.rows("SELECT id FROM users WHERE kind='google'") == []

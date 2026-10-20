"""Generic OIDC sign-in against a local Store; the provider is a synthetic transport."""
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
from pydantic import ValidationError

from app import oidc
from app.config import Settings, oidc_endpoint_allowed
from app.db import Store
from app.identity_kinds import oidc_user_id
from app.oidc import OidcSignIn
from app.security import Security

ORIGIN = 'http://127.0.0.1:8787'
ISSUER = 'https://idp.example.test/realms/moyai'
CALLBACK = ORIGIN + '/auth/oidc/callback'


def oidc_settings(tmp_path, **changes):
    values = dict(_env_file=None, data_dir=tmp_path, public_url=ORIGIN, oidc_issuer=ISSUER,
                  oidc_client_id='moyai', oidc_client_secret='synthetic:secret',
                  google_allowed_domains='example.test', google_admin_emails='admin@example.test')
    return Settings(**(values | changes))


@pytest.fixture
def provider(tmp_path, monkeypatch):
    settings = oidc_settings(tmp_path)
    store = Store(tmp_path)
    security = Security(settings)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Keycloak and others omit alg/use on some keys; an encryption key must never sign.
    keys = [{**jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True), 'kid': 'local-key'},
            {**jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True), 'kid': 'enc-key', 'use': 'enc'}]
    state = SimpleNamespace(claims={}, token_requests=[], discovery_requests=0, signer=key, metadata={
        'issuer': ISSUER, 'authorization_endpoint': ISSUER + '/protocol/openid-connect/auth',
        'token_endpoint': ISSUER + '/protocol/openid-connect/token', 'jwks_uri': ISSUER + '/protocol/openid-connect/certs',
        'token_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post'],
    })

    def respond(request):
        url = str(request.url)
        if url == ISSUER + '/.well-known/openid-configuration':
            state.discovery_requests += 1
            return httpx.Response(200, json=state.metadata)
        if url == state.metadata['jwks_uri']:
            return httpx.Response(200, json={'keys': keys})
        assert request.method == 'POST' and url == state.metadata['token_endpoint']
        state.token_requests.append(request)
        token = jwt.encode(state.claims, state.signer, algorithm='RS256', headers={'kid': state.kid})
        return httpx.Response(200, json={'id_token': token})

    client = httpx.AsyncClient
    transport = httpx.MockTransport(respond)
    monkeypatch.setattr(oidc.httpx, 'AsyncClient', lambda **kwargs: client(**kwargs, transport=transport))
    flow = OidcSignIn(settings, security, store)
    app = FastAPI()
    app.include_router(flow.routes())
    state.kid = 'local-key'
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as browser:
        yield SimpleNamespace(browser=browser, store=store, security=security, flow=flow, state=state)


def start(provider, return_to='/#spend'):
    response = provider.browser.post('/api/auth/oidc/start', json={'return_to': return_to}, headers={'origin': ORIGIN})
    assert response.status_code == 200, response.text
    url = response.json()['url']
    assert url.startswith(provider.state.metadata['authorization_endpoint'] + '?')
    return {key: values[0] for key, values in parse_qs(urlsplit(url).query).items()}


def claims(provider, expected_nonce, **changes):
    now = int(time.time())
    provider.state.claims = {
        'iss': ISSUER, 'aud': 'moyai', 'azp': 'moyai', 'sub': 'subject-1', 'email': 'Admin@Example.test',
        'email_verified': True, 'preferred_username': 'admin', 'nonce': expected_nonce,
        'iat': now, 'exp': now + 300, **changes,
    }
    # None removes a claim, e.g. azp for a multi-audience token.
    provider.state.claims = {key: value for key, value in provider.state.claims.items() if value is not None}


def sign_in(provider, **changes):
    params = start(provider)
    claims(provider, params['nonce'], **changes)
    return provider.browser.get('/auth/oidc/callback', params={'state': params['state'], 'code': 'one-time'})


def session(provider, response):
    cookie = response.cookies.get('workspace_session')
    return provider.security.signer.loads(cookie) if cookie else None


def test_start_uses_discovered_endpoint_and_provider_scoped_state(provider):
    params = start(provider)
    assert params['client_id'] == 'moyai' and params['redirect_uri'] == CALLBACK
    assert params['response_type'] == 'code' and params['scope'] == 'openid email profile'
    assert params['code_challenge_method'] == 'S256' and 'hd' not in params and 'prompt' not in params
    assert [(item.name, item.path) for item in provider.browser.cookies.jar] == [('oidc_login', '/auth/oidc')]
    [row] = provider.store.rows('SELECT state_hash,nonce,verifier FROM login_states')
    # Bound to this provider: an OIDC state never matches a Google callback lookup.
    assert row['state_hash'] == hashlib.sha256(('oidc:' + params['state']).encode()).hexdigest()
    assert row['state_hash'] != hashlib.sha256(params['state'].encode()).hexdigest()
    challenge = base64.urlsafe_b64encode(hashlib.sha256(row['verifier'].encode()).digest()).rstrip(b'=').decode()
    assert params['code_challenge'] == challenge and row['nonce'] == params['nonce']
    start(provider)
    assert provider.state.discovery_requests == 1


def test_callback_signs_in_an_issuer_scoped_account(provider):
    response = sign_in(provider)
    assert response.status_code == 303 and response.headers['location'] == '/#spend'
    info = session(provider, response)
    assert info['method'] == 'oidc' and info['role'] == 'admin' and info['client_id'] == 'moyai'
    assert info['identity'] == {'sub': 'subject-1', 'issuer': ISSUER, 'email': 'admin@example.test',
                                'domain': 'example.test', 'name': 'admin'}
    assert provider.security.session_info(SimpleNamespace(cookies=response.cookies))['role'] == 'admin'
    [request] = provider.state.token_requests
    form = parse_qs(request.content.decode())
    assert form['code'] == ['one-time'] and form['redirect_uri'] == [CALLBACK] and 'client_secret' not in form
    secret = base64.b64encode(b'moyai:synthetic%3Asecret').decode()
    assert request.headers['authorization'] == 'Basic ' + secret
    assert provider.store.rows("SELECT id,kind,email FROM users WHERE kind='oidc'") == [
        {'id': oidc_user_id(ISSUER, 'subject-1'), 'kind': 'oidc', 'email': 'admin@example.test'}]


def test_token_request_uses_the_form_body_when_basic_is_unsupported(provider):
    provider.state.metadata['token_endpoint_auth_methods_supported'] = ['client_secret_post']
    assert sign_in(provider).headers['location'] == '/#spend'
    form = parse_qs(provider.state.token_requests[0].content.decode())
    assert form['client_id'] == ['moyai'] and form['client_secret'] == ['synthetic:secret']
    assert 'authorization' not in provider.state.token_requests[0].headers


@pytest.mark.parametrize('changes', [
    {'email_verified': False}, {'email': 'admin@other.test'}, {'aud': 'other-client'}, {'azp': 'other-client'},
    {'aud': ['moyai', 'other-client'], 'azp': None}, {'iss': 'https://idp.example.test/realms/other'},
    {'nonce': 'replayed-nonce'}, {'exp': int(time.time()) - 300}, {'email': 'not-an-email'}, {'sub': ''},
])
def test_callback_rejects_unverified_or_foreign_identities(provider, changes):
    response = sign_in(provider, **changes)
    assert response.headers['location'] == '/?signin=failed#spend' and session(provider, response) is None
    assert provider.store.rows("SELECT id FROM users WHERE kind='oidc'") == []


def test_callback_rejects_tokens_from_another_key_or_an_encryption_key(provider):
    provider.state.signer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    assert sign_in(provider).headers['location'] == '/?signin=failed#spend'
    provider.state.kid = 'enc-key'
    assert sign_in(provider).headers['location'] == '/?signin=failed#spend'


def test_a_google_state_never_completes_at_the_oidc_callback(provider):
    browser = 'synthetic-browser'
    provider.store.execute(
        'INSERT INTO login_states(state_hash,browser_hash,nonce,verifier,return_path,expires,client) VALUES(?,?,?,?,?,?,?)',
        (hashlib.sha256(b'google-state').hexdigest(), hashlib.sha256(browser.encode()).hexdigest(),
         'nonce', 'verifier', '/#spend', time.time() + 600, 'client'))
    provider.browser.cookies.set('oidc_login', browser, path='/auth/oidc')
    response = provider.browser.get('/auth/oidc/callback', params={'state': 'google-state', 'code': 'one-time'})
    assert response.headers['location'] == '/?signin=failed#tasks' and provider.state.token_requests == []


def test_email_held_by_another_account_kind_is_refused_both_ways(provider, tmp_path):
    stamp = '2026-10-20T00:00:00+00:00'
    provider.store.execute("INSERT INTO users(id,kind,email,name,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                           ('google:existing', 'google', 'admin@example.test', 'Existing', stamp, stamp))
    response = sign_in(provider)
    assert response.headers['location'] == '/?signin=failed#spend' and session(provider, response) is None
    assert provider.store.rows("SELECT id FROM users WHERE kind='oidc'") == []
    # The reverse: a Google sign-in cannot take an email an OIDC account holds.
    identity = {'sub': 'subject-2', 'issuer': ISSUER, 'email': 'member@example.test', 'domain': 'example.test'}
    account = provider.store.identity({'method': 'oidc', 'identity': identity, 'role': 'member'})
    assert account == oidc_user_id(ISSUER, 'subject-2')
    google = {'sub': 'google-2', 'email': 'member@example.test', 'domain': 'example.test'}
    with pytest.raises(ValueError, match='administrator review'):
        provider.store.identity({'method': 'google', 'identity': google, 'role': 'member'})
    # A second subject with the same email (a reassigned IdP account) is reviewed too.
    with pytest.raises(ValueError, match='administrator review'):
        provider.store.identity({'method': 'oidc', 'identity': identity | {'sub': 'subject-3'}, 'role': 'member'})
    # Repeated sign-in by the same account still refreshes it.
    assert provider.store.identity({'method': 'oidc', 'identity': identity | {'name': 'Renamed'}, 'role': 'member'}) == account


def test_unavailable_discovery_fails_closed_without_storing_state(provider):
    provider.state.metadata['issuer'] = 'https://idp.example.test/realms/impostor'
    response = provider.browser.post('/api/auth/oidc/start', json={}, headers={'origin': ORIGIN})
    assert response.status_code == 503 and provider.store.rows('SELECT 1 FROM login_states') == []
    # Failed lookups are not retried on every attempt.
    provider.browser.post('/api/auth/oidc/start', json={}, headers={'origin': ORIGIN})
    assert provider.state.discovery_requests == 1


@pytest.mark.parametrize('field,url', [
    ('authorization_endpoint', 'http://idp.example.test/auth'), ('authorization_endpoint', 'http://keycloak:8080/auth'),
    ('token_endpoint', 'http://idp.example.test/token'), ('jwks_uri', 'https://user:pass@idp.example.test/certs'),
])
def test_discovered_endpoints_must_be_https_or_local_development(provider, field, url):
    provider.state.metadata[field] = url
    assert provider.browser.post('/api/auth/oidc/start', json={}, headers={'origin': ORIGIN}).status_code == 503


def test_session_ends_when_issuer_or_client_changes(provider, tmp_path):
    response = sign_in(provider)
    request = SimpleNamespace(cookies=response.cookies)
    assert provider.security.session_info(request)['method'] == 'oidc'
    for change in ({'oidc_issuer': 'https://idp.example.test/realms/next'}, {'oidc_client_id': 'replacement'},
                   {'oidc_issuer': '', 'oidc_client_id': '', 'oidc_client_secret': ''}):
        provider.security.settings = oidc_settings(tmp_path, **change)
        assert provider.security.session_info(request) is None


def test_unconfigured_provider_and_access_login_keep_their_existing_behavior(tmp_path):
    settings = Settings(_env_file=None, data_dir=tmp_path, public_url=ORIGIN)
    app = FastAPI()
    app.include_router(OidcSignIn(settings, Security(settings), Store(tmp_path)).routes())
    with TestClient(app, base_url=ORIGIN) as browser:
        assert browser.post('/api/auth/oidc/start', json={}, headers={'origin': ORIGIN}).status_code == 409
        assert browser.get('/auth/oidc/callback', params={'state': 's', 'code': 'c'}).status_code == 409


@pytest.mark.parametrize('url,back_channel,allowed', [
    ('https://idp.example.test/realms/moyai', False, True),
    ('http://localhost:8080/realms/moyai', False, True),
    ('http://127.0.0.1:8080/realms/moyai', False, True),
    ('http://idp.example.test/realms/moyai', False, False),
    ('http://keycloak:8080/realms/moyai', False, False),
    ('http://keycloak:8080/realms/moyai', True, True),
    ('http://host.containers.internal:8080/realms/moyai', True, True),
    ('http://idp.example.test/realms/moyai', True, False),
    ('https://user:pass@idp.example.test/', False, False),
    ('https://idp.example.test/#fragment', False, False),
    ('ftp://idp.example.test/', True, False),
])
def test_endpoint_rule_allows_plain_http_only_for_local_development(url, back_channel, allowed):
    assert oidc_endpoint_allowed(url, back_channel=back_channel) is allowed


@pytest.mark.parametrize('changes,message', [
    ({'oidc_client_secret': ''}, 'together'),
    ({'oidc_issuer': 'http://idp.example.test/realms/moyai'}, 'OIDC_ISSUER'),
    ({'oidc_issuer': ISSUER + '?tenant=1'}, 'OIDC_ISSUER'),
    ({'oidc_discovery_url': 'http://idp.example.test/.well-known/openid-configuration'}, 'OIDC_DISCOVERY_URL'),
    ({'oidc_scopes': 'email profile'}, 'OIDC_SCOPES'),
    ({'oidc_scopes': 'openid  email'}, 'OIDC_SCOPES'),
    ({'oidc_display_name': 'Sign\nin'}, 'line breaks'),
])
def test_settings_reject_incomplete_or_unsafe_oidc_configuration(tmp_path, changes, message):
    with pytest.raises(ValidationError, match=message):
        oidc_settings(tmp_path, **changes)


def test_settings_enable_oidc_only_when_complete_and_derive_discovery(tmp_path):
    settings = oidc_settings(tmp_path)
    assert settings.oidc_enabled() and settings.person_login_enabled()
    assert settings.oidc_discovery() == ISSUER + '/.well-known/openid-configuration'
    local = oidc_settings(tmp_path, oidc_issuer='http://localhost:18080/realms/moyai',
                          oidc_discovery_url='http://keycloak:8080/realms/moyai/.well-known/openid-configuration')
    assert local.oidc_discovery() == 'http://keycloak:8080/realms/moyai/.well-known/openid-configuration'
    assert not Settings(_env_file=None, data_dir=tmp_path).oidc_enabled()


def test_security_requires_organization_settings_and_https_for_remote_workspaces(tmp_path):
    with pytest.raises(ValueError, match='ALLOWED_EMAIL_DOMAINS'):
        Security(oidc_settings(tmp_path, google_admin_emails=''))
    with pytest.raises(ValueError, match='ALLOWED_EMAIL_DOMAINS'):
        Security(oidc_settings(tmp_path, google_admin_emails='admin@other.test'))
    with pytest.raises(ValueError, match='HTTPS'):
        Security(oidc_settings(tmp_path, public_url='https://moyai.example.test',
                               oidc_issuer='http://localhost:18080/realms/moyai'))
    assert Security(oidc_settings(tmp_path, public_url='https://moyai.example.test')).settings.oidc_enabled()

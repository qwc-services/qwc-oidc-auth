import os
import logging
from flask import (
    Flask, url_for, jsonify, request, session, redirect, make_response
)
from flask.logging import default_handler
from authlib.integrations.flask_client import OAuth
from flask_jwt_extended import (
    jwt_required, create_access_token, get_jwt_identity,
    set_access_cookies, unset_jwt_cookies
)
from qwc_services_core.auth import auth_manager, GroupNameMapper
from qwc_services_core.tenant_handler import (
    TenantHandler, TenantPrefixMiddleware, TenantSessionInterface
)
from qwc_services_core.runtime_config import RuntimeConfig


# Enable debug logging for libs
root = logging.getLogger()
root.addHandler(default_handler)
root.setLevel(logging.DEBUG)

app = Flask(__name__)

app.config['JWT_COOKIE_SECURE'] = os.environ.get(
    'JWT_COOKIE_SECURE', 'False').lower() == 'true'
app.config['JWT_COOKIE_SAMESITE'] = os.environ.get(
    'JWT_COOKIE_SAMESITE', 'Lax')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = int(os.environ.get(
    'JWT_ACCESS_TOKEN_EXPIRES', 12*3600))
app.config['SESSION_COOKIE_SECURE'] = app.config['JWT_COOKIE_SECURE']
app.config['SESSION_COOKIE_SAMESITE'] = app.config['JWT_COOKIE_SAMESITE']

jwt = auth_manager(app)
app.secret_key = app.config['JWT_SECRET_KEY']

tenant_handler = TenantHandler(app.logger)
config_handler = RuntimeConfig("oidcAuth", app.logger)

app.wsgi_app = TenantPrefixMiddleware(app.wsgi_app)
app.session_interface = TenantSessionInterface(os.environ)

oauth = OAuth(app)


def auth_service_handler():
    """Get or create a OAuth client for a tenant."""
    tenant = tenant_handler.tenant()
    handler = tenant_handler.handler('oidcAuth', 'oidc', tenant)
    if handler is None:
        config = config_handler.tenant_config(tenant)
        client_id = config.get('client_id', os.getenv('CLIENT_ID'))
        client_secret = config.get('client_secret', os.getenv('CLIENT_SECRET'))
        issuer_url = config.get('issuer_url', os.getenv('ISSUER_URL'))
        # e.g. https://accounts.google.com/.well-known/openid-configuration
        metadata_url = f"{issuer_url}/.well-known/openid-configuration"
        openid_scopes = config.get('openid_scopes', 'openid email profile')
        oauth.register(
            name=tenant,
            client_id=client_id,
            client_secret=client_secret,
            server_metadata_url=metadata_url,
            client_kwargs={
                'scope': openid_scopes
            }
            # authorize_params={'resource': 'urn:microsoft:userinfo'}
        )
        oidc = oauth.create_client(tenant)
        handler = tenant_handler.register_handler('oidc', tenant, oidc)
    return handler


def tenant_base():
    """base path for tentant"""
    # Updates config['JWT_ACCESS_COOKIE_PATH'] as side effect
    prefix = app.session_interface.get_cookie_path(app)
    return prefix.rstrip('/') + '/'


@app.route('/login')
def login():
    config = config_handler.tenant_config(tenant_handler.tenant())
    oidc = auth_service_handler()
    target_url = request.args.get('url', tenant_base())
    # We store the target url in the session.
    # Instead we could pass it as OAuth state
    # (state=target_url in authorize_redirect)
    # Then we should only pass the path as state for security reasons
    session['target_url'] = target_url
    app.logger.debug("Request headers:")
    app.logger.debug(request.headers)
    redirect_uri = config.get(
        'redirect_uri', url_for('callback', _external=True))
    app.logger.info(f"redirect_uri: {redirect_uri}")
    return oidc.authorize_redirect(redirect_uri)


@app.route('/callback')
def callback():
    oidc = auth_service_handler()
    token = oidc.authorize_access_token()
    userinfo = token.get('userinfo')
    # {
    #   "userinfo": {
    #     "at_hash": "3lI-Bs8Ym0SmXLpEM6Idqw",
    #     "aud": "cf5ec860-ced2-013a-f0b6-0a510fd395c5120854",
    #     "email": "me@example.com",
    #     "exp": 1662635070,
    #     "family_name": "Doe",
    #     "given_name": "John",
    #     "iat": 1662627870,
    #     "iss": "https://qwc2-dev.onelogin.com/oidc/2",
    #     "name": "John Doe",
    #     "nonce": "2pqk3WdRWhMdIOhaNw1o",
    #     "preferred_username": "me@example.com",
    #     "sid": "9587e574-0a0b-4d2d-b5ba-ed539d5dc81c",
    #     "sub": "37078758",
    #     "updated_at": 1662627811
    #   }
    # }
    #
    # eduid.ch:
    # {
    #   "userinfo": {
    #     "at_hash": "bcCpXNOtQPCKIolbBKVrWg",
    #     "sub": "AW3CJEEOCDQSNR4GLF7CGRINMFPZVTOW",
    #     "swissEduPersonUniqueID": "12345678901@eduid.ch",
    #     "email_verified": true,
    #     "iss": "https://login.eduid.ch/",
    #     "given_name": "John",
    #     "nonce": "rseXKUJ3MaJDe7rmm1lL",
    #     "aud": "<client_id>",
    #     "acr": "password",
    #     "auth_time": 1664372815,
    #     "name": "John Doe",
    #     "exp": 1664387215,
    #     "iat": 1664372815,
    #     "family_name": "Doe",
    #     "email": "me@example.com"
    #   }
    # }
    #
    # ADFS:
    # {
    #   "userinfo": {
    #     "appid": "c8699d44-facf-4329-b2c2-ff1f8c385beb",
    #     "apptype": "Confidential",
    #     "aud": "c8699d44-facf-4329-b2c2-ff1f8c385beb",
    #     "auth_time": 1662626992,
    #     "authmethod": "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/windows",
    #     "exp": 1662630592,
    #     "group": ["User", Admin"],
    #     "iat": 1662626992,
    #     "iss": "https://example.com/adfs",
    #     "nbf": 1662626992,
    #     "nonce": "Ntyr78eXokrvA82BDKsV",
    #     "pwd_exp": "1733602",
    #     "pwd_url": "https://example.com/adfs/portal/updatepassword/",
    #     "scp": "profile email openid"
    #     "sid": "S-1-5-21-111884681-232138482-1136263860-54956",
    #     "sub": "E8uMvTw4EzVtNJjAGGkn/HLxB5lsxPvUz9N8v2ONw6w=",
    #     "unique_name": "DOMAIN\\USER",
    #     "upn": "john.doe@example.com",
    #     "ver": "1.0",
    #   }
    # }
    app.logger.info(userinfo)
    config = config_handler.tenant_config(tenant_handler.tenant())
    groupinfo = config.get('groupinfo', 'group')
    mapper = GroupNameMapper()

    if config.get('username'):
        username = userinfo.get(config.get('username'))
    else:
        username = userinfo.get('preferred_username',
                                userinfo.get('upn', userinfo.get('email')))
    groups = userinfo.get(groupinfo, [])
    if isinstance(groups, str):
        groups = [groups]
    # Add group for all authenticated users
    groups.append('verified')
    # Apply group name mappings
    groups = [
        mapper.mapped_group(g)
        for g in groups
    ]
    identity = {'username': username, 'groups': groups}
    app.logger.info(identity)
    # Create the tokens we will be sending back to the user
    access_token = create_access_token(identity)
    # refresh_token = create_refresh_token(identity)

    base_url = tenant_base()
    target_url = session.pop('target_url', base_url)

    resp = make_response(redirect(target_url))
    set_access_cookies(resp, access_token)
    return resp


@app.route('/logout', methods=['GET', 'POST'])
@jwt_required(optional=True)
def logout():
    target_url = request.args.get('url', tenant_base())
    resp = make_response(redirect(target_url))
    unset_jwt_cookies(resp)
    return resp


@app.route('/')
@jwt_required(optional=True)
def index():
    identity = get_jwt_identity()
    return jsonify(identity)


@app.route("/ready")
def ready():
    """ readyness probe endpoint """
    return jsonify({"status": "OK"})


@app.route("/healthz")
def healthz():
    """ liveness probe endpoint """
    return jsonify({"status": "OK"})


if __name__ == '__main__':
    print("Starting OIDC Auth service...")
    app.logger.setLevel(logging.DEBUG)
    app.run(host='localhost', port=5017, debug=True)

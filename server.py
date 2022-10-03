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
from qwc_services_core.auth import auth_manager


# Enable debug logging for libs
root = logging.getLogger()
root.addHandler(default_handler)
root.setLevel(logging.DEBUG)

app = Flask(__name__)

app.config['JWT_COOKIE_SECURE'] = bool(os.environ.get(
    'JWT_COOKIE_SECURE', False))
app.config['JWT_COOKIE_SAMESITE'] = os.environ.get(
    'JWT_COOKIE_SAMESITE', 'Lax')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = int(os.environ.get(
    'JWT_ACCESS_TOKEN_EXPIRES', 12*3600))

jwt = auth_manager(app)
app.secret_key = app.config['JWT_SECRET_KEY']

app.config['OIDC_CLIENT_ID'] = os.getenv('CLIENT_ID')
app.config['OIDC_CLIENT_SECRET'] = os.getenv('CLIENT_SECRET')
# e.g. https://accounts.google.com/.well-known/openid-configuration
OPENID_METADATA_URL = os.getenv('ISSUER_URL') + \
                     '/.well-known/openid-configuration'
OPENID_SCOPES = os.getenv('OPENID_SCOPES', 'openid email profile')

oauth = OAuth(app)
oauth.register(
    name='oidc',
    server_metadata_url=OPENID_METADATA_URL,
    client_kwargs={
        'scope': OPENID_SCOPES
    }
    # authorize_params={'resource': 'urn:microsoft:userinfo'}
)
oidc = oauth.create_client('oidc')


@app.route('/login')
def login():
    target_url = request.args.get('url', '/')
    session['target_url'] = target_url
    app.logger.debug("Request headers:")
    app.logger.debug(request.headers)
    redirect_uri = url_for('callback', _external=True)
    app.logger.info(f"redirect_uri: {redirect_uri}")
    return oidc.authorize_redirect(redirect_uri)


@app.route('/callback')
def callback():
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
    #     "aud": "c8699d44-facf-4329-b2c2-ff1f8c385beb",
    #     "auth_time": 1662626992,
    #     "exp": 1662630592,
    #     "iat": 1662626992,
    #     "iss": "https://example.com/adfs",
    #     "nbf": 1662626992,
    #     "nonce": "Ntyr78eXokrvA82BDKsV",
    #     "pwd_exp": "1733602",
    #     "pwd_url": "https://example.com/adfs/portal/updatepassword/",
    #     "sid": "S-1-5-21-111884681-232138482-1136263860-54956",
    #     "sub": "E8uMvTw4EzVtNJjAGGkn/HLxB5lsxPvUz9N8v2ONw6w=",
    #     "unique_name": "DOMAIN\\USER",
    #     "upn": "john.doe@example.com"
    #   }
    # }
    app.logger.info(userinfo)
    username = userinfo.get('preferred_username',
                            userinfo.get('upn', userinfo.get('email')))
    groups = []
    identity = {'username': username, 'groups': groups}
    # Create the tokens we will be sending back to the user
    access_token = create_access_token(identity)
    # refresh_token = create_refresh_token(identity)

    target_url = session.pop('target_url', '/')

    resp = make_response(redirect(target_url))
    set_access_cookies(resp, access_token)
    return resp


@app.route('/logout', methods=['GET', 'POST'])
@jwt_required(optional=True)
def logout():
    target_url = request.args.get('url', '/')
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

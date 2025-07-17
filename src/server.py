import os
import logging
import requests

from authlib.oauth2.rfc6749 import TokenValidator
from authlib.oauth2.rfc6750 import errors
from authlib.integrations.flask_oauth2 import ResourceProtector
from authlib.jose import jwk, jwt as auth_jwt, JWTClaims
from flask import Flask, jsonify
from flask.logging import default_handler
from flask_jwt_extended import jwt_required, get_jwt_identity

from qwc_services_core.auth import auth_manager
from qwc_services_core.tenant_handler import (
    TenantHandler, TenantPrefixMiddleware, TenantSessionInterface
)

from oidc_auth import OIDCAuth

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
app.wsgi_app = TenantPrefixMiddleware(app.wsgi_app)
app.session_interface = TenantSessionInterface()

def auth_service_handler():
    """Get or create a OAuth client for a tenant."""
    tenant = tenant_handler.tenant()
    handler = tenant_handler.handler('oidcAuth', 'oidc', tenant)
    if handler is None:
        handler = tenant_handler.register_handler('oidc', tenant, OIDCAuth(tenant, app))
    return handler

class APITokenValidator(TokenValidator):
    def authenticate_token(self, token_string):
        config = auth_service_handler().config()
        authorized_api_token = config.get('authorized_api_token', None)
        if authorized_api_token:
            for api in authorized_api_token:
                def load_key(header, payload):
                    jwk_set = requests.get(api["keys_url"]).json()
                    app.logger.debug(f"header = {header}")
                    try:
                        return jwk.loads(jwk_set, header.get('kid'))
                    except ValueError:
                        app.logger.debug("Invalid JSON Web Key Set")
                        return ""
                try:
                    claims_options = api["claims_options"]
                    claims_options["exp"] = {
                        "validate": JWTClaims.validate_exp,
                    }
                    app.logger.debug(f"{claims_options=}")
                    token = auth_jwt.decode(token_string, load_key, claims_options=claims_options)
                    token.validate()
                    token["active"] = True
                    app.logger.debug(f"{token=}")
                    return token

                except Exception as e:
                    app.logger.debug(f"Decode token error : {e}")

        return None

    def validate_token(self, token, scopes, request):
        if not token:
            raise errors.InvalidTokenError()
        token.validate()


require_oauth = ResourceProtector()
require_oauth.register_token_validator(APITokenValidator())


@app.route('/login')
def login():
    return auth_service_handler().login()


@app.route('/callback')
def callback():
    return auth_service_handler().callback()


@app.route('/tokenlogin')
@require_oauth()
def token_login():
    return auth_service_handler().token_login()


@app.route('/logout', methods=['GET', 'POST'])
@jwt_required(optional=True)
def logout():
    app.logger.debug("Logout")
    return auth_service_handler().logout()

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

import datetime
import flask
import logging
from flask import Flask, jsonify

from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession

app = Flask(__name__)
# See https://flask.palletsprojects.com/en/2.0.x/config/
app.config.update({'OIDC_REDIRECT_URI': 'http://localhost:5000/redirect_uri',
                   'SECRET_KEY': 'dev_key',  # make sure to change this!!
                   'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=7).total_seconds(),
                   'DEBUG': True})

ISSUER = 'https://provider.example.com'
CLIENT = 'client@provider'
PROVIDER_NAME = 'provider'
PROVIDER_CONFIG = ProviderConfiguration(
    issuer=ISSUER,
    client_metadata=ClientMetadata(CLIENT, 'secret'))
auth = OIDCAuthentication({PROVIDER_NAME: PROVIDER_CONFIG})


@app.route('/login')
@auth.oidc_auth(PROVIDER_NAME)
def login():
    user_session = UserSession(flask.session)
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)


@app.route('/api')
@auth.token_auth(PROVIDER_NAME,
                 scopes_required=['read', 'write'])
def api():
    current_token_identity = auth.current_token_identity
    return current_token_identity


@app.route('/profile')
@auth.access_control(PROVIDER_NAME)
def profile():
    if auth.current_token_identity:
        return auth.current_token_identity
    else:
        user_session = UserSession(flask.session)
        return jsonify(access_token=user_session.access_token,
                       id_token=user_session.id_token,
                       userinfo=user_session.userinfo)


@app.route('/logout')
@auth.oidc_logout
def logout():
    return "You've been successfully logged out!"


@auth.error_view
def error(error=None, error_description=None):
    return jsonify({'error': error, 'message': error_description})


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    auth.init_app(app)
    app.run()

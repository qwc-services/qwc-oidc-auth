import datetime
import os
import flask
import logging
from flask import Flask, jsonify

from flask_pyoidc import OIDCAuthentication
from flask_pyoidc.provider_configuration import ProviderConfiguration, ClientMetadata
from flask_pyoidc.user_session import UserSession

app = Flask(__name__)
app.logger.setLevel(logging.DEBUG)

# See https://flask.palletsprojects.com/en/2.0.x/config/
app.config.update({'SECRET_KEY': 'dev_key',  # make sure to change this!!
                   'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=7).total_seconds(),
                   'DEBUG': True})


app.config['OIDC_REDIRECT_URI'] = os.environ.get(
    'OIDC_REDIRECT_URI', 'http://127.0.0.1:5017/callback')

PROVIDER_CONFIG = ProviderConfiguration(
    issuer=os.environ['ISSUER_URL'],
    client_metadata=ClientMetadata(
        os.environ['CLIENT_ID'], os.environ['CLIENT_SECRET']))
auth = OIDCAuthentication({'default': PROVIDER_CONFIG})
auth.init_app(app)


@app.route('/login')
@auth.oidc_auth('default')
def login():
    user_session = UserSession(flask.session)
    app.logger.debug({"id_token": user_session.id_token,
                      "userinfo": user_session.userinfo})
    return jsonify(access_token=user_session.access_token,
                   id_token=user_session.id_token,
                   userinfo=user_session.userinfo)


@app.route('/api')
@auth.token_auth('default',
                 scopes_required=['read', 'write'])
def api():
    current_token_identity = auth.current_token_identity
    return current_token_identity


@app.route('/profile')
@auth.access_control('default')
def profile():
    if auth.current_token_identity:
        return auth.current_token_identity
    else:
        user_session = UserSession(flask.session)
        app.logger.debug({"id_token": user_session.id_token,
                          "userinfo": user_session.userinfo})
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
    print("Starting OIDC Auth service...")
    app.logger.setLevel(logging.DEBUG)
    app.run(host='localhost', port=5017, debug=True)

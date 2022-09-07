import datetime
import os
import flask
import logging
from flask import Flask, url_for, jsonify
from flask.logging import default_handler

from authlib.integrations.flask_client import OAuth


app = Flask(__name__)

# See https://flask.palletsprojects.com/en/2.0.x/config/
app.config.update({'SECRET_KEY': 'dev_key',  # make sure to change this!!
                   'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=7).total_seconds(),
                   'DEBUG': True})

# Enable debug logging for libs
logging.basicConfig(level="DEBUG")
root = logging.getLogger()
root.addHandler(default_handler)
# log = logging.getLogger('authlib')
# log.addHandler(logging.StreamHandler(sys.stdout))
# log.setLevel(logging.DEBUG)

app.config['OIDC_CLIENT_ID'] = os.getenv('CLIENT_ID')
app.config['OIDC_CLIENT_SECRET'] = os.getenv('CLIENT_SECRET')
# e.g. https://accounts.google.com/.well-known/openid-configuration
OPENID_METADATA_URL = os.getenv('ISSUER_URL') + \
                     '/.well-known/openid-configuration'

# https://docs.authlib.org/en/latest/client/flask.html#flask-openid-connect-client
oauth = OAuth(app)
oauth.register(
    name='oidc',
    server_metadata_url=OPENID_METADATA_URL,
    client_kwargs={
        'scope': 'openid email profile'
    }
)
oidc = oauth.create_client('oidc')


@app.route('/login')
def login():
    redirect_uri = url_for('callback', _external=True)
    return oidc.authorize_redirect(redirect_uri)


@app.route('/callback')
def callback():
    token = oidc.authorize_access_token()
    app.logger.debug(token)
    return jsonify(userinfo=token['userinfo'])


if __name__ == '__main__':
    print("Starting OIDC Auth service...")
    app.logger.setLevel(logging.DEBUG)
    app.run(host='localhost', port=5017, debug=True)

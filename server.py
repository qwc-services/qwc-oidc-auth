import datetime
import os
import flask
import logging
from flask import Flask, url_for, jsonify
from flask.logging import default_handler
from werkzeug.middleware.proxy_fix import ProxyFix
from authlib.integrations.flask_client import OAuth


# Enable debug logging for libs
root = logging.getLogger()
root.addHandler(default_handler)
root.setLevel(logging.DEBUG)

app = Flask(__name__)

# App is behind one proxy that sets the -For and -Host headers.
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# See https://flask.palletsprojects.com/en/2.0.x/config/
app.config.update({'SECRET_KEY': 'dev_key',  # make sure to change this!!
                   'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=7).total_seconds(),
                   'DEBUG': True})

app.config['OIDC_CLIENT_ID'] = os.getenv('CLIENT_ID')
app.config['OIDC_CLIENT_SECRET'] = os.getenv('CLIENT_SECRET')
# e.g. https://accounts.google.com/.well-known/openid-configuration
OPENID_METADATA_URL = os.getenv('ISSUER_URL') + \
                     '/.well-known/openid-configuration'

oauth = OAuth(app)
oauth.register(
    name='oidc',
    server_metadata_url=OPENID_METADATA_URL,
    client_kwargs={
        'scope': 'openid email profile'
    }
    #     'scope': 'user.read openid profile email'
    # },
    # authorize_params={'resource': 'urn:microsoft:userinfo'}
)
oidc = oauth.create_client('oidc')


@app.route('/login')
def login():
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
    return jsonify(userinfo=userinfo)


if __name__ == '__main__':
    print("Starting OIDC Auth service...")
    app.logger.setLevel(logging.DEBUG)
    app.run(host='localhost', port=5017, debug=True)

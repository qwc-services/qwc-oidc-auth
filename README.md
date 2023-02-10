OpenID Connect Authentication
=============================

Authentication service with OpenID Connect.

Dependencies
------------

* [Authlib](https://github.com/lepture/authlib)
* [Flask-JWT-Extended](http://flask-jwt-extended.readthedocs.io/)


Configuration
-------------

Environment variables (single tenant):

|     Variable    |        Description        | Default value |
|-----------------|---------------------------|---------------|
| `ISSUER_URL`    | OpenID Connect Issuer URL | -             |
| `CLIENT_ID`     | Client ID                 | -             |
| `CLIENT_SECRET` | Client secret             | -             |


### Service config

* [JSON schema](schemas/qwc-oidc-auth.json)
* File location: `$CONFIG_PATH/<tenant>/oidcAuthConfig.json`

Example:
```json
{
  "$schema": "https://github.com/qwc-services/qwc-oidc-auth/raw/master/schemas/qwc-oidc-auth.json",
  "service": "oidc-auth",
  "config": {
    "issuer_url": "https://qwc2-dev.onelogin.com/oidc/2",
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxxxxxxxx",
    "client_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  }
}
```

Usage/Development
-----------------

Create a virtual environment:

    virtualenv --python=/usr/bin/python3 .venv

Activate virtual environment:

    source .venv/bin/activate

Install requirements:

    pip install -r requirements.txt

Configure environment:

    echo FLASK_ENV=development >.flaskenv

Start local service:

     python server.py


### Usage

Run standalone application:

    python server.py

Login:
    http://127.0.0.1:5017/login

[![](https://github.com/qwc-services/qwc-oidc-auth/workflows/build/badge.svg)](https://github.com/qwc-services/qwc-oidc-auth/actions)
[![docker](https://img.shields.io/docker/v/sourcepole/qwc-oidc-auth?label=Docker%20image&sort=semver)](https://hub.docker.com/r/sourcepole/qwc-oidc-auth)

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
  "$schema": "https://github.com/qwc-services/qwc-oidc-auth/raw/main/schemas/qwc-oidc-auth.json",
  "service": "oidc-auth",
  "config": {
    "issuer_url": "https://qwc2-dev.onelogin.com/oidc/2",
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxxxxxxxx",
    "client_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
  }
}
```

The service expects authentication service information at $ISSUER_URL/.well-known/openid-configuration

See [JSON schema](schemas/qwc-oidc-auth.json) for optional configuration options.


### Identity provider configuration

CLIENT_ID and CLIENT_SECRET are defined on identity provider side.

The Redirect URI is the public base URL with the endpoint /callback (Example: https://qwc2.sourcepole.ch/oauth/callback).

This redirect URI can be manually configured with `redirect_uri`.


Usage/Development
-----------------

Create a virtual environment:

    python3 -m venv .venv

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

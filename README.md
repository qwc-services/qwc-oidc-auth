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

The static config files are stored as JSON files in `$CONFIG_PATH` with subdirectories for each tenant,
e.g. `$CONFIG_PATH/default/*.json`. The default tenant name is `default`.

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

The service expects authentication service information at `$ISSUER_URL/.well-known/openid-configuration`

See the [schema definition](schemas/qwc-oidc-auth.json) for the full set of supported config variables.

### Environment variables

Config options in the config file can be overridden by equivalent uppercase environment variables.

#### Configure Access Token endpoint

It is possible to authorize connection with a external Access Token in  the Authorization Header (endpoint `/tokenlogin`).

For each token a configuration needs to be add in `authorized_api_token`.

Example:
```json
{
  "$schema": "https://github.com/qwc-services/qwc-oidc-auth/raw/main/schemas/qwc-oidc-auth.json",
  "service": "oidc-auth",
  "config": {
    "issuer_url": "https://qwc2-dev.onelogin.com/oidc/2",
    "client_id": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxxxxxxxx",
    "client_secret": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "authorized_api_token": [{
      "keys_url": "https://public_keys_url_to_decode_token",
      "claims_options":{
        "iss": {
            "essential": true,
            "values": ["https://example.com", "https://example.org"]
        },
        "sub": {
            "essential": true,
            "value": "xxxxxxxxxxxxx"
        },
        "aud": {
          "essential": true,
          "value": "api://xxxx-xxxxxxxxx-xxxxx"
        }
      }
    }]
  }
}
```

`claims_options` are the token validation parameters which allow fine control over the content of the payload. See https://docs.authlib.org/en/latest/jose/jwt.html#jwt-payload-claims-validation.

### Identity provider configuration

`CLIENT_ID` and `CLIENT_SECRET `are defined on identity provider side.

The redirect URI is the public base URL with the endpoint `/callback` (Example: https://qwc2.sourcepole.ch/oauth/callback).

This redirect URI can be manually configured with `redirect_uri`.

### End session on logout

To end the OpenID session on when `/logout` is called, set `"end_session_on_logout": true` in the service config.
If your OpenID provider does not provide a `end_session_endpoint` in the `.well-known/openid-configuration`, you can set a custom logout URL via `session_logout_url`.


Run locally
-----------

Install dependencies and run:

    export CONFIG_PATH=<CONFIG_PATH>
    uv run src/server.py

To use configs from a `qwc-docker` setup, set `CONFIG_PATH=<...>/qwc-docker/volumes/config`.

Set `FLASK_DEBUG=1` for additional debug output.

Set `FLASK_RUN_PORT=<port>` to change the default port (default: `5000`).

Docker usage
------------

The Docker image is published on [Dockerhub](https://hub.docker.com/r/sourcepole/qwc-oidc-auth).

See sample [docker-compose.yml](https://github.com/qwc-services/qwc-docker/blob/master/docker-compose-example.yml) of [qwc-docker](https://github.com/qwc-services/qwc-docker).

OpenID Connect Authentication
=============================

Authentication service with OpenID Connect.

Dependencies
------------

* [Flask-pyoidc](https://github.com/zamzterz/Flask-pyoidc)
* [Flask-JWT-Extended](http://flask-jwt-extended.readthedocs.io/)


Configuration
-------------

Environment variables:

|     Variable    |        Description        | Default value |
|-----------------|---------------------------|---------------|
| `ISSUER_URL`    | OpenID Connect Issuer URL | -             |
| `CLIENT_ID`     | Client ID                 | -             |
| `CLIENT_SECRET` | Client secret             | -             |


Usage/Development
-----------------

CCreate a virtual environment:

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

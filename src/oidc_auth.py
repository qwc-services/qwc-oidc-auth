import os

from authlib.integrations.flask_client import OAuth
from authlib.integrations.flask_oauth2 import current_token
from flask import (
    url_for, request, session, redirect, make_response
)
from flask_jwt_extended import (
    create_access_token, set_access_cookies, unset_jwt_cookies
)

from qwc_services_core.auth import GroupNameMapper
from qwc_services_core.runtime_config import RuntimeConfig

class OIDCAuth:
    """OIDCAuth class

    User login with OpenID Connect
    """

    def __init__(self, tenant, app):
        """Constructor

        :param str tenant: Tenant ID
        :param App app: Flask application
        """
        self.tenant = tenant
        self.app = app
        self.logger = app.logger

        config_handler = RuntimeConfig("oidcAuth", self.logger)
        self._config = config_handler.tenant_config(tenant)

        oauth = OAuth(app)
        client_id = self._config.get('client_id', os.getenv('CLIENT_ID'))
        client_secret = self._config.get('client_secret', os.getenv('CLIENT_SECRET'))
        issuer_url = self._config.get('issuer_url', os.getenv('ISSUER_URL'))
        # e.g. https://accounts.google.com/.well-known/openid-configuration
        metadata_url = f"{issuer_url}/.well-known/openid-configuration"
        openid_scopes = self._config.get('openid_scopes', 'openid email profile')
        oauth.register(
            name=tenant,
            client_id=client_id,
            client_secret=client_secret,
            server_metadata_url=metadata_url,
            client_kwargs={
                'scope': openid_scopes
            }
            # authorize_params={'resource': 'urn:microsoft:userinfo'}
        )
        self._oidc = oauth.create_client(tenant)

    def config(self):
        return self._config

    def tenant_base(self):
        """base path for tenant"""
        # Updates config['JWT_ACCESS_COOKIE_PATH'] as side effect
        prefix = self.app.session_interface.get_cookie_path(self.app)
        return prefix.rstrip('/') + '/'

    def callback(self):
        token = self._oidc.authorize_access_token()
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
        #     "appid": "c8699d44-facf-4329-b2c2-ff1f8c385beb",
        #     "apptype": "Confidential",
        #     "aud": "c8699d44-facf-4329-b2c2-ff1f8c385beb",
        #     "auth_time": 1662626992,
        #     "authmethod": "http://schemas.microsoft.com/ws/2008/06/identity/authenticationmethod/windows",
        #     "exp": 1662630592,
        #     "group": ["User", Admin"],
        #     "iat": 1662626992,
        #     "iss": "https://example.com/adfs",
        #     "nbf": 1662626992,
        #     "nonce": "Ntyr78eXokrvA82BDKsV",
        #     "pwd_exp": "1733602",
        #     "pwd_url": "https://example.com/adfs/portal/updatepassword/",
        #     "scp": "profile email openid"
        #     "sid": "S-1-5-21-111884681-232138482-1136263860-54956",
        #     "sub": "E8uMvTw4EzVtNJjAGGkn/HLxB5lsxPvUz9N8v2ONw6w=",
        #     "unique_name": "DOMAIN\\USER",
        #     "upn": "john.doe@example.com",
        #     "ver": "1.0",
        #   }
        # }
        self.logger.info(userinfo)
        groupinfo = self._config.get('groupinfo', 'group')
        mapper = GroupNameMapper()

        if self._config.get('username'):
            username = userinfo.get(self._config.get('username'))
        else:
            username = userinfo.get('preferred_username',
                                    userinfo.get('upn', userinfo.get('email')))
        groups = userinfo.get(groupinfo, [])
        if isinstance(groups, str):
            groups = [groups]
        # Add group for all authenticated users
        groups.append('verified')
        # Apply group name mappings
        groups = [
            mapper.mapped_group(g)
            for g in groups
        ]
        identity = {'username': username, 'groups': groups}
        self.logger.info(identity)
        # Create the tokens we will be sending back to the user
        access_token = create_access_token(identity)
        # refresh_token = create_refresh_token(identity)

        base_url = self.tenant_base()
        target_url = session.pop('target_url', base_url)

        resp = make_response(redirect(target_url))
        set_access_cookies(resp, access_token)
        return resp        

    def login(self):
        target_url = request.args.get('url', self.tenant_base())
        # We store the target url in the session.
        # Instead we could pass it as OAuth state
        # (state=target_url in authorize_redirect)
        # Then we should only pass the path as state for security reasons
        session['target_url'] = target_url
        self.logger.debug("Request headers:")
        self.logger.debug(request.headers)
        redirect_uri = self._config.get(
            'redirect_uri', url_for('callback', _external=True))
        self.logger.info(f"redirect_uri: {redirect_uri}")
        return self._oidc.authorize_redirect(redirect_uri)

    def logout(self):
        self.logger.debug("Logout from handler")
        target_url = request.args.get('url', self.tenant_base())
        resp = make_response(redirect(target_url))
        unset_jwt_cookies(resp)
        return resp

    def token_login(self):
        userinfo = current_token
        self.logger.info(userinfo)
        groupinfo = self._config.get('groupinfo', 'group')
        mapper = GroupNameMapper()

        if self._config.get('username'):
            username = userinfo.get(self._config.get('username'))
        else:
            username = userinfo.get('preferred_username',
                                    userinfo.get('upn', userinfo.get('email')))
        groups = userinfo.get(groupinfo, [])
        if isinstance(groups, str):
            groups = [groups]
        # Add group for all authenticated users
        groups.append('verified')
        # Apply group name mappings
        groups = [
            mapper.mapped_group(g)
            for g in groups
        ]
        identity = {'username': username, 'groups': groups}
        self.logger.info(identity)
        # Create the tokens we will be sending back to the user
        access_token = create_access_token(identity)

        base_url = self.tenant_base()
        target_url = session.pop('target_url', base_url)

        resp = make_response(redirect(target_url))
        set_access_cookies(resp, access_token)
        return resp

import os, logging, json, posixpath

from airflow import configuration as conf
from airflow.www.security import AirflowSecurityManager
from flask import abort, make_response, redirect
from flask_appbuilder.security.manager import AUTH_OID
from flask_appbuilder.security.views import AuthOIDView
from flask_appbuilder.views import ModelView, SimpleFormView, expose
from flask_login import login_user
from flask_oidc import OpenIDConnect

logger = logging.getLogger(__name__)

# Set the OIDC field that should be used
NICKNAME_OIDC_FIELD = os.getenv('NICKNAME_OIDC_FIELD', 'nickname')
FULL_NAME_OIDC_FIELD = os.getenv('FULL_NAME_OIDC_FIELD', 'name')
GROUPS_OIDC_FIELD = os.getenv('GROUPS_OIDC_FIELD', 'groups')
EMAIL_FIELD = os.getenv('EMAIL_FIELD', 'email')
SUB_FIELD = os.getenv('SUB_FIELD', 'sub')  # User ID


# Convert groups from comma separated string to list
ALLOWED_PROVIDER_GROUPS = os.environ.get('ALLOWED_PROVIDER_GROUPS')
if ALLOWED_PROVIDER_GROUPS:
    ALLOWED_PROVIDER_GROUPS = [g.strip() for g in ALLOWED_PROVIDER_GROUPS.split(',')]
else: ALLOWED_PROVIDER_GROUPS = []

if ALLOWED_PROVIDER_GROUPS:
    logger.debug('AirFlow access requires membership to one of the following groups: %s'
        % ', '.join(ALLOWED_PROVIDER_GROUPS))


# Extending AuthOIDView
class AuthOIDCView(AuthOIDView):

    @expose('/login/', methods=['GET', 'POST'])
    def login(self, flag=True):

        sm = self.appbuilder.sm
        oidc = sm.oid

        @self.appbuilder.sm.oid.require_login
        def handle_login():
            user = sm.auth_user_oid(oidc.user_getfield(EMAIL_FIELD))

            # Group membership required
            if ALLOWED_PROVIDER_GROUPS:

                # Fetch group membership information from OIDC provider
                groups = oidc.user_getinfo([GROUPS_OIDC_FIELD]).get(GROUPS_OIDC_FIELD, [])
                intersection = set(ALLOWED_PROVIDER_GROUPS) & set(groups)
                logger.debug('AirFlow user member of groups in ACL list: %s' % ', '.join(intersection))

                # Unable to find common groups, prevent login
                if not intersection:
                    return abort(403)

            # Create user (if it doesn't already exist)
            # TODO: remove for client as we do not want to allow new users to be created, just map from current IDP to existing airflow user
            if user is None:
                info = oidc.user_getinfo([
                    NICKNAME_OIDC_FIELD,
                    FULL_NAME_OIDC_FIELD,
                    GROUPS_OIDC_FIELD,
                    SUB_FIELD,
                    EMAIL_FIELD,
                    "profile"
                ])
                full_name = info.get(FULL_NAME_OIDC_FIELD)
                if " " in full_name:
                    full_name = full_name.split(" ")
                    first_name = full_name[0]
                    last_name = full_name[1]
                else:
                    first_name = full_name
                    last_name = ""
                user = sm.add_user(
                    username=info.get(NICKNAME_OIDC_FIELD),
                    first_name=first_name,
                    last_name=last_name,
                    email=info.get(EMAIL_FIELD),
                    role=sm.find_role(sm.auth_user_registration_role)
                )

            login_user(user, remember=False)
            return redirect(self.appbuilder.get_url_for_index)

        return handle_login()

    @expose('/logout/', methods=['GET', 'POST'])
    def logout(self):
        oidc = self.appbuilder.sm.oid
        if not oidc.credentials_store:
            return redirect('/login/')
        self.revoke_token()
        oidc.logout()
        super(AuthOIDCView, self).logout()
        response = make_response("You have been signed out")
        return response

    def revoke_token(self):
        """ Revokes the provided access token. Sends a POST request to the token revocation endpoint
        """
        import aiohttp
        import asyncio
        import json
        oidc = self.appbuilder.sm.oid
        sub = oidc.user_getfield(SUB_FIELD)
        config = oidc.credentials_store
        config = config.get(str(sub))
        config = json.loads(config)
        payload = {
            "token": config['access_token'],
            "token_type_hint": "refresh_token"
        }
        auth = aiohttp.BasicAuth(config['client_id'], config['client_secret'])
        # Sends an asynchronous POST request to revoke the token
      
        async def revoke():
            async with aiohttp.ClientSession() as session:
                async with session.post(self.appbuilder.app.config.get('OIDC_LOGOUT_URI'), data=payload, auth=auth) as response:
                    logging.info(f"Revoke response {response.status}")

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(revoke())



class OIDCSecurityManager(AirflowSecurityManager):
    """
    Custom security manager class that allows using the OpenID Connection authentication method.
    """
    def __init__(self, appbuilder):
        super(OIDCSecurityManager, self).__init__(appbuilder)
        if self.auth_type == AUTH_OID:
           self.oid = OpenIDConnect(self.appbuilder.get_app)
           self.authoidview = AuthOIDCView


basedir = os.path.abspath(os.path.dirname(__file__))

SECURITY_MANAGER_CLASS = OIDCSecurityManager
# The SQLAlchemy connection string.
SQLALCHEMY_DATABASE_URI = conf.get('core', 'SQL_ALCHEMY_CONN')

# Flask-WTF flag for CSRF
CSRF_ENABLED = True

AUTH_TYPE = AUTH_OID
OIDC_CLIENT_SECRETS = os.getenv('OIDC_CLIENT_SECRETS', 'client_secret.json')  # Configuration file for OIDC provider OIDC
OIDC_COOKIE_SECURE= False
OIDC_ID_TOKEN_COOKIE_SECURE = False
OIDC_REQUIRE_VERIFIED_EMAIL = False
OIDC_USER_INFO_ENABLED = True
CUSTOM_SECURITY_MANAGER = OIDCSecurityManager

# Ensure that the secrets file exists
if not os.path.exists(OIDC_CLIENT_SECRETS):
    ValueError('Unable to load OIDC client configuration. %s does not exist.' % OIDC_CLIENT_SECRETS)

# Parse client_secret.json for scopes and logout URL
with open(OIDC_CLIENT_SECRETS) as f:
    OIDC_APPCONFIG = json.loads(f.read())

# Ensure that the logout/revoke URL is specified in the client secrets file
PROVIDER_OIDC_URL = OIDC_APPCONFIG.get('web', {}).get('issuer')
OIDC_PROVIDER_NAME = OIDC_APPCONFIG.get('web', {}).get('name')
if not PROVIDER_OIDC_URL:
    raise ValueError('Invalid OIDC client configuration, OIDC provider OIDC URI not specified.')

# this will change based on the OIDC provider
OIDC_SCOPES = OIDC_APPCONFIG.get('OIDC_SCOPES', ['openid', 'email', 'profile'])  # Scopes that should be requested.
OIDC_LOGOUT_URI = posixpath.join(PROVIDER_OIDC_URL, 'oauth/revoke') # OIDC logout URL

# Allow user self registration
AUTH_USER_REGISTRATION = False

# Default role to provide to new users
AUTH_USER_REGISTRATION_ROLE = os.environ.get('AUTH_USER_REGISTRATION_ROLE', 'Public')

AUTH_ROLE_ADMIN = 'Admin'
AUTH_ROLE_PUBLIC = "Public"

OPENID_PROVIDERS = [
   {'name': OIDC_PROVIDER_NAME, 'url': posixpath.join(PROVIDER_OIDC_URL, 'oauth/authorize')}
]
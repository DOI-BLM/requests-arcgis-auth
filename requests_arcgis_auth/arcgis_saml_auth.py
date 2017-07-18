

from datetime import datetime
from exceptions import ValueError

import requests
from requests.auth import AuthBase
from requests_kerberos import HTTPKerberosAuth, OPTIONAL
from requests_ntlm import HttpNtlmAuth
from bs4 import BeautifulSoup                               # required - pip install --trusted-host pypi.python.org beautifulsoup4
import re

from urlparse import urlparse
import json

from arcgis_exceptions import TokenAuthenticationError, TokenAuthenticationWarning


class ArcGISPortalSAMLAuth(AuthBase):
    # Esri ArcGIS Online (AGOL) and Portal for ArcGIS Authentication Handler to be used with the Python Requests Package
    # Specifically designed to work with portals that are federated to a SAML Based identity provider with 'enterprise logins'.
    # This will execute the OAuth2 "User login via Application" workflow (Authorization Code Grant) as documented at - http://resources.arcgis.com/en/help/arcgis-rest-api/index.html#//02r30000009z000000

    def __init__(self,
        client_id,
        capture_request_history = False,
        saml_auth = HTTPKerberosAuth(mutual_authentication = OPTIONAL),
        expiration = 120,
        verify = True):

        self.client_id = client_id
        self.capture_request_history = capture_request_history
        self.history=[]
        self.expiration = expiration    # Defaults to 2 hours (120 min)
        self.verify = verify
        self.redirect_uri = 'urn:ietf:wg:oauth:2.0:oob'

        # DOI SAML service required these headers for single-sign-on.  Developers can explicity over-write if needed...
        self.saml_headers = {"User-Agent":"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/7.0; SLCC2; .NET CLR 2.0.50727; .NET4.0C; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET4.0E; InfoPath.3)"}

        # DOI SAML service did not support 'REQUIRED' mutual authentication.  HTTPKerberosAuth threw a 'mutual authentication exception'.  Developers can explicity over-write if needed (or even add NTLM or some other 3rd party auth handler to the SAML communications)
        self.saml_auth = saml_auth

        ### Derived Fields ###
        self._verify_cert = True
        self._base_url = None       # Expected to be - https://host/<instance>/sharing/rest     where <instance> is optional
        self._oauth_info = None     # Derived from the portal "authorize" endpoint
        self._saml_code = None      # Derived from the SAML login
        self._token_data = None     # Derived from the portal "token" endpoint
        self._token_acquired = None

    def __call__(self, prepared_request):

        # Initialze on the first call ...
        if (self._base_url is None):
            self._init(prepared_request.url)


        # Handle Expired Token
        prepared_request.register_hook('response', self._handle_response)


        # Check token expiration and re-acquire if needed
        # TODO - What happens when the refresh token is expired???
        delta = datetime.now() - self._token_acquired
        if delta.total_seconds()/60 >= self._token_data.get("expires_in"):
            payload = {
                "client_id": self.client_id,
                "grant_type": "refresh_token",
                "refresh_token": self._token_data.get("refresh_token")}
            self._get_access_token(payload)

        return self._add_token_to_request(prepared_request)

    def _init(self, url):

        # Initialze the authentication handler (first request only)

        if self._base_url is None:
            self._derive_base_url(url)

        self._get_portal_authorization_info()
        self._authenticate_with_saml()
        self._get_portal_tokens()

    def _derive_base_url(self,url):
        # Need to support the following example URL's:
            # https://ORG.maps.arcgis.com/
            # https://ORG.maps.arcgis.com
            # https://ORG.maps.arcgis.com/sharing/rest
            # https://ORG.maps.arcgis.com/sharing/rest/
            # https://ORG.maps.arcgis.com/sharing/rest/portals/self
            # https://ORG.maps.arcgis.com/instance
            # https://ORG.maps.arcgis.com/instance/
            # https://ORG.maps.arcgis.com/instance/sharing/rest
            # https://ORG.maps.arcgis.com/instance/sharing/rest/
            # https://ORG.maps.arcgis.com/instance/sharing/rest/portals/self
            # https://fqdn/instance
            # https://fqdn/instance/
            # https://fqdn/instance/sharing/rest
            # https://fqdn/instance/sharing/rest/
            # https://fqdn/instance/sharing/rest/portals/self
        up = urlparse(url)
        path_splt = up.path.split("/")
        instance = path_splt[1] if len(path_splt) > 1 else "sharing"
        instance = "/{0}".format(instance) if instance.lower() != "sharing" and instance != "" else ""
        final_up = up._replace(path="{0}/sharing/rest".format(instance), query="")
        self._base_url = final_up.geturl()

    def _get_portal_authorization_info(self):

        # Obtain the Identity Provider URL (idpAuthorizeUrl) and OAUTH State (oauth_state)
        # http://resources.arcgis.com/en/help/arcgis-rest-api/index.html#/Authorize/02r300000214000000/

        ERROR_STRING = "Unable to obtain portal authorization information"

        # Execute request to portal 'authorize' end-point
        portal_auth_url = self._base_url + "/oauth2/authorize"
        params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'expiration': self.expiration,
            'redirect_uri': self.redirect_uri}
        response = requests.get(portal_auth_url, params=params, verify = self.verify)
        if self.capture_request_history:
            self.history.append(response)
        if response.status_code != 200:
            raise TokenAuthenticationError("{err}; HTTP Status Code {sc} from {url}".format(err=ERROR_STRING,sc=response.status_code,url=portal_auth_url))

        # Parse the response and obtain authentication information
        pattern = re.compile('var oAuthInfo = ({.*?});', re.DOTALL)
        soup = BeautifulSoup(response.text, 'html.parser')
        for script in soup.find_all('script'):
            script_code = str(script.string.encode("utf-8")).strip() if script.string is not None else ""
            matches = pattern.search(script_code)
            if matches is not None:
                js_object = matches.groups()[0]
                self._oauth_info = json.loads(js_object)
                break
        if self._oauth_info is None or self._oauth_info == {}:
            raise TokenAuthenticationError("{err}; unable to parse response to obtain oAuthInfo".format(err=ERROR_STRING))

    def _authenticate_with_saml(self):

        # Authenticate with the SAML service & obtain SAML code

        ERROR_STRING = r'Unable to authenticate with SAML Service'

        # Execute request to SAML service
        try:
            idp_url = self._oauth_info.get("federationInfo").get("idpAuthorizeUrl")
        except:
            raise TokenAuthenticationError("{err}; unable to determine IDP Authorization URL from {json}".format(err=ERROR_STRING,json=self._oauth_info))

        payload = {'oauth_state':self._oauth_info.get('oauth_state')}
        response = requests.post(idp_url, data = payload, auth = self.saml_auth, headers = self.saml_headers, allow_redirects = True, verify = self.verify)
        if self.capture_request_history:
            self.history.append(response)
        if response.status_code != 200:
            raise TokenAuthenticationError("{err}; HTTP Status Code {sc} from {url}".format(err=ERROR_STRING,sc=response.status_code,url=idp_url))

        # Parse the response and obtain the SAML CODE
        soup = BeautifulSoup(response.text, 'html.parser')
        url=""
        for form in soup.find_all('form', { 'name' : 'hiddenform' }):
            # Get the URL to POST
            url = form['action']
            # Get all of the named input fields
            inputElements = form.find_all('input', { 'name' : True })
            post_data = dict([(el['name'], el['value']) for el in inputElements])
            # Submit the form and hopefully get our code value
            response = requests.post(url, data = post_data, allow_redirects = True, auth=self.saml_auth, verify = self.verify)
            if self.capture_request_history:
                self.history.append(response)
            if response.status_code != 200:
                raise TokenAuthenticationError("{err}; HTTP Status Code {sc} from {url}".format(err=ERROR_STRING,sc=response.status_code,url=idp_url))
            token_content = response.text
            break
        try:
            soup = BeautifulSoup(token_content, 'html.parser')
            self._saml_code = soup.find(id='code')['value']
        except:
            raise TokenAuthenticationError("{err}; Unable to acquire SAML code from {url}".format(err=ERROR_STRING,url=idp_url))

    def _get_portal_tokens(self):

        # provide SAML code to portal and acquire portal access_token and refresh_token

        payload = {
            'client_id': self.client_id,
            'code': self._saml_code,
            'redirect_uri': self.redirect_uri,
            'grant_type': 'authorization_code'}
        self._get_access_token(payload)

    def _get_access_token(self,params):

        # Acquire access token
        # http://resources.arcgis.com/en/help/arcgis-rest-api/index.html#/Token/02r300000213000000/

        ERROR_STRING = r'Unable to obtain portal access_token'

        portal_token_url = self._base_url + "/oauth2/token"
        payload = params

        response = requests.post(portal_token_url, data = payload, verify = self.verify)
        self._token_acquired = datetime.now()
        if self.capture_request_history:
            self.history.append(response)
        if response.status_code != 200:
            raise TokenAuthenticationError("{err}; HTTP Status Code {sc} from {url}".format(err=ERROR_STRING,sc=response.status_code,url=portal_token_url))
        self._token_data = response.json()

    def _handle_response(self, resp, **kwargs):
        # type(r) = Response
        # Check the response for an expired token... re-acquire if necessary
        #       ex:     {u'error': {u'code': 498, u'details': [], u'message': u'Invalid token.'}}

        ### Handling Expired Tokens!!!

        # Check for actual HTTP Status code 498 (when f=json is not supplied)
        if resp.status_code == 498:
            return self._handle_expired_token(resp,**kwargs)

        # Check for JSON error (vendor spec)
        try:
            if resp.json().get("error") is not None:
                err = resp.json().get("error")
                if err.get("code") == 498 and err.get("message") == "Invalid token.":
                    return self._handle_expired_token(resp, **kwargs)
                else:
                    # Why do we get here?!?!?!?
                    #    {u'error': {u'code': 403,
                    #        u'details': [],
                    #        u'message': u'You do not have permissions to access this resource or perform this operation.',
                    #        u'messageCode': u'GWM_0003'}}
                    # OTHERS?!?!?!?
                    # raise TokenAuthenticationError("Failed to handle expired token...")
                    pass
        # Unable to parse JSON data... requestor could ask for non-JSON formatted data...  Just throw away exception for now...
        except ValueError:
            pass
        return resp

    def _handle_expired_token(self, resp, **kwargs):
        # Handle an expired token by re-initializing the object

        req=resp.request.copy()
        self._init(req.url)
        req=self._add_token_to_request(req)
        response = resp.connection.send(req,**kwargs)
        if self.capture_request_history:
            self.history.append(response)
        return response

    def _add_token_to_request(self, prepared_request):

        # Add the token to the request

        # Force the request to POST.  Possible future implicatons here (like if a request only supports GET)
        prepared_request.method="POST"

        # Add the token to the request
        if self._token_data.get("access_token") is None:
            raise TokenAuthenticationWarning("Unable to add the access_token to the request;")
        params={"token": self._token_data.get("access_token")}

        # Remove the token form the request QUERY if it already exists...
        up = urlparse(prepared_request.url)
        orig_params = up.query.split("&")
        for p in orig_params:
            if p != "":                 # Handle empty Parameter List
                k,v = p.split("=")
                if k.lower() != "token":
                    params.update({k:v})
        up = up._replace(query="")
        prepared_request.prepare_url(up.geturl(), params = params)

        return prepared_request

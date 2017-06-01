print
import os
from datetime import datetime
import time
import warnings


# Ideally pull 'requests' from root install location.  If not we could potentially bundle with the package (bad practice!)
    # Maybe follow behind requests... put this in a 'packages' folder and note that these are not for modification??  https://github.com/kennethreitz/requests/tree/master/requests/packages

import requests
from requests.auth import AuthBase
from requests_kerberos import HTTPKerberosAuth
from requests_ntlm import HttpNtlmAuth

from urllib import urlencode
from urlparse import urlparse

from arcgis_token_auth import ArcGISServerTokenAuth, ArcGISPortalTokenAuth
from arcgis_exceptions import TokenAuthenticationError, TokenAuthenticationWarning

# Added this to be able to execute from PyScripter (which kept throwing errors about not being in a 'package').
"""try:
    from .arcgis_exceptions import TokenAuthenticationError, TokenAuthenticationWarning
except:
    import sys
    from os import path
    sys.path.append( path.dirname( path.dirname( path.abspath(__file__) ) ) )
    from arcgis_exceptions import TokenAuthenticationError, TokenAuthenticationWarning
"""

""" TODOS
    Try to securely pass it (with post in the body).  Esri does not seem to support that on the admin interface.  For now, just add to the URI parameters
    if username/pwd is wrong... dont keep re-requesting it... accounts get locked easily (3 failed login attempts)?
"""

""" NOTES
    will generate a token using the token URL from the FIRST REQUEST only at this point.
        Meaning the token object will not be able to be re-used between management interfaces (seperate ArcGIS for Server Sites)
"""
class ArcGISServerAuth(ArcGISServerTokenAuth,HTTPKerberosAuth,HttpNtlmAuth):
    # Will determine security posture and will setup either web-tier or token security.

    def __init__(self,username=None,password=None,verify=True,instance=None):
        super(ArcGISServerAuth, self).__init__(username,password,verify,instance)
        self._instanceof=None

    def __call__(self,r):

        self._init(r)

        # Possible future TODO - what if there is no auth handler set???  For now, do not raise an exception...  This would support 'anonymous' access.
        if self._instanceof is None:
            warnings.warn("Unable to authenticate with the site; site does not support token, kerberos, or NTLM authentication.",TokenAuthenticationWarning)
            return r

        return self._instanceof.__call__(self,r)

    def _init(self,r):
        # Only execute if after initialized (first request)

        # Derive Auth Information
        if self._auth_info is None:
            self._determine_auth_handler(r)

    def _determine_auth_handler(self,r):
        # Determine the Authenticaiton Handler to use (token, kerberos, NTLM)

        # First try the Token Authentication
        try:
            ArcGISServerTokenAuth._init(self,r)
            if self._auth_info.get("isTokenBasedSecurity"):
                self._instanceof=ArcGISServerTokenAuth
                return True
        except TokenAuthenticationError:
            # catch & throw away exception and try other handlers.
            pass

        # If token auth fails, check for "Web-Tier" security
        lr = self._last_request
        auths=[]
        if lr.status_code == 401 and lr.headers.get("WWW-Authenticate") is not None:
            auths=lr.headers.get("WWW-Authenticate").split(", ")

        # Try Kerberos
        if 'Negotiate' in auths:
            test_req = requests.head(r.url,auth=HTTPKerberosAuth(),verify=self.verify)
            if test_req.status_code == 200:
                self._instanceof = HTTPKerberosAuth
                self._auth_info={"isTokenBasedSecurity": False}
                HTTPKerberosAuth.__init__(self)
                return True

        # Try NTLM
        if 'Negotiate' in auths or 'NTLM' in auths:
            test_req = requests.head(r.url,auth=HttpNtlmAuth(self.username,self.password),verify=self.verify)
            if test_req.status_code == 200:
                self._instanceof = HttpNtlmAuth
                self._auth_info={"isTokenBasedSecurity": False}
                HttpNtlmAuth.__init__(self,self.username,self.password)
                return True

        return False


    def _derive_instance(self,r):

        # Need to determine the "instance" from the requesting URL, then security posture (info) endpoint.
        # Expected Inputs:
        #   https://host/arcgis
        #   https://host/arcgis/sharing
        #   https://host/arcgis/sharing/rest
        #   https://host:port/sharing/rest

        # Derive the 'Instance' (normally the first path element), unless it is "sharing" (ex: AGOL).  This is the 'Web-Adaptor' name for on-premise portals
        if self.instance is None:
            up=urlparse(r.url)
            path1=up.path.split("/")[1]
            self.instance = path1 if path1 != "sharing" else ""

    """def _get_server_security_posture(self,r,auth=None):

        # Query the server 'Info' to determine security posture
        server_info_url=self._get_url_string(r,"/rest/info")

        # Add f=json to parameters if not included in the URL string
        params={"f":"json"} if server_info_url.find("f=json") is -1 else {}
        self._last_request=requests.post(server_info_url,params=params,verify=self.verify,auth=auth)
        if self._last_request.status_code != 200:
            raise TokenAuthenticationError("Unable to acquire token; cannot determine site information at {url}.  HTTP Status Code {sc}".format(url=server_info_url,sc=self._last_request.status_code))

        if not self._last_request.json().has_key('authInfo'):
            raise TokenAuthenticationError("Unable to acquire token; authInfo JSON Key unavailable at {url}.  HTTP Status Code {sc}".format(url=server_info_url,sc=self._last_request.status_code))

        self._auth_info = self._last_request.json().get('authInfo')
    """

class ArcGISPortalAuth(ArcGISPortalTokenAuth,HTTPKerberosAuth,HttpNtlmAuth):
    # Will determine security posture and will setup either web-tier or token security.

    def __init__(self,username=None,password=None,verify=True,instance=None):
        super(ArcGISPortalAuth, self).__init__(username,password,verify,instance)
        self._instanceof=None
        self._auth_info = None

    def __call__(self,r):

        self._init(r)

        # Possible future TODO - what if there is no auth handler set???  For now, do not raise an exception...  This would support 'anonymous' access.
        if self._instanceof is None:
            warnings.warn("Unable to authenticate with the portal; portal does not support token, kerberos, or NTLM authentication.",TokenAuthenticationWarning)
            return r

        return self._instanceof.__call__(self,r)

    def _init(self,r):
        # Only execute if after initialized (first request)

        # Derive Auth Information
        if self._auth_info is None:
            self._determine_auth_handler(r)

    def _determine_auth_handler(self,r):
        # Determine the Authenticaiton Handler to use (token, kerberos, NTLM)

        # First try the Token Authentication
### !!! LEFT OFF HERE!!!  Need to determine server security type, then use right instance of...
        self._last_request=requests.head(self._get_token_url(r),verify=self.verify)
        if self._last_request.status_code==200:
            #try:
            ArcGISPortalTokenAuth._init(self,r)
            self._instanceof=ArcGISPortalTokenAuth
            self._auth_info={"isTokenBasedSecurity": True}
            return True
            #except TokenAuthenticationError:
            #    # catch & throw away exception and try other handlers.
            #    pass

        # If token auth fails, check for "Web-Tier" security
        lr = self._last_request
        auths=[]
        if lr.status_code == 401 and lr.headers.get("WWW-Authenticate") is not None:
            auths=lr.headers.get("WWW-Authenticate").split(", ")

        # Try Kerberos
        if 'Negotiate' in auths:
            self._last_request = requests.head(r.url,auth=HTTPKerberosAuth(),verify=self.verify)
            if self._last_request.status_code == 200:
                self._instanceof = HTTPKerberosAuth
                self._auth_info={"isTokenBasedSecurity": False}
                HTTPKerberosAuth.__init__(self)
                return True

        # Try NTLM
        if 'Negotiate' in auths or 'NTLM' in auths:
            self._last_request = requests.head(r.url,auth=HttpNtlmAuth(self.username,self.password),verify=self.verify)
            if self._last_request.status_code == 200:
                self._instanceof = HttpNtlmAuth
                self._auth_info={"isTokenBasedSecurity": False}
                HttpNtlmAuth.__init__(self,self.username,self.password)
                return True

        return False




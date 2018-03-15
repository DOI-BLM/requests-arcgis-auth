
import os
from datetime import datetime
import time
import warnings

# Ideally pull 'requests' from root install location.  If not we could potentially bundle with the package (bad practice!)
    # Maybe follow behind requests... put this in a 'packages' folder and note that these are not for modification??  https://github.com/kennethreitz/requests/tree/master/requests/packages

import requests
from requests.auth import AuthBase
try:
    from urllib import urlencode
except:
    from urllib.parse import quote
    def urlencode(input_dict):
        return ('&'.join(['{}={}'.format(quote(k, safe='/'), quote(v, safe='/'))
            for k, v in input_dict.items()]))

try:
    from urlparse import urlparse
except:
    from urllib.parse import urlparse


# Added this to be able to execute from PyScripter (which kept throwing errors about not being in a 'package').
try:
    from .arcgis_exceptions import TokenAuthenticationError, TokenAuthenticationWarning
except:
    import sys
    from os import path
    sys.path.append( path.dirname( path.dirname( path.abspath(__file__) ) ) )
    from arcgis_exceptions import TokenAuthenticationError, TokenAuthenticationWarning

""" TODOS
    Try to securely pass it (with post in the body).  Esri does not seem to support that on the admin interface.  For now, just add to the URI parameters
    if username/pwd is wrong... dont keep re-requesting it... accounts get locked easily (3 failed login attempts)?
"""

""" NOTES
    will generate a token using the token URL from the FIRST REQUEST only at this point.
        Meaning the token object will not be able to be re-used between management interfaces (seperate ArcGIS for Server Sites)
"""

class ArcGISServerTokenAuth(AuthBase):
    # Esri ArcGIS for Server Authentication Handler to be used with the Requests Package
    """Python Requests Authentication Handler for the Esri ArcGIS Server product (Stand Alone).  This class only supports the vendor proprietary 'Token Based'TokenAuthenticationError authentication.

    Args:
        username (:obj:`str`): Username of user authenticating.
        password (:obj:`str`): Password of user authenticating.
        verify (:obj:`bool`, Optional): Verify SSL Certificates (default: True).  Use caution disabiling this (not reccomended for production use)
        instance (:obj:`str`, Optional): - The 'instance' name of the ArcGIS for Server Site (also known as the web-adaptor name).  Code will attempt to derive if not supplied.  ex: 'arcgis'
    """
    def __init__(self,username,password,verify=True,instance=None):

        # Public attributes
        self.username=username
        self.password=password
        self.instance=instance                                              # The 'instance' is also the 'web-adaptor' name.  Defaults to 'arcgis'.  Will be derived from the first URL request if not supplied.
        self.verify=verify

        # 'Private' Attributes
        self._token={}
        self._auth_info=None
        self._expires=datetime.fromtimestamp(int(time.time())-120)          # Set to 2 min ago
        self._last_request=None
        self._redirect=None                                                 # Only used for debugging... possibly remove?

    def __call__(self,r):

        # type(r) = PreparedRequest

        self._init(r)

        # If the site does not support token authentication, then dont generate a token and just return the prepared request
        if not self._auth_info.get("isTokenBasedSecurity"):
            warnings.warn(("Unable to acquire token; site does not support token authentication"),TokenAuthenticationWarning)
            return r

        # Check token expiration and generate a new one if needed.  If it expires within 2 min from now (a little padding)
        if (self._expires - datetime.now()).total_seconds() < 120:
            self._get_token(self._auth_info.get("tokenServicesUrl"))

        # Handle Re-Directs - See https://github.com/kennethreitz/requests/issues/4040
        r.register_hook('response', self.handle_redirect)

        self._add_token_to_request(r)
        return r

    def _init(self,r):

        # Only execute if after initialized (first request) - Derive Instance (if needed) & Authentication Info

        if self.instance is None:
            self._derive_instance(r)

        if self._auth_info is None:
            self._get_server_security_posture(r)


    def handle_redirect(self, r, **kwargs):

        # Handling Re-Direct!!!  This was necessary because the method (POST) was not persisting on an HTTP 302 re-direct.  See https://github.com/kennethreitz/requests/issues/4040
        # type(r) = Response

        if r.is_redirect:
            self._redirect=r
            req=r.request.copy()
            req.url=r.headers.get("Location")
            self._add_token_to_request(req)
            self._redirect_resend=r.connection.send(req,**kwargs)
            return self._redirect_resend
        return r

    def _add_token_to_request(self,r):

        # Force the request to POST.  Possible future implicatons here (like if a request only supports GET)
        r.method="POST"

        ### ATTN !!!  Only able to get this to work by adding the token to the URL parameters... not in the body...
        # GOAL was to Add the token to the body (encoded), although when the method is POST and the token is present in the body... the server returns:
        #   {"status":"error","messages":["Unauthorized access. Token not found. You can generate a token using the 'generateToken' operation."],"code":499}
        #r.body=urlencode(self._token) if r.body is None else r.body+urlencode(self._token)

        # For now... Add the token as a URL Query parameter
        r.prepare_url(r.url,self._token)
        return r

    def _get_token(self,token_url):

        # Submit user credentials to acquire security token

        params={}
        params['f']='json'
        params['username']=self.username
        params['password']=self.password
        params['client']="requestip"            # Possible Future TODO - Allow developer to specify a specific IP.  Also... possibly allow developer to specify requested expiration...

        self._last_request=requests.post(token_url,data=urlencode(params),verify=self.verify,headers={"Content-type": "application/x-www-form-urlencoded","Accept": "text/plain"})

        # Possible future TODO -  Handle bad requests (invalid uname/pwd, etc)
        if self._last_request.json().get("error") is not None:
            err=self._last_request.json().get("error")
            raise TokenAuthenticationError("Unable to acquire token; {json}".format(json=str(err)))
        self._token['token']=self._last_request.json().get("token")
        self._expires=datetime.fromtimestamp(self._last_request.json().get("expires")/1000)

    def _get_url_string(self,r,path):

        # Add the path above to the 'instance'.  The Path should can include a preceding '/' (or not)
        #   !!! WARNING !!! Possible that we receive an array index  exception if the path is an empty string...  Possibly add future checks??
        path=path[1:] if path[0] is "/" else path
        up=urlparse(r.url)
        return up.geturl().replace(up.path,"/%s/%s"%(self.instance,path))

    def _derive_instance(self,r):

        # Need to determine the "instance" from the requesting URL, then security posture (info) endpoint.
        # Expected Inputs:
        #   https://host/arcgis
        #   https://host/arcgis/rest
        #   https://host/arcgis/rest/services
        #   https://host:port/*

        # Derive the 'Instance' (normally the first path element).  This is the 'Web-Adaptor' name
        if self.instance is None:
            up=urlparse(r.url)
            self.instance = up.path.split("/")[1]

    def _get_server_security_posture(self,r,auth=None):

        # Query the server 'Info' to determine security posture
        server_info_url=self._get_url_string(r,"/rest/info")

        # Add f=json to parameters if not included in the URL string
        params={"f":"json"} if server_info_url.find("f=json") is -1 else {}
        self._last_request=requests.post(server_info_url,params=params,verify=self.verify,auth=auth)
        if self._last_request.status_code != 200:
            raise TokenAuthenticationError("Unable to acquire token; cannot determine site information at {url}.  HTTP Status Code {sc}".format(url=server_info_url,sc=self._last_request.status_code))

        if not 'authInfo' in self._last_request.json():
            raise TokenAuthenticationError("Unable to acquire token; authInfo JSON Key unavailable at {url}.  HTTP Status Code {sc}".format(url=server_info_url,sc=self._last_request.status_code))

        self._auth_info = self._last_request.json().get('authInfo')


class ArcGISPortalTokenAuth(AuthBase):
    # Esri ArcGIS Portal (and ArcGIS Online) Authentication Handler to be used with the Requests Package

    """Python Requests Authentication Handler for the Esri Portal for ArcGIS product and ArcGIS Online.  This class only supports the vendor proprietary 'Token Based' authentication.

    Args:
        username (:obj:`str`): Username of user authenticating.
        password (:obj:`str`): Password of user authenticating.
        verify (:obj:`bool`, Optional): Verify SSL Certificates (default: True).  Use caution disabiling this (not reccomended for production use)
        instance (:obj:`str`, Optional): - The 'instance' name of the ArcGIS for Server Site (also known as the web-adaptor name).  Code will attempt to derive if not supplied.  ex: 'portal'
    """

    def __init__(self,username,password,verify=True,instance=None):

        # Public Attributes
        self.username=username
        self.password=password
        self.instance=instance                                              # The 'instance' is also the 'web-adaptor' name.  Defaults to 'arcgis'.  Will be derived from the first URL request if not supplied.
        self.verify=verify

        # 'Private' Attributes
        self._token={}
        self._expires=datetime.fromtimestamp(int(time.time())-120)          # Set to 2 min ago
        self._last_request=None
        self._redirect=None                                                 # Only used for debugging... possibly remove?

    def __call__(self,r):

        # type(r) = PreparedRequest

        self._init(r)

        # Check token expiration and generate a new one if needed.  If it expires within 2 min from now (a little padding)
        if (self._expires - datetime.now()).total_seconds() < 120:
            self._get_token(self._get_token_url(r))

        # Handle Re-Directs - See https://github.com/kennethreitz/requests/issues/4040
        r.register_hook('response', self.handle_redirect)

        self._add_token_to_request(r)
        return r

    def _init(self,r):

        # Only execute if after initialized (first request) - Derive Instance (if needed) & Authentication Info

        if self.instance is None:
            self._derive_instance(r)

    def handle_redirect(self, r, **kwargs):

        # Handling Re-Direct!!!  This was necessary because the method (POST) was not persisting on an HTTP 302 re-direct.  See https://github.com/kennethreitz/requests/issues/4040
        # type(r) = Response
        if r.is_redirect:
            self._redirect=r
            req=r.request.copy()
            req.url=r.headers.get("Location")
            self._add_token_to_request(req)
            self._redirect_resend=r.connection.send(req,**kwargs)
            return self._redirect_resend
        return r

    def _add_token_to_request(self,r):

        # Force the request to POST.  Possible future implicatons here (like if a request only supports GET)
        r.method="POST"

        ### ATTN !!!  Only able to get this to work by adding the token to the URL parameters... not in the body...
        # GOAL was to Add the token to the body (encoded), although when the method is POST and the token is present in the body... the server returns:
        #   {"status":"error","messages":["Unauthorized access. Token not found. You can generate a token using the 'generateToken' operation."],"code":499}
        #r.body=urlencode(self._token) if r.body is None else r.body+urlencode(self._token)

        # For now... Add the token as a URL Query parameter
        r.prepare_url(r.url,self._token)
        return r

    def _get_token_url(self,r):
        up=urlparse(r.url)
        return up.geturl().replace(up.path,"/%s%s"%(self.instance,"/sharing/rest/generateToken"))

    def _get_token(self,token_url):
        # print "getting Token"
        # Submit user credentials to acquire security token
        params={}
        params['f']='json'
        params['username']=self.username
        params['password']=self.password
        params['client']="requestip"            # Possible Future TODO - Allow developer to specify a specific IP.  Also... possibly allow developer to specify requested expiration...

        self._last_request=requests.post(token_url,data=urlencode(params),verify=self.verify,headers={"Content-type": "application/x-www-form-urlencoded","Accept": "text/plain"})

        # Possible future TODO -  Handle bad requests (invalid uname/pwd, etc)
        if self._last_request.json().get("error") is not None:
            err=self._last_request.json().get("error")
            raise TokenAuthenticationError("Unable to acquire token; {json}".format(json=str(err)))
        self._token['token']=self._last_request.json().get("token")
        self._expires=datetime.fromtimestamp(self._last_request.json().get("expires")/1000)


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



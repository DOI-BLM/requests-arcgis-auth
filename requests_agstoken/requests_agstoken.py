
import os
from datetime import datetime
import time

# Ideally pull 'requests' from root install location.  If not it has been bundled with the package (bad practice!)
# Maybe follow behind requests... put this in a 'packages' folder and note that these are not for modification??  https://github.com/kennethreitz/requests/tree/master/requests/packages

import requests
from requests.auth import AuthBase

from urllib import urlencode
from urlparse import urlparse
from urlparse import parse_qs

# Need to determine the "instance", then security posture (info) endpoint.
# Expected Inputs:
#   https://host/arcgis
#   https://host/arcgis/rest
#   https://host/arcgis/rest/services
#   https://host:port/*


""" TODOS
    Currently the token will get generated on every request, re-use it!!
    Setup mechanism to re-generate token
    Try to securely pass it (with post in the body)
"""

""" NOTES

    will generate a token using the token URL from the FIRST REQUEST only at this point.
        Meaning the token object will not be able to be re-used between management interfaces (seperate ArcGIS for Server Sites)

"""

class ArcGISServerTokenAuth(AuthBase):
    # Esri ArcGIS for Server Authentication Handler to be used with the Requests Package
    # Need to handle expired tokens (for long running processes like windows services)

    def __init__(self,username,password,verify=True,instance=None):
        self.username=username
        self.password=password
        self.instance=instance
        self.verify=verify

        self._token={}
        self._auth_info=None
        self._expires=datetime.fromtimestamp(int(time.time())-120)          # Set to 2 min ago
        self._last_request=None

    def __call__(self,r):
        # type(r) = PreparedRequest
        print ("!!! CALLED ArcGISServerTokenAuth !!!")

        # Only executte if after initialized (first request)
        if self.instance is None:
            self._derive_instance(r)

        if self._auth_info is None:
            self._get_server_security_posture(r)

        # Possible FUTURE TODO -
        #   What if the server is NOT token Auth??  For now, do not acquire a token and just return the prepared request...
        if not self._auth_info.get("isTokenBasedSecurity"):
            return r

        if (self._expires - datetime.now()).total_seconds() < 0:
            self._get_token(self._auth_info.get("tokenServicesUrl"))

        # force all requests to POST??  To protect the token???

        ### ATTN !!! IT APPEARS THAT THE METHOD AND BODY WILL BE DROPPED ON A RE-DIRECT
        r.method="POST"

        # Add the token to the body (encoded)
        ### ATTN !!!  Only able to get this to work by adding the token to the URL parameters... not in the body...
        r.body=urlencode(self._token) if r.body is None else r.body+urlencode(self._token)
        #r.params=self._token if r.params is None else r.params.update(self._token)
        r.prepare_url(r.url,self._token)

        r.headers.update(self._token)

        # Return the prepared request
        return r

    def _get_token(self,token_url):
        # Submit user credentials to acquire security token
        print ("!!! GETTING TOKEN !!!")
        params={}
        params['f']='json'
        params['username']=self.username
        params['password']=self.password
        params['client']="requestip"            # Possible Future TODO - Allow developer to specify a specific IP.  Also... possibly allow developer to specify requested expiration...

        print "Token URL: "+token_url
        #print "params: "+str(urlencode(params))
        self._last_request=requests.post(token_url,data=urlencode(params),verify=self.verify,headers={"Content-type": "application/x-www-form-urlencoded","Accept": "text/plain"})
        print self._last_request.text

        # Possible future TODO -  Handle bad requests (invalid uname/pwd, etc)
        #   Just ignore the 'expires' key for now... no need for it yet, but could be stored for future use..  On future calls, maybe check the time agains the expires?  then req-acquire?  tabled for now...
        self._token['token']=self._last_request.json().get("token")
        self._expires=datetime.fromtimestamp(self._last_request.json().get("expires")/1000)

    def _get_url_string(self,r,path):

        # Add the path above to the 'instance'.  The Path should can include a preceding '/' (or not)
        #   !!! WARNING !!! Possible that we receive an array index  exception if the path is an empty string...  Possibly add future checks??
        path=path[1:] if path[0] is "/" else path
        up=urlparse(r.url)
        return up.geturl().replace(up.path,"/%s/%s"%(self.instance,path))

    def _derive_instance(self,r):

        # Derive the 'Instance' (normally the first path element).  This is the 'Web-Adaptor' name
        if self.instance is None:
            up=urlparse(r.url)
            self.instance = up.path.split("/")[1]

    def _get_server_security_posture(self,r):

        # Query the server 'Info' to determine security posture
        server_info_url=self._get_url_string(r,"/rest/info")
        self._last_request=requests.post(server_info_url,params={"f":"json"},verify=self.verify)

        # Possible future TODO: Check response before sending back to avoid key error exception??
        self._auth_info = self._last_request.json().get('authInfo')

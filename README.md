# ArcGISServerTokenAuth

**Authentication handler for using Esri ArcGIS for Server Token Authentication with Python Requests**

----------

This module provides a python requests authentication handler for the propriatery Esri ArcGIS for Server Token Authentication.  

Information about the Esri ArcGIS for Server Token authentication can be found at: http://server.arcgis.com/en/server/latest/administer/windows/about-arcgis-tokens.htm

Information on python requests can be found at: http://docs.python-requests.org/en/master/

Usage (Non-Session Based): 
```python
import requests
from requests_agstoken import ArcGISServerTokenAuth
r = requests.get(r'https://host/arcgis/rest/services', auth=ArcGISServerTokenAuth(username,password))
```

Usage (Session Based):
```python
import requests
from requests_agstoken import ArcGISServerTokenAuth
s = requests.Session()
s.auth=ArcGISServerTokenAuth(username,password)
r = s.get(r'https://host/arcgis/rest/services')
```

The authentication handler will acquire a token on the first request to the web-service endpoint.  This token will be added to all future requests to authenticate the request with the credentials supplied.  All requests will be forced to an HTTP POST (even if a get was explicity called).  The handler tracks the token expiration and will re-aqcuire a new token if it has expired (for long running processes).  This handler will also handle HTTP re-directs.  

This was developed and tested using the standard python installation bundled with Esri ArcGIS for Desktop 10.3.1 (2.7.8) and the requests API.  

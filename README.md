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

This module is not complete.  Currently it shows success with acquiring an authentication token to authorize access to the services, but has not been used in a production fashion yet.  The authentication handler will track the token expiration and re-request a token if it has expired.  

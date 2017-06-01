# ArcGISServerTokenAuth

**Authentication handler for using Esri ArcGIS for Server and Portal (ArcGIS Online) Authentication with Python Requests**

----------

This module provides a python requests authentication handler for the propriatery Esri ArcGIS for Server and Portal Token Authentication.  This also supports 'web-tier' authentication using Kerberos or NTLM (Microsoft Integrated Windows Authentication)

Information about the Esri ArcGIS for Server Token authentication can be found at: http://server.arcgis.com/en/server/latest/administer/windows/about-arcgis-tokens.htm

Information about the Esri Portal for ArcGIS Token Authentication can be found at: http://resources.arcgis.com/en/help/arcgis-rest-api/index.html#/Generate_Token/02r3000000m5000000/

Information on python requests can be found at: http://docs.python-requests.org/en/master/


ArcGIS for Server "Token Authentication" Usage (Non-Session Based): 
```python
import requests
from requests_arcgis_auth import ArcGISServerTokenAuth
r = requests.get(r'https://host/arcgis/rest/services?f=json', auth=ArcGISServerTokenAuth(username,password))
```

ArcGIS for Server "Token" Authentication Usage (Session Based):
```python
import requests
from requests_arcgis_auth import ArcGISServerTokenAuth
s = requests.Session()
s.auth=ArcGISServerTokenAuth(username,password)
r = s.get(r'https://host/arcgis/rest/services?f=json')
```

ArcGIS Online and Portal for ArcGIS "Token" Authentication Usage:
```python
import requests
from requests_arcgis_auth import ArcGISPortalTokenAuth
s=requests.Session()
s.auth = ArcGISPortalTokenAuth(username,password)
r = s.get(r'https://host/sharing/rest?f=json')
```

The authentication handler will acquire a token on the first request to the web-service endpoint.  This token will be added to all future requests to authenticate the request with the credentials supplied.  All requests will be forced to an HTTP POST (even if a GET was explicity called).  The handler tracks the token expiration and will re-aqcuire a new token if it has expired (for long running processes).  This handler will also handle HTTP re-directs.  

Leveraging the **ArcGISServerTokenAuth** or **ArcGISPortalTokenAuth** authentication handlers only requires the python requests API.  There are 'general' authentication handlers that will implement Kerberos or NTLM if the server does not support Token Authentication and instead deployed with 'Web-Tier' Authentication using Microsoft Integrated Windows Authentication.  The **ArcGISServerAuth** and **ArcGISPortalAuth** handlers will require requests_kerberos and requests_ntlm to function.  These handlers will first attempt token authentication and in the event of an HTTP status code 401 the handlers will inspect the response headers for Kerberos or NTLM support.  These 'general' authentication handlers in the future may support additional forms of authentication as the need arises and the technology capability exists (i.e. OAuth, Enterprise Logins via SAML)

ArcGIS for Server "Token" or "Web-Tier" Authentication Usage:
```python
from requests_arcgis_auth import ArcGISServerAuth
auth = ArcGISServerAuth(username,password)
```

Portal for ArcGIS "Token" or "Web-Tier" Authentication Usage:
```python
from requests_arcgis_auth import ArcGISPortalAuth
auth = ArcGISPortalAuth(username,password)
```

These 'general' authentcation handlers can also be invoked without a username/password if the underlying site is known to support Kerberos Authentication.  The site, local machine, and user account logged into the machine are all required to be 'trusted' with registered Service Princial Names (SPN's) in the underlying domain for Kerberos single-sign-on to function (without the requirement for a username/password). This implementation approach will inherit the logged in users credentials without having to explicity store the username/password.  

ArcGIS for Server "Kerberos" Authentication Usage:
```python
from requests_arcgis_auth import ArcGISServerAuth
auth = ArcGISServerAuth()
```

Portal for ArcGIS "Kerberos" Authentication Usage:
```python
from requests_arcgis_auth import ArcGISPortalAuth
auth = ArcGISPortalAuth()
```

This was developed and tested using the standard python installation bundled with Esri ArcGIS for Desktop 10.3.1 (2.7.8) and the requests API.  

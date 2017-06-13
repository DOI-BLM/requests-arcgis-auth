# Esri ArcGIS Authentication for Python Requests

**Authentication handler for using Esri ArcGIS for Server and Portal (ArcGIS Online) Authentication with Python Requests**

----------

This module provides python requests authentication handlers for the Esri ArcGIS Server and Portal products. This supports the current deployment models:

* Proprietary Esri ArcGIS for Server and Portal Token Authentication.
* 'Web-tier' authentication using Kerberos or NTLM (Microsoft Integrated Windows Authentication)
* Portal for ArcGIS Enterprise Logins (OAuth2 with SAML)


ArcGIS for Server "Token Authentication" Usage (Non-Session Based): 
```python
import requests
from requests_arcgis_auth import ArcGISServerTokenAuth
r = requests.get(r'https://host/arcgis/rest/services?f=json', auth=ArcGISServerTokenAuth(username,password))
```

ArcGIS Online and Portal for ArcGIS "Token" Authentication Usage:
```python
import requests
from requests_arcgis_auth import ArcGISPortalTokenAuth
s=requests.Session()
s.auth = ArcGISPortalTokenAuth(username,password)
r = s.get(r'https://host/sharing/rest?f=json')
```

ArcGIS Online and Portal for ArcGIS "Enterprise Logins via SAML" Authentication Usage:
```python
import requests
from requests_arcgis_auth import ArcGISPortalSAMLAuth
auth = ArcGISPortalSAMLAuth(client_id)
s = requests.session()
s.auth = auth
s.get("https://org.maps.arcgis.com/sharing/rest/portals/self?f=json")
```

More information and examples can be found on the WIKI Pages - https://github.com/DOI-BLM/requests-arcgis-auth/wiki

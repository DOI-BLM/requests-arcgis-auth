# ArcGISServerTokenAuth

**Authentication handler for using Esri ArcGIS for Server Token Authentication with Python Requests**


----------

This module provides a python requests authentication handler for the propriatery Esri ArcGIS for Server Token Authentication.  

Information about the Esri ArcGIS for Server Token authentication can be found at: http://server.arcgis.com/en/server/latest/administer/windows/about-arcgis-tokens.htm

Information on python requests can be found at: http://docs.python-requests.org/en/master/

Usage: 
```python
from requests_agstoken import ArcGISServerTokenAuth
r=requests.get(r'https://host/arcgis/rest/services',auth=ArcGISServerTokenAuth(username,password))
```

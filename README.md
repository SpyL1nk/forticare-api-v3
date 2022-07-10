# FortiCare APIv3

## Introduction

This is a quick PoC used to connect to FortiCare API and retrieve assets.

Technical information can be found on this KB : https://community.fortinet.com/t5/FortiCloud-Products/Technical-Tip-API-how-to-retrieve-list-of-registered-units-for/ta-p/194760

Full API documentation can be found on the Fortinet Developer Network (FNDN) : https://fndn.fortinet.net/index.php?/fortiapi/55-forticare-registration/ (requires an account)

This scripts currently extract "all" assets available on the tenant and save it into a file named `assets.csv` in the working directory.

It can be modified to get more details on a specific product, register licence or even decomission a product.

## Configuration file

The configuration file must be name `.forticare` in the working directory for now.
It contains two section :
- forticare :
    - url : URL of the FortiCare service, should be `https://support.fortinet.com/ES/api/registration/v3/`
    - client_id : Define the scope to use for this OAuth token;
    - api_id : IAM API ID generated;
    - api_password : IAM API private token;
- customerauth :
    - url : URL of the FortiAuthenticator used to deliver OAuth tokens for some (all ?) the Fortinet cloud solutions. Should be `https://customerapiauth.fortinet.com/api/v1/oauth/`;

```INI
[forticare]
url = https://support.fortinet.com/ES/api/registration/v3/
client_id = assetmanagement
api_id = 12345678-90AB-CDEF-IJKL-MNOPQRSTVWXY
api_password = xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

[customerauth]
url = https://customerapiauth.fortinet.com/api/v1/oauth/
```

## Usage

For now, no options are available, usage is simple :

```
python3 forticare_automation.py
```
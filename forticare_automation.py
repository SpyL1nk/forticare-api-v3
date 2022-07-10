  
#!/usr/bin/env python3

# Copyright 2022 Alexandre Moreau <a.moreau@spyl1nk.net>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import requests
import json
import configparser
import logging
import os
import re
import sys
from optparse import OptionParser

def init_logging():
    """Initialize and return an Logger object.

    Returns
    -------
        logger: logger
            The logger object.
    """
    global logger

    prog = os.path.basename(sys.argv[0])

    # create logger
    logger = logging.getLogger(prog)
    logger.setLevel(logging.DEBUG)

    # create console handler and set level to debug
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )

    # add formatter to ch
    ch.setFormatter(formatter)

    # add ch to logger
    logger.addHandler(ch)

    return logger


def init_forticare(file=".forticare"):
    """Retrieve FortiCare API credentials from the configuration file.
    Parameters
    ----------
    file: str
        The config file in INI format (default to .forticare)

    Returns
    -------
    forticare_url: str
        The FortiCare URL.
    forticare_client_id: str
        The FortiCare Client ID.
    forticare_api_id: str
        The FortiCare API ID.
    foricare_api_password: str
        The FortiCare API Password.
    customerauth_url: str
        The CustomerAuth URL.
    """
    config = configparser.ConfigParser()
    config.read(file)
    section = "forticare"

    # FortiCare API Version 3 uses two URL :
    # 1/ https://customerapiauth.fortinet.com/api/v1/oauth/ : For the authentication
    # 2/ https://support.fortinet.com/ES/api/registration/v3/ : For the FortiCare API Calls

    try:
        forticare_url           = config[section]["url"]
        forticare_client_id     = config[section]["client_id"]
        forticare_api_id        = config[section]["api_id"]
        forticare_api_password  = config[section]["api_password"]
    except KeyError as k:
        logger.error('Missing key {} in configuration file "{}"'.format(k, file))
        quit()

    section = "customerauth"

    try:
        customerauth_url           = config[section]["url"]
    except KeyError as k:
        logger.error('Missing key {} in configuration file "{}"'.format(k, file))
        quit()

    logger.debug(f"FortiCare URL: {forticare_url}, FortiCare Client ID: {forticare_client_id}, \
        FortiCare API ID: {forticare_api_id}, FortiCare API Password: {forticare_api_password}, \
        CustomerAuth URL: {customerauth_url}")

    return forticare_url, forticare_client_id, forticare_api_id, forticare_api_password, customerauth_url


def forticare_login(customerauth_url, forticare_client_id, forticare_api_id, forticare_api_password):
    """Login to the CustomerAuth API (FortiAuthenticator OAuth) using IAM API User

    Parameters
    ----------
    forticare_client_id: str
        The FortiCare Client ID.
    forticare_api_id: str
        The FortiCare API ID.
    foricare_api_password: str
        The FortiCare API Password.
    customerauth_url: str
        The CustomerAuth URL.

    Returns
    -------
    forticare_bearer_token: str
        The FortiCare Bearer token.
    forticare_refresh_token: str
        The FortiCare Bearer's refresh token.
    """

    json_payload = {
        "username": forticare_api_id,
        "password": forticare_api_password,
        "client_id": forticare_client_id,
        "grant_type": "password"
    }

    logger.debug("Payload to post is:")
    logger.debug(json.dumps(json_payload, indent=4))

    url = customerauth_url + "token/"
    r = requests.post(url=url, json=json_payload)

    logger.debug('FortiCare login operation terminated with "%s"' % r.json()["message"])
    logger.debug("JSON output is:")
    logger.debug(json.dumps(r.json(), indent=4))

    return r.json()["access_token"], r.json()["refresh_token"]


def forticare_list_assets(forticare_url, forticare_bearer_token):
    """Retrieve assets from FortiCare API

    Parameters
    ----------
    forticare_url: str
        The FortiCare URL.
    forticare_bearer_token: str
         The FortiCare Bearer token.

    Returns
    -------
    assets_list: list
        A list containing assets.
    """

    header = {'Authorization': 'Bearer ' + forticare_bearer_token}
    # FortiCare, as of today, doesn't offer any way to get all assets by default.
    # It must be filtered per Serial Number or expiry date. So we are using a really
    # far date to get all the assets.
    json_payload = {
        "expireBefore": "2040-01-01T00:00:00+0:00"
    }

    logger.debug("Payload to post is:")
    logger.debug(json.dumps(json_payload, indent=4))

    url = forticare_url + "products/list"
    r = requests.post(url=url, json=json_payload, headers=header)

    logger.debug('FortiCare assets operation terminated with "%s"' % r.json()["message"])
    logger.debug("JSON output is:")
    logger.debug(json.dumps(r.json(), indent=4))

    return r.json()['assets']

if __name__ == "__main__":

    init_logging()

    forticare_url, forticare_client_id, forticare_api_id, forticare_api_password, customerauth_url = init_forticare()


    forticare_bearer_token, forticare_refresh_token = forticare_login(customerauth_url, forticare_client_id, forticare_api_id, forticare_api_password)

    assests_list = forticare_list_assets(forticare_url, forticare_bearer_token)

    with open('assets.json', 'w', encoding='utf-8') as f:
        json.dump(assests_list, f, ensure_ascii=False, indent=4)


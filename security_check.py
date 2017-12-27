import requests
from datetime import datetime as dtg
import json
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('security_checker')
logger.debug(str(dtg.now()) + ': check started')


def get_cmdb_data(device_type):
    """
    Get data from observium database based on the device_type

    Should return dictionary of:
    ID, Hostname, OS_Version

    :return: dict
    """
    pass


def psirt_get_token():
    """
    get an access token

    TODO: Need to add a tracking file for timeframe of the token
          This will keep the app from calling a new token if the
          current token is still valid

    TODO: Add exception handling

    :return:
    """
    creds = json.load(open('creds.json'))
    psirt_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    psirt_payload = {
        'client_id': creds['CLIENT_ID'],
        'client_secret': creds['CLIENT_SECRET'],
        'grant_type': 'client_credentials'
    }
    url = 'https://cloudsso.cisco.com/as/token.oauth2'
    response = requests.post(url=url, data=psirt_payload, headers=psirt_headers).json()
    logger.debug('access_token_check = ' + response['access_token'])
    return response['access_token']

def psirt_query(token):
    """
    Send required information to PSIRT API and return true if vulnerable?

    {"access_token":"blablablablabla","token_type":"Bearer","expires_in":3599}

    TODO: Add exception handling

    :return: bool
    """
    url = 'https://api.cisco.com/security/advisories/cvrf/latest/10'
    headers = {
        'Accept': 'application/json',
        'Authorization': 'Bearer ' + token,
    }
    last_10_vulns = requests.get(url, headers=headers)
    logger.info('query response code = ' + str(last_10_vulns.status_code))
    logger.debug(last_10_vulns)


def junos_cve_query(version):
    """
    not sure about this one, prolly the same kind of deal as PSIRT, but for Junos

    :return: bool
    """
    pass

def update_vluln_table():
    """
    Do you want to track this in another DB or just have a report?

    add Date, CMDB_ID, Hostname, is_vuln=True
    :return:
    """

def create_vuln_report():
    """
    Create Vulnerability report based on data pulled from APIs

    :return html
    """

psirt_query(psirt_get_token())

import requests
from datetime import datetime as dtg
import json
import logging
import sys

logging.basicConfig(level=logging.DEBUG, filename='/opt/sec_check/test1.txt')
logger = logging.getLogger('security_checker')

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

def call_api(url):
    try:
        r = requests.get(url)
    except requests.exceptions.RequestException as e:
        logger.error('API CALL ERROR: {}'.format(e))
        return None
    if r.status_code != 200:
        return None
    else:
        return r.json()


def show_vendor_product():
    """
    Show a specific product for a vendor
    # TODO: Needs input validation
    """
    vendor = input("Enter the Vendor: ")
    product = input("Enter the product: ")
    filter_string = input("Enter Optional Search string (i.e. HTTP): ")
    logger.debug("Searching: {} from {} -- Filter = {}".format(product, vendor, filter_string))
    search_url = "http://cve.circl.lu/api/search/{}/{}".format(vendor, product)
    req = call_api(search_url)
    if not req:
        logger.debug("something no workie with the vendor product call")
    else:
        print("Searching: {} from {} -- Filter = {}".format(product, vendor, filter_string))
        for item in req:
            if filter_string != '' or not filter_string:
                if filter_string in item['summary']:
                    print("\nSummary: " + item['summary'])
                    print("CVE: " + item['id'])
                    print("CVSS: " + str(item['cvss']))
            else:
                print("\nSummary: " + item['summary'])
                print("CVE: " + item['id'])
                print("CVSS: " + str(item['cvss']))
    menu()


def menu():
    options = [sys.exit, show_vendor_product]
    print("Which would you like to do \n\t 1) Show Vulnerabilities by Vendor/Product \n\t0) Exit")
    response = input(": ")
    options[int(response)]()


if __name__ == "__main__":
    menu()


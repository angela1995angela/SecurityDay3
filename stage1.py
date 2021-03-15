#!/usr/bin/env python

import env
import requests
import json
import sys
from pathlib import Path
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from pprint import pprint
import datetime

here = Path(__file__).parent.absolute()
repository_root = (here / "..").resolve()
sys.path.insert(0, str(repository_root))


inv_url = env.UMBRELLA.get("inv_url")
inv_token = env.UMBRELLA.get("inv_token")
en_url = env.UMBRELLA.get('en_url')
en_key = env.UMBRELLA.get('en_key')
#Use a domain of your choice
domain = input("type the URL you want to check its status: ")

#Construct the API request to the Umbrella Investigate API to query for the status of the domain
url = f"{inv_url}/domains/categorization/{domain}?showLabels"
headers = {"Authorization": f'Bearer {inv_token}'}
response = requests.get(url, headers=headers)
response.raise_for_status()

today = datetime.datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
#print(today)
#And don't forget to check for errors that may have occured!
if response.status_code != 200:
    print('An error occured with error code', response.status_code)


#Make sure the right data in the correct format is chosen, you can use print statements to debug your code
domain_status = response.json()[domain]["status"]

if domain_status == 1:
    print(f"The domain {domain} is found CLEAN")
elif domain_status == -1:
    print(f"The domain {domain} is found MALICIOUS")
elif domain_status == 0:
    print(f"The domain {domain} is found UNDEFINED")

print("This is how the response data from Umbrella Investigate looks like: \n")
pprint(response.json(), indent=4)

#Add another call here, where you check the historical data for either the domain from the intro or your own domain and print it out in a readable format
timeline_url = f"{inv_url}/timeline/{domain}"
resp = requests.get(timeline_url, headers=headers)
data = resp.json()
print('\n\n')
print('This shows the historical data for the URL: ')
pprint(data, indent=3)

#Block url if malicious
if domain_status == -1:
    block_url = f"{en_url}/events?customerKey={en_key}"
    headers = {"Content-Type": "application/json"}
    payload = {
        "deviceId": "ba6a59f4-e692-4724-ba36-c28132c761de",
        "deviceVersion": "13.7a",
        "eventTime": f"{today}",
        "alertTime": f"{today}",
        "dstDomain": f"www.{domain}",
        "dstUrl": f"http://{domain}",
        "protocolVersion": "1.0a",
        "providerName": "Security Platform"
    }
    block_response = requests.post(block_url, headers=headers, json=payload)
    block = block_response.json()
    print(block)


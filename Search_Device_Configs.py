#!/usr/bin/env python
# Import Requests to get the webpage from DNA Center
import requests
# Import HTTPBasicAuth to authenticate to DNA Center
from requests.auth import HTTPBasicAuth
# Bypass certificate warnings
import requests.packages.urllib3.exceptions
from urllib3.exceptions import InsecureRequestWarning
# Import json to return the results from the get request in a json format
import json
import difflib
# This is used to write the results to a csv file.
import csv
# This allows the csv filename to include the timestamp
import datetime as dt
import time
# time.sleep(10) pauses for 10 seconds
# This enables encoding the username and password to receive a token from DNA Center
import base64
# Today's date
currentDate = dt.datetime.today().strftime('%m-%d-%Y-%Hh-%Mm-%Ss')
# Suppress Insecure Requests Warnings for self-signed certificate on DNA Center
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
# Specify the DNA Center Server
# dnacServer = "172.21.21.10"
# Prompt the user for the DNA Center Server
dnacServer = input('Enter DNA Center Server IP Address:\n')
# Specify the URL to create a token
tokenURL = "https://" + dnacServer + "/dna/system/api/v1/auth/token"
# Username and password used to create the token
myUserName = input('Username:\n')
myPassword = input('Password:\n')
# myUserName = "admin"
# myPassword = "Cisco123"
myUserPass = myUserName + ":" + myPassword
# print(myUserPass)

# Encode the username and password to submit as a header when creating the token
encodedUserPass = str(base64.b64encode(bytes(myUserPass, "utf-8")))
encodedLength = len(encodedUserPass) - 1
encodedUserPass = encodedUserPass[2:encodedLength]
encodedUserPass = "Basic " + encodedUserPass

# Create the header used to create the token
headers = {
    'Authorization': encodedUserPass
}
# Create the token
myTokenResponse = requests.post(tokenURL, headers=headers, verify=False)
myTokenDict = myTokenResponse.json()
# Creating a token returns a Dictionary where the attribute is Token and the value is the actual token
myToken = myTokenDict['Token']

payload = {}
headers = {
    'X-Auth-Token': myToken,
    'Authorization': encodedUserPass
}

# URL for API
# Get device count for pagination
url = "https://" + dnacServer + "/dna/intent/api/v1/network-device/config/count"
response = requests.get(url, headers=headers, data=payload, verify=False)
json_object = json.loads(response.text)
deviceCount = json_object['response']

print("Number of network devices found: " + str(deviceCount))
offset = 1
limit = 20

responseDict = []
deviceList = []

while offset <= deviceCount:
    url = "https://" + dnacServer + "/dna/intent/api/v1/network-device/config?limit=20&offset=" + str(offset)
    response = requests.get(url, headers=headers, data=payload, verify=False)
    json_object = json.loads(response.text)
    responseDict.extend(json_object['response'])
    json_object = {}
    offset += limit

# Search for string in device configuration
print('Utilize Cisco DNA Center to search for specific device configurations!')
searchString = input('Enter search string: ')

for listItem in responseDict:
    if "\nhostname" in listItem['runningConfig']:
        if searchString in listItem['runningConfig']:
            hostname = listItem['runningConfig'].split("\nhostname ", 1)[1].split("\n")[0]
            print(searchString + " was found in " + hostname)
            deviceList.append(hostname)

print(deviceList)
# Delete Comment to write results to a file
# with open('Device_List_{}.csv'.format(currentDate), 'w') as csv_file:
#    writer = csv.writer(csv_file)
#    writer.writerows([deviceList])

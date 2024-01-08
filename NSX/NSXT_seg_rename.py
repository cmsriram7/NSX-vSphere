# encoding: utf-8

import argparse
import sys
import ssl
import requests
import getpass
import base64
import xmltodict
import re
import json
import dicttoxml
import urllib3
urllib3.disable_warnings()

def encode_b64(strng):
    strng = strng.encode("utf-8")
    b64_val = base64.b64encode(strng)
    b64_val = b64_val.decode()
    
    return b64_val

def send_request(req_type, hostname, endpoint, username, password, data):
    url = "https://{}{}".format(hostname, endpoint)
    usrPass = "{}:{}".format(username, password)
    b64_val = encode_b64(usrPass)
    headers = {"Authorization" : "Basic %s" % b64_val, 'Content-Type': 'application/json'}
    try:
        if req_type == 'get':
            resp = requests.get(url, headers=headers, verify=False)
            
        elif req_type == 'put':
            resp = requests.put(url, data=json.dumps(data), headers=headers, verify=False)
            
        elif req_type == 'post':
            resp = requests.post(url, data=data, headers=headers, verify=False)
        
        elif req_type == 'delete':
            resp = requests.delete(url, headers=headers, verify=False)
        
        elif req_type == 'patch':
            resp = requests.patch(url, headers=headers, data=json.dumps(data), verify=False)
        else:
            print("Unknown method")
            
        if (resp.status_code == 200) or (resp.status_code == 204):
            return resp.text
        else:
            return False
    except requests.exceptions.ConnectTimeout:
        print("Connection timed out, please check the IP Address")
        sys.exit(1)
    except:
        print("Unable to execute the API requests")
        
                                             
def nsxt_segment_rename(nsxt_host, uname, password):
    try:
        url = "https://{}{}".format(nsxt_host, "/api/v1/infra/segments")
        usrPass = "{}:{}".format(uname, password)
        b64_val = encode_b64(usrPass)
        headers = {"Authorization" : "Basic %s" % b64_val, "Accept": "*/*"}
        resp = requests.get(url, headers=headers, verify=False)
        jvar = "{}".format(resp.text)
        jdict = json.loads(jvar)
    
        if "results" not in jdict.keys():
            print("Got wrong response from server, please check your credentials")
            return
        for elem in jdict['results']:
            #print(elem)
            if 'L2E_' in elem['display_name']:
                
                elem['display_name'] = elem['display_name'].replace('L2E_', '')
                id = elem['id']
                print("Removing the L2E_ prefix and renaming the segment: {}".format(id))
                elem['id'] = id.replace('L2E_', '')
                ep = "/api/v1/infra/segments/" + id + "?force=true"
                resp = send_request("patch", nsxt_host, ep, uname, password, data=elem)
    except:
        print("Unable to execute the API requests on the segments")
        print(sys.exc_info())
    print("Successfully renamed all segments removing the unwanted L2E_ prefixes")        
        
def enable_base64(hostname, username, password):
    base64_enable_json = """
<auth>
  <username>{}</username>
  <password>{}</password>
  <disableBasicAuth>false</disableBasicAuth>
</auth>
""".format(username, password)
    resp = send_request("put", hostname, "/api/2.0/services/auth/basic", username, password, base64_enable_json)

    b64_enabled = True

if __name__ == '__main__':

    while True:
        try:
            nsxt_host = input("Enter the NSXT manager hostname or IP: ")
            nsxt_user = input("Enter NSX Manager Username: ")
            nsxt_pass = getpass.getpass("Enter NSX Manager Password: ")
            enable_base64(nsxt_host, nsxt_user, nsxt_pass)
            nsxt_segment_rename(nsxt_host, nsxt_user, nsxt_pass)
            to_quit = input("Enter q to quit or press any key to continue: ")
            if to_quit == "q":
                break
        except KeyboardInterrupt:
            print("\n User interrupted the script ")
            sys.exit(1) 
      

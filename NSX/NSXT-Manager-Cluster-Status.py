# encoding: utf-8
import paramiko
import ssl
import argparse
import sys
sys.path.append("/opt/vmware/sddc-support/dependency/pyVpx/")
import time
import ssl
import requests
import getpass
import base64
import xmltodict
import re
import json
import dicttoxml
import pprint
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
    headers = {"Authorization" : "Basic %s" % b64_val, 'Content-Type': 'application/xml'}
    try:
        if req_type == 'get':
            resp = requests.get(url, headers=headers, verify=False)
            
        elif req_type == 'put':
            resp = requests.put(url, data=data, headers=headers, verify=False)
            
        elif req_type == 'post':
            resp = requests.post(url, data=data, headers=headers, verify=False)
        
        elif req_type == 'delete':
            resp = requests.delete(url, headers=headers, verify=False)
        
        else:
            print("Unknown method")
            
        if (resp.status_code == 200) or (resp.status_code == 204):
            return resp.text
        else:
            return False
    except:
        print("unable to execute the API requests")
        print(sys.exc_info())
                                             
def nsxt_manager_cluster(nsxt_host, uname, password):
    resp = send_request("get", nsxt_host, "/api/v1/cluster/status", uname, password, data=None)
    jvar = "{}".format(resp)
    jdict = json.loads(jvar)
    # pprint.pprint(jdict)
    overall_status = jdict['mgmt_cluster_status']
    groups = [x for x in jdict['detailed_cluster_status']['groups'] if x['group_type'] == 'DATASTORE']
    group_type = groups[0]['group_type']
    group_status = groups[0]['group_status']
    group_members = groups[0]['members']
    print("Outputting the overall details of the management cluster") 
    pprint.pprint(overall_status)
    print("Outputting the overall details of the datastore cluster")
    print(group_type, group_status)
    pprint.pprint(group_members)
    
    # for e in jdict.items():
        # value = {}
        # if e[0] == 'detailed_cluster_status':
            # value = e[1]
        # if "groups" in value.keys():
            # for elem in value['groups']:
                # grp_type.append(elem['group_type'])
                # grp_status.append(elem['group_status'])
    # print(grp_type)
    # print(grp_status)
        
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
            
            nsxt_manager_cluster(nsxt_host, nsxt_user, nsxt_pass)
            to_quit = input("Enter q to quit or press any key to continue: ")
            if to_quit == "q":
                break
        except KeyboardInterrupt:
            print("\n User interrupted the script ")
            sys.exit(1) 
      

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
                                             
def nsxt_backup_status(nsxt_host, uname, password):
    resp = send_request("get", nsxt_host, "/api/v1/cluster/backups/status", uname, password, data=None)
    jvar = "{}".format(resp)
    jdict = json.loads(jvar)
    
    if jdict['operation_type'] == "none":
        print("There are no backups in progress.Good to proceed with Upgrades")
        return True
    elif jdict['operation_type'] == "backup":
        print("Backups are in progress, halt for Upgrades")
        return False
            
def nsxt_backup_history(nsxt_host, uname, password):
    resp = send_request("get", nsxt_host, "/api/v1/cluster/backups/history", uname, password, data=None)
    jvar = "{}".format(resp)
    jdict = json.loads(jvar)
    #pprint.pprint(jdict)
    if ('success' in jdict['cluster_backup_statuses'][0].keys()) and ('success' in jdict['node_backup_statuses'][0].keys()) and ('success' in jdict['inventory_backup_statuses'][0].keys()):
        if jdict['cluster_backup_statuses'][0]['success'] == True and jdict['node_backup_statuses'][0]['success'] == True and jdict['inventory_backup_statuses'][0]['success'] == True:
            print("Backups are successful and its good to proceed with upgrades")    
    
def nsxt_restore(nsxt_host, uname, password):
    resp = send_request("get", nsxt_host, "/api/v1/cluster/restore/status", uname, password, data=None)
    jvar = "{}".format(resp)
    jdict = json.loads(jvar)
    str = "Restore process didn't yet start"
    if str in jdict['status']['description']:
        print("There is no restore process in progress. Can proceed for upgrades")
    
    
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
            backup_taken = nsxt_backup_status(nsxt_host, nsxt_user, nsxt_pass)
            if backup_taken:
                print("Backups are done, user can proceed for Upgrades")
            nsxt_backup_history(nsxt_host, nsxt_user, nsxt_pass)
            nsxt_restore(nsxt_host, nsxt_user, nsxt_pass)
            to_quit = input("Enter q to quit or press any key to continue: ")
            if to_quit == "q":
                break
        except KeyboardInterrupt:
            print("\n User interrupted the script ")
            sys.exit(1) 
      

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
        print("Connection timed out, please enter the correct IP Address or FQDN of the NSXT manager")
        sys.exit(1)
    except:
        print("Unable to execute the API requests")
        
                                             
def create_t1(nsxt_host, uname, password):
    
          
    # overall_status = jdict['mgmt_cluster_status']
    # groups = [x for x in jdict['detailed_cluster_status']['groups'] if x['group_type'] == 'DATASTORE']
    # group_type = groups[0]['group_type']
    # group_status = groups[0]['group_status']
    # group_members = groups[0]['members']
    # print("Outputting the overall details of the management cluster") 
    # pprint.pprint(overall_status)
    # print("Outputting the overall details of the datastore cluster")
    # print(group_type, group_status)
    # pprint.pprint(group_members)
    
    # # for e in jdict.items():
        # # value = {}
        # # if e[0] == 'detailed_cluster_status':
            # # value = e[1]
        # # if "groups" in value.keys():
            # # for elem in value['groups']:
                # # grp_type.append(elem['group_type'])
                # # grp_status.append(elem['group_status'])
    # # print(grp_type)
    # # print(grp_status)


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

def nsxv_ls_details(hostname, username, password):
    resp = send_request("get", hostname, "/api/4.0/edges", username, password, data=None)
    if resp:
        config = xmltodict.parse(resp)  
    edges = config["pagedEdgeList"]["edgePage"]["edgeSummary"]
    if isinstance(edges,list):
        #ESGs interface information is collecting.
        for edge_details in edges:
            id = edge_details["objectId"]
            edge_resp = send_request("get", hostname, "/api/4.0/edges/{}".format(id), username, password, data=None)
            if resp:
                edge_config = xmltodict.parse(edge_resp)
                if edge_details["edgeType"]=="distributedRouter":
                    Interfaces = edge_config["edge"]["interfaces"]["interface"]
                    for interface in Interfaces:
                        if interface["isConnected"] =="true":
                            interface_name = interface["name"]
                            interface_type = interface["type"]
                            interface_ipaddress = interface["addressGroups"]["addressGroup"]["primaryAddress"]
                            interface_subnet= interface["addressGroups"]["addressGroup"]["subnetPrefixLength"]
                            interface_connected_to = interface["connectedToName"]
                            edge_virtualwire_resp = send_request("get", hostname, "/api/2.0/vdn/virtualwires".format(id), username, password, data=None)
                            if edge_virtualwire_resp:
                                edge_virualwire_config = xmltodict.parse(edge_virtualwire_resp)
                                virtual_wires = edge_virualwire_config["virtualWires"]["dataPage"]["virtualWire"]
                                for virtual_wire in virtual_wires:
                                    virtual_wire_name = virtual_wire["name"]
                                    if interface_name == virtual_wire_name:
                                        vdn_id = virtual_wire["vdnId"]
                                        #migrate_VWtoNSXT(interface_ipaddress,interface_subnet,vdn_id)
    
    return  interface_ipaddress,interface_subnet,vdn_id  

def migrate_ls_nsxt(nsxt_host, uname, password,interface_ipaddress,interface_subnet,vdn_id):
    try:
        seg_name = input("Enter the name of the nsxt segment to be created :")
        jvar = """{
\"display_name\":\"%s\",
\"id\": \"%s\",
\"subnets\": [
      {
        \"gateway_address\": \"%s/%s\"
      }
    ],
    \"connectivity_path\": \"/infra/tier-1s/vc-t1\"
}""" % (seg_name, vdn_id, interface_ipaddress, interface_subnet)
    
        #jdict = json.loads(jvar)
        ep = "/policy/api/v1/infra/segments/" + id + "?force=true"
        resp = send_request("patch", nsxt_host, ep, uname, password, data=jvar)
    except:
        print("Unable to execute the API requests on the segments")
        print(sys.exc_info())    
              
if __name__ == '__main__':

    while True:
        try:
            # nsxt_host = input("Enter the NSXT manager hostname or IP: ")
            # nsxt_user = input("Enter NSX Manager Username: ")
            # nsxt_pass = getpass.getpass("Enter NSX Manager Password: ")
            nsxt_host = "10.10.11.15"
            nsxt_user = "admin"
            nsxt_pass = "NFVra02@km123"
            enable_base64(nsxt_host, nsxt_user, nsxt_pass)
            interface_ipaddress,interface_subnet,vdn_id = nsxv_ls_details("192.168.120.13","admin","VMware123!")
            #nsxt_segment(nsxt_host, nsxt_user, nsxt_pass)
            to_quit = input("Enter q to quit or press any key to continue: ")
            if to_quit == "q":
                break
        except KeyboardInterrupt:
            print("\n User interrupted the script ")
            sys.exit(1) 
      

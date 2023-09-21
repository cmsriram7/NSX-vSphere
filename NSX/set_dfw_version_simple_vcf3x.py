# encoding: utf-8
import paramiko
import ssl
import argparse
import sys
import time
import ssl
from pyVim.connect import SmartConnect
import getpass
import requests
import json
import pprint
import urllib3
import base64
urllib3.disable_warnings()

def get_ssh_connection(host, username, password):
    client = paramiko.client.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, 22, username=username, password=password)
    except:
        print("Unable to connect to remote machine")
        return False

    return client

def encode_b64(strng):
    strng = strng.encode("utf-8")
    b64_val = base64.b64encode(strng)
    b64_val = b64_val.decode()
    
    return b64_val
    
def get_creds(host, username, password, priv_user, priv_pwd):
    url = "https://{}/v1/credentials".format(host)
    auth_str = "{}:{}".format(username, password)
    auth_str = encode_b64(auth_str)
    
    headers = {'Content-Type' : 'application/json', 'Accept' : 'application/json', "Authorization" : "Basic {}".format(auth_str), "privileged-username" : priv_user,
        "privileged-password" : priv_pwd}
    try:
        resp = requests.get(url, headers=headers, verify=False)
        config = json.loads(resp.text)
        elems = config['elements']
        creds = {}
        for elem in elems:
            if elem['resource']['resourceType'] == 'ESXI':
                username = elem['username']
                password = elem['password']
                name = elem['resource']['resourceName']
                creds[name] = {'username': username, 'password': password}
    except:
        print("Unable to login into SDDC Manager")
        print(sys.exc_info())
        return False

    return creds

def login_to_vc(host, user, pwd):
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ssl_context.verify_mode = ssl.CERT_NONE
    try:
        si = SmartConnect(host=host, user=user, pwd=pwd,
                              sslContext=ssl_context)
    except:
        if "Cannot complete login due to an incorrect user name or password" in str(sys.exc_info()):
            print("Unable to login to VC because of wrong credentials")
        print("Unable to login into VC")
        return None

    return si
    
def enable_ssh(host_system):
    # host_system = get_obj(content, [vim.HostSystem], None)
    service_system = host_system.configManager.serviceSystem
    ssh_service = [x for x in service_system.serviceInfo.service if x.key == 'TSM-SSH'][0]
    if not ssh_service.running:
        service_system.Start(ssh_service.key)
    if ssh_service.running:
        print("SSH Service is running")
    else:
        print("SSH Service is not running")

def set_dfw_version(vc_ip, vc_username, vc_password, creds):
        print("Logging into {}".format(vc_ip))
        si = login_to_vc(vc_ip, vc_username, vc_password)
        if si == None:
            return False
        content = si.RetrieveContent()
        children = content.rootFolder.childEntity
        for child in children:
            datacenter = child
            clusters = datacenter.hostFolder.childEntity
            print("Clusters in the host:")
            cls_dct = {}
            for sn, cluster in enumerate(clusters, start=1):
                cls_dct[sn] = cluster
                print(sn, cluster.name)
            
            cluster_num = int(input("Enter the cluster number: "))
            sel_cls = cls_dct[cluster_num]
            
            hosts = sel_cls.host    
            host_dict = {}
                
            for host in hosts:
                host_dict[host.name] = host
            
            hosts = [x.name for x in hosts]
                    
            for host in hosts:   
                print("Connecting to host ", host)
                enable_ssh(host_dict[host])
                username = creds[host]['username']
                password = creds[host]['password']
                client = get_ssh_connection(host, username=username, password=password)
                try:
                    cmd = "vsipioctl getfilters | grep \"Filter Name\" | grep \"sfw.2\""
                    stdin, stdout, stderr = client.exec_command(cmd)
                    output = stdout.read().decode()
                    
                    nics = output.split("\n")
                    
                    nics = [x for x in nics if x != '']
                    nics = [x.split(":")[1].strip() for x in nics]
                    
                    print("Host {} has {} vNICS with dfw enabled ".format(host, len(nics)))
                    
                    for nic in nics:
                        time.sleep(3)  
                        cmd = "vsipioctl getexportversion -f {}".format(nic)
                        stdin, stdout, stderr = client.exec_command(cmd)
                        cur_version = stdout.read().decode()
                        cur_version = int(cur_version.split(" ")[-1])
                        print("Current version is: {}".format(cur_version))
                        if cur_version == 1000:
                            print("No action needed from the script side")
                            continue
                        #print("Current version is: {}".format(cur_version))
                        cmd = "vsipioctl setexportversion -f {} -e 1000".format(nic)
                        stdin, stdout, stderr = client.exec_command(cmd)
                        output = stdout.read().decode()
                        
                        cmd = "vsipioctl getexportversion -f {}".format(nic)
                        stdin, stdout, stderr = client.exec_command(cmd)
                        updated_version = stdout.read().decode()
                        print("Updated version is: {}".format(updated_version))
                      
                except:
                    print("Execution of command failed")
                    print(sys.exc_info())
                    
            return True

if __name__ == '__main__':
    ans = input("This Script sets the dfw expot version.Are you sure you want to execute it: ")
    ans = ans.lower()
    if (ans == "no") or (ans == "n"):
        sys.exit(1)    
    sddc_m_hostname = input("Enter SDDC Manager hostname: ")
    sddc_m_username = input("Enter SDDC Manager username: ")
    sddc_m_password = getpass.getpass("Enter SDDC Manager password: ")
    sddc_priv_user = input("Enter SDDC priv username: ")
    sddc_priv_pwd = getpass.getpass("Enter SDDC priv user password: ")
    print("Getting credentials of hosts from SDDC Manager")

    creds = get_creds(sddc_m_hostname, sddc_m_username, sddc_m_password, sddc_priv_user, sddc_priv_pwd)
    
    if not creds:
        print("Unable to get credentials from SDDC Manager")
        sys.exit(1)
    
    vcenters = []
           
    while True:
        if len(vcenters) != 0:
            for vc in vcenters:      
                vc_ip = vc['vcenter_ip']
                vc_username = vc['vcenter_user']
                vc_password = vc['vcenter_pass']

                result = set_dfw_version(vc_ip, vc_username, vc_password, creds)
        else:
            try:
                vc_ip = input("Enter VCenter IP or FQDN (or 'q' to quit): ")
                if vc_ip == 'q':
                    break

                vc_username = input("Enter VC Username: ")
                vc_password = getpass.getpass("Enter VC Password: ")
                result = set_dfw_version(vc_ip, vc_username, vc_password, creds)
            except:
                print("\nUser interrupted the flow")
                print(sys.exc_info())
                sys.exit(1)
        if result == False:
            break



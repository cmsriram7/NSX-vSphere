# encoding: utf-8
import paramiko
import ssl
import argparse
import sys
sys.path.append("/opt/vmware/sddc-support/dependency/pyVpx/")
from pyVmomi import vim
from pyVim.connect import SmartConnect, Disconnect
import time
import atexit
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

def get_ssh_connection(host, username, password):
    client = paramiko.client.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, 22, username=username, password=password)
    except:
        print("Unable to connect to the remote machine")

    return client
        
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
    
def connect(host, user, pwd):
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    context.verify_mode = ssl.CERT_NONE
    si = SmartConnect(host=host, user=user, pwd=pwd,
                              sslContext=context)
    atexit.register(Disconnect, si)
    content = si.RetrieveContent()
    return content
    
def check_certificate(client):
    cmd = "cat /etc/vmware/ssl/rui.crt | od -A n -t x1 | grep -i '0d 0a'"
    stdin, stdout, stderr = client.exec_command(cmd)
    output = str(stdout.read(), encoding="utf-8")
    if "0d 0a" in output:
        print("\\r and \\n characters found in the certificate file")
        return True
    else:
        print("No \\r and \\n characters in certificate file")
        return False

def remove_CR(client):
    try:
        print("Creating a copy of the certificate file")
        cmd = "cp /etc/vmware/ssl/rui.crt /etc/vmware/ssl/rui_old.crt"
        stdin, stdout, stderr = client.exec_command(cmd)
        output = stdout.read().decode()
        print("Replacing the CR characters in the certificate")
        cmd = "sed 's/\r$//' /etc/vmware/ssl/rui.crt > /etc/vmware/ssl/rui_new.crt"
        stdin, stdout, stderr = client.exec_command(cmd)
        output = stdout.read().decode()
        print("Moving the new file to the original location")
        cmd = "mv /etc/vmware/ssl/rui_new.crt /etc/vmware/ssl/rui.crt"
        stdin, stdout, stderr = client.exec_command(cmd)
        output = stdout.read().decode()
        print("Removing temporary files")
        cmd = "rm -f /etc/vmware/ssl/rui_old.crt"
        stdin, stdout, stderr = client.exec_command(cmd)
        output = stdout.read().decode()
    except:
        print("unable to execute the commands")
        print(sys.exc_info())
        
def restart_svc(client):
    print("Restarting service")
 
    cmd = "services.sh restart"
    stdin, stdout, stderr = client.exec_command(cmd)
    output = stdout.read().decode()
    if "started" in output:
        print("Services restarted successfully")
    else:
        print("Restarting of services failed")

def get_obj(content, vimtype, name):
    """
    Return an object by name, if name is None the
    first found object is returned
    """
    obj = None
    container = content.viewManager.CreateContainerView(
        content.rootFolder, vimtype, True)
    for c in container.view:
        if name:
            if c.name == name:
                obj = c
                break
        else:
            obj = c
            break

    container.Destroy()
    return obj
    
def enable_ssh(host_system):
    # host_system = get_obj(content, [vim.HostSystem], None)
    service_system = host_system.configManager.serviceSystem
    ssh_service = [x for x in service_system.serviceInfo.service if x.key == 'TSM-SSH'][0]
    if not ssh_service.running:
        print("SSH service is not running, enabling the SSH service now")
        service_system.Start(ssh_service.key)
        
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
                                     
def nsxvhosts_executecmd(hostname, username, password):
    resp = send_request("get", hostname, "/api/4.0/firewall/globalroot-0/status", username, password, data=None)
    if resp:
        config = xmltodict.parse(resp)
        hostsList = []
        for elem in config['firewallStatus']['clusterList']['clusterStatus']['hostStatusList']['hostStatus']:
            hostFqdn = elem['hostName']
            hostsList.append(hostFqdn)
        for host in hostsList:
            host_uname = input("Enter the username of host {}: ".format(host))
            host_pass = getpass.getpass("Enter host password: ")
            content = None
            try:
                content = connect(host, host_uname, host_pass) 
            except vim.fault.InvalidLogin:
                print("vim: Invalid login")
                continue
            except:
                print("Exceptions while logging into the hosts")
                continue
 
            host_system = get_obj(content, [vim.HostSystem], None)
            enable_ssh(host_system)
            client = get_ssh_connection(host, host_uname, host_pass)
            bool_value = check_certificate(client)
            if bool_value:
                print("The host certificate has \\r and \\n characters present")
                print("Calling the function to remove \\r and \\n characters")
                remove_CR(client)
                bool_value = check_certificate(client)
                if not bool_value:
                    print("\\r \\n successfully removed from host certificate file")
                else:
                    print("\\r \\n not removed from host certificate file")
                restart_svc(client)
            else:
                print("The host certificate is not having \\r and \\n characters")
    else:
        print("Unable to execute commands on the nsxt prepared hosts")
        
def nsxt_hosts(nsxt_host, uname, password):
    resp = send_request("get", nsxt_host, "/api/v1/fabric/discovered-nodes", uname, password, data=None)
    jvar = "{}".format(resp)
    jdict = json.loads(jvar)
    pprint.pprint(jdict["results"][0]["display_name"])
    tprep_hosts = []
    for e in jdict["results"]:
        print(e["display_name"])
        tprep_hosts.append(e["display_name"])
    for host in tprep_hosts:
        host_uname = input("Enter the username of host {}: ".format(host))
        host_pass = getpass.getpass("Enter host password: ")
        content = None
        try:
            content = connect(host, host_uname, host_pass)
        except vim.fault.InvalidLogin:
            print("vim: Invalid login")
            continue
        except:
            print("Exceptions while logging into the hosts")
            continue
        host_system = get_obj(content, [vim.HostSystem], None)
        enable_ssh(host_system)
        client = get_ssh_connection(host, host_uname, host_pass)
        bool_value = check_certificate(client)
        if bool_value:
            print("The host certificate has \\r and \\n characters present")
            print("Calling the function to remove \\r and \\n characters")
            remove_CR(client)
            bool_value = check_certificate(client)
            if not bool_value:
                print("\\r \\n successfully removed from host certificate file")
            else:
                print("\\r \\n not removed from host certificate file")
            restart_svc(client)
        else:
            print("The host certificate is not having \\r and \\n characters")
        
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
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument("-o", "--nsx_hostname", required=True, type=str, help="FQDN or IP")
    args = parser.parse_args()
    nsxv_hostname = args.nsx_hostname
    
    while True:
        try:
            nsxv_user = input("Enter NSXV Manager Username: ")
            nsxv_pass = getpass.getpass("Enter NSXV Manager Password: ")
            nsxt_host = input("Enter the NSXT manager hostname or IP: ")
            nsxt_user = input("Enter NSXT Manager Username: ")
            nsxt_pass = getpass.getpass("Enter NSXT Manager Password: ")
            enable_base64(nsxv_hostname, nsxv_user, nsxv_pass)
            nsxvhosts_executecmd(nsxv_hostname, nsxv_user, nsxv_pass)
            nsxt_hosts(nsxt_host, nsxt_user, nsxt_pass)
            to_quit = input("Enter q to quit or press any key to continue: ")
            if to_quit == "q":
                break
        except KeyboardInterrupt:
            print("\n User interrupted the script ")
            sys.exit(1) 
      

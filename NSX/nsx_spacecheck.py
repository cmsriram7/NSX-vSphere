# encoding: utf-8
import paramiko
import ssl
import argparse
import sys
import time
import ssl
import requests
from pexpect import pxssh
sys.path.append("/opt/vmware/sddc-support/dependency/pyVpx/")
import shutil
import getpass
import base64
import re
import json

def get_ssh_connection(host, username, password):
    client = pxssh.pxssh()
    try:
        
        client.login(host, username=username, password=password, auto_prompt_reset=False, login_timeout=1)
        
    except:
        print("Unable to login to remote machine")
        print(sys.exc_Info())
    return client

def login_to_vc(host, user, pwd):
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ssl_context.verify_mode = ssl.CERT_NONE
    si = SmartConnect(host=host, user=user, pwd=pwd,
                              sslContext=ssl_context)

    return si
    
def space_check(dir_name):
    try:
        print("Checking the space usage in {}".format(dir_name))
        print("Running the command 'df -hk'")
        usage = execute_cmds(client, f"df -hk /{dir_name}")
        print(usage)
        print("Disk usage stats for the {} directory".format(dir_name))
        
        usagelst = usage.split()
        # used = None
        # for e in usagelst:
            # if "used" in e:
                # used = e
                # break
        used = usagelst[2]
        perc = usagelst[4]
        print(f"The space used in {dir_name} directory is {used} bytes ({perc} percent)")
    except FileNotFoundError:
        print("File or directory ({}) specified not found".format(dir_name))
    except:
        print("Unable to execute the space check commands")

def execute_cmds(client, cmd):
    try:
        client.sendline(cmd)
        client.prompt(timeout=1)
        output = client.before
        output = output.decode("UTF-8")
        output = output.split("\r\n")
        output = output[-2]
    except:
        print("unable to execute the commands")
        print(sys.exc_info())
    
    return output
    
def encode_b64(strng):
    strng = strng.encode("utf-8")
    b64_val = base64.b64encode(strng)
    b64_val = b64_val.decode()
    
    return b64_val
            
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--nsx_hostname", required=True, type=str, help="FQDN or IP")
    args = parser.parse_args()
    nsx_hostname = args.nsx_hostname
    nsx_username = input("Enter the nsx username: ")
    nsx_password = getpass.getpass("Enter the nsx password: ")
    
    client = get_ssh_connection(nsx_hostname, nsx_username, nsx_password)
    print("Logging into the NSX appliance")

    if nsx_username == 'admin':
        print("Running the command 'st en' to get into privileged user mode")
        output = client.sendline("st en")
        client.prompt(timeout=1)
        print("Typing the nsx password")
        client.sendline(nsx_password)
        print("Running the command 'df -hk' for space check on different directories")
        # output = execute_cmds(client, "df -hk /tmp")
        # print(output)
        # path = "/tmp"
        # stats = shutil.disk_usage(path)
        # print("Disk usage stats for the temp directory")
        # print(stats)
        space_check("/tmp")
        space_check("/image")
        space_check("/config")
        
        

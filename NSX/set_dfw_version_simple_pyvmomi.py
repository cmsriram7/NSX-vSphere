# encoding: utf-8
import paramiko
import ssl
import argparse
import sys
import time
import ssl
from pyVim.connect import SmartConnect
import getpass

def get_ssh_connection(host, username, password):
    client = paramiko.client.SSHClient()
    client.load_system_host_keys()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, 22, username=username, password=password)
    except:
        print("Unable to connect to remote machine")

    return client


def login_to_vc(host, user, pwd):
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    ssl_context.verify_mode = ssl.CERT_NONE
    si = SmartConnect(host=host, user=user, pwd=pwd,
                              sslContext=ssl_context)

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

def set_dfw_version(vc_ip, vc_username, vc_password):
        print("Logging into {}".format(vc_ip))
        si = login_to_vc(vc_ip, vc_username, vc_password)
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
            username = input("Enter host username: ")
            password = getpass.getpass("Enter host password: ")
          
                    
            for host in hosts:   
                          
                print("Connecting to host ", host)
                enable_ssh(host_dict[host])
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
                        print("Current version is: {}".format(cur_version))
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
                    
            
if __name__ == '__main__':
        
    vcenters = []
           
    while True:
        if len(vcenters) != 0:
            for vc in vcenters:      
                vc_ip = vc['vcenter_ip']
                vc_username = vc['vcenter_user']
                vc_password = vc['vcenter_pass']

                set_dfw_version(vc_ip, vc_username, vc_password)
        else:
            try:
                vc_ip = input("Enter VCenter IP or FQDN (or 'q' to quit): ")
                if vc_ip == 'q':
                    break

                vc_username = input("Enter VC Username: ")
                vc_password = getpass.getpass("Enter VC Password: ")
                set_dfw_version(vc_ip, vc_username, vc_password)
            except:
                print("\nUser interrupted the flow")
                #print(sys.exc_info())
                sys.exit(1)
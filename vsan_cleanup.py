import sys
import paramiko
import json
from sys import argv
from collections import OrderedDict

class host_creds:
    def __init__(self, host_ip, host_username, host_password):
        self.host_ip = host_ip
        self.host_username = host_username
        self.host_password = host_password
        self.host_ssh_conn = None

def connect(hc):
    try:
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hc.host_ip, 22, hc.host_username, hc.host_password)
        print(f"Connection to host {hc.host_ip} successful")
        hc.host_ssh_conn = ssh
    except:
        print(f"Unable to connect to Host {hc.host_ip}")
        return False
    return True
     
def vsan_cleanup(hc):
    ssh = hc.host_ssh_key
    cmds = OrderedDict()
    cmds['Host VSAN Storage List'] = 'esxcli vsan storage list'
    cmds["Set Automode"] = 'esxcli vsan storage automode set --enabled false'
    cmds["Storage Remove"] = 'esxcli vsan storage remove -s '
    cmds["Get Cluster list"] = 'esxcli vsan cluster get'
    cmds['VSAN Leave'] = 'esxcli vsan cluster leave'
    vsan_enabled = False
    for cmd in cmds:
        print(f"Running {cmd}")
        try:
            if cmd == 'VSAN Leave':
                if not vsan_enabled:
                    break
                else:
                    pass
                    # Run the command and process output
            stdin, stdout, stderr = ssh.exec_command(cmd)
            error = stderr.read()
            if len(error) != 0:
                print("Below error was returned:")
                print(error)
                return False
            output = stdout.read()
            if "Display Name" in output:
                pass
                # convert the output to a JSON Dict and process it here
            # Write logic to convert the output to JSON Dict and parse it to find if VSAN is enabled here
            # Set vsan_enabled = True here if it is enabled

        except:
            return False

        return True

if __name__ == "__main__":    
    fd = open(argv[1], 'r')
    data=json.load(fd)

    for key, value in data.iteritems():
        print(f"Cleaning Vsan from host {key} with password {value}")
        hc = host_creds(key, 'root', value)
        result = connect(hc)
        if not result:
            sys.exit(1)

        vsan_cleanup(hc)
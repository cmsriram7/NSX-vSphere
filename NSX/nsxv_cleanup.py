# encoding: utf-8
import requests
import base64
import xmltodict
import urllib3
import time
import getpass
import paramiko

urllib3.disable_warnings()
global rules
rules = 0 

api ={"logicalswitches" : "/api/2.0/vdn/virtualwires","firewall_global_config" :"/api/4.0/firewall/globalroot-0/config", "edges": "/api/4.0/edges"}



def encode_b64(strng):
    strng = strng.encode("utf-8")
    b64_val = base64.b64encode(strng)
    b64_val = b64_val.decode()
    
    return b64_val


def delete_user_input(content):
    user_delete_user_input = input("Do you want to delete all above mentioned {} (y/n): ".format(content))
    if user_delete_user_input.upper() == "Y" or user_delete_user_input.upper()=="N":
        return user_delete_user_input.upper()
    else:
        delete_user_input()


def send_request(req_type, hostname, endpoint, username, password, data):
    url = "https://{}{}".format(hostname, endpoint)
    usrPass = "{}:{}".format(username, password)
    b64_val = encode_b64(usrPass)
    headers = {"Authorization" : "Basic %s" % b64_val, 'Content-Type': 'application/json'}
    
    if req_type == 'get':
        resp = requests.get(url, headers=headers, verify=False)
        
    elif req_type == 'put':
        resp = requests.put(url, data=data, headers=headers, verify=False)
        
    elif req_type == 'post':
        resp = requests.post(url, data=data, headers=headers, verify=False)
        
    elif req_type == 'delete':
        resp = requests.delete(url, headers=headers, verify=False)
        
    else:
        print("\n Unknown api method \n")
    
    if (resp.status_code == 200) or (resp.status_code == 204):
        return resp.text
    else:
        return False


def is_valid(data):
    if not data:
        return False
    
    try:
        config = xmltodict.parse(data)
    except xml.parsers.expat.ExpatError:
        print("Server did not return proper XML")
        return False
    
    return True


def delete_tz(hostname, username, password):
    resp = send_request("get", hostname, "/api/2.0/vdn/scopes", username, password, data=None)
    
    if is_valid(resp):
        config = xmltodict.parse(resp)
        
    else:
        print("\nUnable to execute the GET call on the NSX system\n") 
    if config['vdnScopes'] == None:
        print("\nThere are no transport zones present in the system\n")
        return False        
    
    elif isinstance(config['vdnScopes']['vdnScope'], list):
        for index in range(len(config['vdnScopes']['vdnScope'])):
            item = config['vdnScopes']['vdnScope'][index]['objectId']
            resp = send_request("delete", hostname, "/api/2.0/vdn/scopes/{}".format(item), username, password, data=None)
            if resp != False:
                print("\nSuccessfully deleted the transport zone\n")
            else:
                print("\nFailed to delete the transport zone\n")
    
    elif isinstance(config['vdnScopes']['vdnScope'], dict):
        item = config['vdnScopes']['vdnScope']['objectId']
        resp = send_request("delete", hostname, "/api/2.0/vdn/scopes/{}".format(item), username, password, data=None)
        if resp != False:
            print("\nSuccessfully deleted the transport zone\n")
        else:
            print("\nFailed to delete the transport zone\n")
    
    else:
        print("\ninvalid response\n")
    
    resp = send_request("get", hostname, "/api/2.0/vdn/scopes", username, password, data=None)

    if resp:
        config = xmltodict.parse(resp)
    if config['vdnScopes'] == None:
        print("\nAll transport zones present have been deleted\n")    
        return True
     

def validate_edge_deletion(hostname, username, password,rules):
    resp = send_request("get", hostname, api["firewall_global_config"], username, password, data=None)

    if is_valid(resp):
        config = xmltodict.parse(resp)
        firewall = config["firewallConfiguration"]["layer3Sections"]["section"]
        try:
            for i in range(len(firewall)):
                Rule_name = config["firewallConfiguration"]["layer3Sections"]["section"]["rule"][i]["name"]
                Rule_type = config["firewallConfiguration"]["layer3Sections"]["section"]["rule"][i]["action"] 
                appliedOn = config["firewallConfiguration"]["layer3Sections"]["section"]["rule"][i]["appliedToList"]["appliedTo"]["value"]
                valid_status = config["firewallConfiguration"]["layer3Sections"]["section"]["rule"][i]["appliedToList"]["appliedTo"]["isValid"]
                if Rule_name== "Reject All Rule" and Rule_type == "reject" and appliedOn == "ALL_EDGES" and valid_status =="true":
                    return True
                else:
                    print("\nReject rule is not verified\n")
                
        except Exception as e:
            #print(e)
            rules= rules+1
            if rules <=len(firewall):
                validate_edge_deletion(hostname, username, password,rules)
             

def delete_edges(hostname, username, password):
    resp = send_request("get", hostname, api["edges"], username, password, data=None)

    if is_valid(resp):
        config = xmltodict.parse(resp)
    else:
        print("\nUnable to execute the GET call on the NSX system\n")
        return True
   
    try:
        if int(config['pagedEdgeList']['edgePage']['pagingInfo']['totalCount']) == 0:
            print("\nNo edges found in the system\n")
            return True
        else:
            if isinstance(config['pagedEdgeList']['edgePage']['edgeSummary'], list):
                edge_obj_ids = []
                for edge_num in range(8):
                    edges = config['pagedEdgeList']['edgePage']['edgeSummary'][edge_num]['name']
                    edge_obj_ids.append(edges)
                
                print(edge_obj_ids)
                
                if delete_user_input("edges including others").upper()=="Y":
                        if validate_edge_deletion(hostname, username, password,rules) is True:
                            for index in range(len(config['pagedEdgeList']['edgePage']['edgeSummary'])):
                                item = config['pagedEdgeList']['edgePage']['edgeSummary'][index]['objectId']
                                try:
                                    resp = send_request("delete", hostname, api["edges"]+"/{}".format(item), username, password, data=None)
                                except Exception as e:
                                    print(e)
                                    
                                if resp != False:
                                    print("\nSuccessfully deleted the edge node:", config['pagedEdgeList']['edgePage']['edgeSummary'][index]['name'])
                                else:
                                    print("\nFailed to delete the edge node\n")
                        else:
                            print("\nEdge Delete validation failed\n")
                                
                                
            elif isinstance(config['pagedEdgeList']['edgePage']['edgeSummary'], dict):
                item = config['pagedEdgeList']['edgePage']['edgeSummary']['objectId']
                if validate_edge_deletion(hostname, username, password,rules) is True:
                    try:
                        resp = send_request("delete", hostname, api["edges"]+"/{}".format(item), username, password, data=None)
                    except Exception as e:
                            print(e)
                
                if resp != False:
                        print("\nSuccessfully deleted the edge node\n")
                else:
                        print("\nFailed to delete the edge node\n")        
    
    except Exception as e:
        print(e)
        
    resp = send_request("get", hostname, api["edges"], username, password, data=None)    
    if resp:
        config = xmltodict.parse(resp)
    try:
        if int(config['pagedEdgeList']['edgePage']['pagingInfo']['totalCount']) == 0:
            print("\nAll edges have been deleted\n")
            return True
        else:
            print("\nEdge nodes are not deleted succefully\n")
            return False
    except Exception as e:
        return False
        print(e)


def delete_logicalswitches(hostname, username, password):
    resp = send_request("get", hostname, api["logicalswitches"], username, password, None)
    if is_valid(resp):
        config = xmltodict.parse(resp)
        logical_switches = config['virtualWires']['dataPage']['virtualWire']
        for logical_switch in logical_switches:
            logical_id = logical_switch.get("objectId")
            logical_name = logical_switch.get("name")
            print(logical_name, logical_id)

        if delete_user_input("Logical_switches") =="Y":
            obj_ids = []
            not_deleted_ls = []
            try:
                if isinstance(config['virtualWires']['dataPage']['virtualWire'], list):
                    for index in range(len(config['virtualWires']['dataPage']['virtualWire'])):
                        elem = config['virtualWires']['dataPage']['virtualWire'][index]
                        obj_ids.append(elem['objectId'])
                    for obj_id in obj_ids:
                        resp = send_request("delete", hostname,api["logicalswitches"]+"/{}".format(obj_id), username, password, None)
                        
                        print("\ndeleting the logical switches",obj_id)
                        time.sleep(2)


                        if resp != False:
                            print("\n Successfully deleted the logical switch \n")
                        else:
                            print("\n Unable to delete the logical switch \n")
                            not_deleted_ls.append(obj_id)
                    

                    if not_deleted_ls[0] != None:
                        print("\n Below logical switches are not get deleted:\n", not_deleted_ls)
                        confirm_manual_delaetion= input("Delete all the pending logical switches manually and confirm if all the logical swutches has been deleted manually (Y/N) :")
                        if confirm_manual_delaetion.upper() =="Y":
                                    print("\nChecking the status of logical switch\n")
                        else:
                            print("\nPlease delete the logical switches or terminate the seesion\n")
                
                    else:
                        print("\nAll the logical switches has been deleted succefully\n")


                elif isinstance(config['virtualWires']['dataPage']['virtualWire'], dict):
                    obj_id = config['virtualWires']['dataPage']['virtualWire']['objectId']     
                    resp = send_request("delete", hostname, api["logicalswitches"]+"/{}".format(obj_id), username, password, None)
                    print("\ndeleting the logical switches",obj_id)
                    if resp != False:
                        print("\nSuccessfully deleted the logical switch\n")
                    
                    else:
                        print("\nUnable to delete the logical switch\n")
                        not_deleted_ls.append(obj_id)
                print("\n Below logical switches are not get deleted:\n", not_deleted_ls)
            
            except Exception as e:
                if resp:
                    config = xmltodict.parse(resp)
                    print("\nSending GET request to check there are no logical switches present\n")
                    resp = send_request("get", hostname, api["logicalswitches"], username, password, None)
                    if resp:
                        config = xmltodict.parse(resp)
                        if int(config['virtualWires']['dataPage']['pagingInfo']['totalCount']) == 0:
                            print("\nThere are no logical switches present\n")

                        else:
                            print("\nNot able to delete the logical switches: ", e)
  
       
        else:
            print("\nNo any logical switches will be deleted\n")
    
    else:
        print("\nUnable to execute the GET call on the logical switches\n")
        
    
    print("\nSending GET request to check there are no logical switches present\n")
    resp = send_request("get", hostname, api["logicalswitches"], username, password, None)
    if is_valid(resp):
        config = xmltodict.parse(resp)
        try:
            if int(config['virtualWires']['dataPage']['pagingInfo']['totalCount']) == 0:
                print("\nAll logical switches have been deleted\n")
                return True
            else:
                print("\nLogical switches are not cleaned up\n")
                return False     
        except Exception as e:
            print(e)
            return False
    else:
        print("\nUnable to execute the GET call on the logical switches\n")
        return False


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
    nsx_hostname = input("Enter NSX-V manager IP: ")
    nsx_user = "admin"
    print("\nNSX-V username: admin\n")
    nsx_pass = getpass.getpass("Enter NSX_V Password: ")

    while True:       
        enable_base64(nsx_hostname, nsx_user, nsx_pass)
        status_del_edge = delete_edges(nsx_hostname, nsx_user, nsx_pass)
        if status_del_edge:
            status_del_ls = delete_logicalswitches(nsx_hostname, nsx_user, nsx_pass)  
            if status_del_ls:
                del_tz = delete_tz(nsx_hostname, nsx_user, nsx_pass)
                if del_tz:
                    print("\nDelete transport zone completed\n")
                else:
                    print("\nTansport zone not deleted succesfully\n")
            else:
                print("\nLogical Switches not properly deleted\n")    
        else:
            print("\nEdges are not deleted\n")
        to_quit = input("Enter q to quit or press any key to continue: ")
        if to_quit == "q":
            break    




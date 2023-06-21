# remove_infra_groups.py
# Always run in SUBTENANT
# Best effort - caught failures will not cause exceptions
#
# Date: 28 Feb 2022
# Author: Neil van Rensburg
# Email: nvanrensburg@morpheusdata.com
# Change: first release (morpheus-snow integration)
#
# Date: 09 Mar 2023
# Author: Fabrizio Montanini
# Email: fabrizio.montanini@dxc.com
# Change: morpheus-keycloak integration
#
# Date: 18 May 2023
# Author: Fabrizio Montanini
# Email: fabrizio.montanini@dxc.com
# Change: role management made compliant with morpheus 6.0.3 changes


import requests
import json
#py2
#from urllib import urlencode
#py3
from urllib.parse import urlencode
from datetime import datetime
import urllib3
urllib3.disable_warnings()
from morpheuscypher import Cypher


# Misc
CONFIRMATION_STRING = "YES"
TIME_STAMP = datetime.now().strftime('%Y-%m-%d')


# Inputs
#MORPHEUS_GROUPS = morpheus['customOptions']['infra_groups']
try:
    MORPHEUS_GROUP_LIST = morpheus['customOptions']['morpheus_groups']
except KeyError:
    MORPHEUS_GROUP_LIST = ""
if isinstance(MORPHEUS_GROUP_LIST, list):
    MORPHEUS_GROUPS = (','.join(MORPHEUS_GROUP_LIST)).strip().upper()
else:
    MORPHEUS_GROUPS = MORPHEUS_GROUP_LIST.strip().upper()

I_AM_SURE = morpheus['customOptions']['IAmSureIWantToDelete']

# Morpheus Globals
MORPHEUS_HOST = morpheus['morpheus']['applianceHost']
MORPHEUS_TOKEN = morpheus['morpheus']['apiAccessToken']
MORPHEUS_HEADERS = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + MORPHEUS_TOKEN} 
MORPHEUS_VERIFY_SSL_CERT = False
MORPHEUS_TENANT_ADMIN_ROLES = ['TENANT_ADMIN_TOSC']


# SNow Globals
SNOW_HEADERS = { "Content-Type": "application/json", "Accept": "application/json" }
SNOW_HOSTNAME = "regionetoscanatest.service-now.com"
SNOW_USER = 'morpheus'
SNOW_PWD = str(Cypher(morpheus=morpheus, ssl_verify=False).get("secret/dxcsnowpass"))
SNOW_OP_STATUS_RETIRED = "6"

if 'skip_snow_operations' in morpheus['customOptions']:
    SNOW_SKIP = bool(morpheus['customOptions']['skip_snow_operations'])
else:
    SNOW_SKIP = False


#Keycloak Globals
KEYCLOAK_REST_CLIENT_ID = "rest-client"
KEYCLOAK_REST_CLIENT_SECRET = str(Cypher(morpheus=morpheus, ssl_verify=False).get("secret/KeycloakRestClientSecret"))
KEYCLOAK_HOST = "10.156.160.62:8080/auth"

KEYCLOAK_VERIFY_SSL_CERT = False
KEYCLOAK_TENANT_ROLES_BRANCH="1. RUOLI_PER_TENANT"
KEYCLOAK_REALM = "Toscana"
#DELETE_KEYCLOAK_GROUPS = morpheus['customOptions']['delete_idm_groups']
DELETE_KEYCLOAK_GROUPS = "on"



#############
# Functions #
#############


# Get current Morpheus tenant
def get_morpheus_current_tenant(morpheus_host, access_token):
 
    url = "https://%s/api/whoami" % (morpheus_host)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + (access_token)
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error getting tenant name for current user: Response code %s: %s" % (response.status_code, response.text))
        raise Exception("Error getting tenant name for current user: Response code %s: %s" % (response.status_code, response.text))
 
    data = response.json()
    #print(json.dumps(data, indent=4))
    return { "tenant_name": data["user"]["account"]["name"], "tenant_id": data["user"]["account"]["id"] }


# Get Morpheus Role ID by Name
def get_morpheus_role_id_by_name(morpheus_host, role_name, access_token):
    url = "https://%s/api/roles/?max=-1" % (morpheus_host)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + access_token
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error getting role '%s': Response code %s: %s" % (role_name, response.status_code, response.text))
        #raise Exception("Error getting role '%s': Response code %s: %s" % (role_name, response.status_code, response.text))
 
    data = response.json()
         
    for role in data["roles"]:
        if role["authority"] == role_name:
            return role["id"]
 
    print("Role %s not found..." % (role_name))
    #raise Exception("Role %s not found..." % (role_name))
    return 0


# Get Morpheus Infra Group ID by Name
def get_morpheus_group_id_by_name(morpheus_host, group_name, access_token):
    url = "https://%s/api/groups/?max=-1" % (morpheus_host)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + access_token
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error getting Groups: Response code %s: %s" % (response.status_code, response.text))
        #raise Exception("Error getting Tenants: Response code %s: %s" % (response.status_code, response.text))
 
    data = response.json()
         
    for group in data["groups"]:
        if group["name"].lower() == group_name.lower():
            return group["id"]
 
    print("Group %s not found..." % (group_name))
    #raise Exception("Group %s not found..." % (group_name))
    return 0


# Generic morpheus delete request
def delete_morpheus_object(morpheus_host, relative_url, access_token):
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + access_token
    url = "https://%s%s" % (morpheus_host, relative_url)
    response = requests.delete(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error deleting object '%s': Response code %s: %s" % (relative_url, response.status_code, response.text))
        raise Exception("Error deleting object '%s': Response code %s: %s" % (relative_url, response.status_code, response.text))


# Get ServiceNow sys_id of the tenant - return list of tenant matching the name
def get_snow_tenant_ci_sys_id(snow_host, tenant_name):
    url = 'https://%s/api/now/table/u_cmdb_ci_tenant' % (snow_host)
    params = { "sysparm_query": "name=" + tenant_name + "^operational_status!=" + SNOW_OP_STATUS_RETIRED }
    response = requests.get(url, auth=(SNOW_USER, SNOW_PWD), headers=SNOW_HEADERS, params=params)
    if not response.ok:
        print("Error looking up tenant CI '%s' in ServiceNow: Response code %s: %s" % (tenant_name, response.status_code, response.text))
        #raise Exception("Error looking up tenant CI '%s' in ServiceNow: Response code %s: %s" % (tenant_name, response.status_code, response.text))
        return []

    data = response.json()
    if len(data["result"]) == 0:
        print("Operational Tenant CI '%s' not found in ServiceNow." % (tenant_name))
        #raise Exception("Operational Tenant CI '%s' not found in ServiceNow." % (tenant_name))
        return []

    if len(data["result"]) > 1:
        print("Warning: Duplicates of Operational Tenant CI '%s' not found in ServiceNow. Please cleaning up all of them...." % (tenant_name))

    tenant_sys_ids = [x['sys_id'] for x in data["result"]] 

    #print(json.dumps(tenant_sys_ids))
    return tenant_sys_ids


# Find CMP groups by Tenant sys_id
def get_active_snow_tenant_groups_sys_ids(snow_host, tenant_id):
    url = 'https://%s/api/now/table/u_cmdb_ci_cmpresourcegroup' % (snow_host)
    params = { "sysparm_query": "u_tenant=" + tenant_id + "^operational_status!=" + SNOW_OP_STATUS_RETIRED}
    response = requests.get(url, auth=(SNOW_USER, SNOW_PWD), headers=SNOW_HEADERS, params=params)
    if not response.ok:
        print("Error looking up CMP groups for tenant '%s' in ServiceNow: Response code %s: %s" % (tenant_id, response.status_code, response.text))
        #raise Exception("Error looking up CMP groups for tenant '%s' in ServiceNow: Response code %s: %s" % (tenant_id, response.status_code, response.text))
        return []

    data = response.json()
    if len(data["result"]) == 0:
        print("No groups found for Tenant '%s' in ServiceNow." % (tenant_id))
        #raise Exception("No groups found for Tenant '%s' in ServiceNow." % (tenant_id))
        return []

    result = []
    for grp in data["result"]:
        result.append({ "name": grp["name"], "sys_id": grp["sys_id"] }) 

    return result

# Append _deleted to the tenant name and change the operational status to retired
def retire_snow_tenant_ci(tenant_name, tenant_id):
    jbody = {"name": tenant_name.strip() + "_deleted_" + TIME_STAMP, "operational_status": SNOW_OP_STATUS_RETIRED }
    body = json.dumps(jbody)
    #print(body)
    url = 'https://%s/api/now/table/u_cmdb_ci_tenant/%s' % (SNOW_HOSTNAME, tenant_id)
    response = requests.put(url, auth=(SNOW_USER, SNOW_PWD), headers=SNOW_HEADERS ,data=body)
    if not response.ok:
        print("Error updating tenant CI for tenant '%s' in ServiceNow: Response code %s: %s" % (tenant_name, response.status_code, response.text))
        #raise Exception("Error updating tenant CI for tenant '%s' in ServiceNow: Response code %s: %s" % (tenant_name, response.status_code, response.text))

    return tenant_id


# Append _deleted to the group name and change the operational status to retired
def retire_snow_tenant_cmp_group_ci(group_name, group_id):
    jbody = {"name": group_name.strip() + "_deleted_" + TIME_STAMP, "operational_status": SNOW_OP_STATUS_RETIRED }
    body = json.dumps(jbody)
    #print(body)
    url = 'https://%s/api/now/table/u_cmdb_ci_cmpresourcegroup/%s' % (SNOW_HOSTNAME, group_id)
    response = requests.put(url, auth=(SNOW_USER, SNOW_PWD), headers=SNOW_HEADERS ,data=body)
    if not response.ok:
        print("Error updating tenant CMP Group '%s' in ServiceNow: Response code %s: %s" % (group_name, response.status_code, response.text))
        #raise Exception("Error updating tenant CMP Group '%s' in ServiceNow: Response code %s: %s" % (group_name, response.status_code, response.text))

    return group_id
   
#---- Keycloak ----

def get_keycloak_access_token(keycloak_host, keycloak_realm, client_id, client_secret):
#Get temporary Keycloak API key from a keycloak rest-client
    header = {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}
    url = "http://%s/realms/%s/protocol/openid-connect/token" % (keycloak_host, keycloak_realm)
    b = {'client_id': client_id, 'client_secret': client_secret, 'grant_type':'client_credentials'}
    body=urlencode(b)
    response = requests.post(url, headers=header, data=body, verify=KEYCLOAK_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error getting token from Keycloak client '%s' access token: Response code %s: %s" % (client_id, response.status_code, response.text))
        raise Exception("Error getting token from Keycloak client '%s' access token: Response code %s: %s" % (client_id, response.status_code, response.text))
 
    data = response.json()
    access_token = data['access_token']
    return access_token


def get_keycloak_group_id_by_name(keycloak_host, keycloak_realm, group_name, access_token, start_group_id, depth = -1):
#Search Group by name in the group hierachy starting from given start_group_id (start_group_id=0 means root)
#Returns Group ID if group is found, -1 if not found in subgroups of start_group_id
#Scanning depth is by default full tree, otherwise, if optional depth parameter is specified, depth is 1 level only
#NOTE: group_name search is case insensitive
    result = -1

    def recursive_search_subgroups(group):
        nonlocal group_name, result
        #print(group["name"])
        if group["name"].lower() == group_name.lower():
            #print(group["id"])
            result = group["id"]
        elif result == -1:
           for subgrp in group["subGroups"]:
                recursive_search_subgroups(subgrp)
                if result != -1:
                    break

    url = "http://%s/admin/realms/%s/groups/%s" % (keycloak_host, keycloak_realm, start_group_id)
    header = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + access_token}
    response = requests.get(url, headers=header, verify=KEYCLOAK_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error searching keycloak group '%s': Response code %s: %s" % (group_name, response.status_code, response.text))
        raise Exception("Error searching keycloak group '%s': Response code %s: %s" % (group_name, response.status_code, response.text))
 
    data = response.json()
    #print(json.dumps(data, indent=4))

    if start_group_id == "":                    #Scanning from top level
        for grp in data:                        #Scanning 1st sublevel
            #print(grp["name"])
            if grp["name"].lower() == group_name.lower():
                return grp["id"]
        if depth == -1:                         #Scanning all remaining sublevels
            for grp in data:
                for grp1 in grp["subGroups"]:
                    if result != -1:
                        break
                    else:
                        group_id = recursive_search_subgroups(grp1)

    else:                                       #Scanning from start_group_id
        for subgrp1 in data["subGroups"]:       #Scanning 1st sublevel
            #print(subgrp1["name"])
            if subgrp1["name"].lower() == group_name.lower():
                return subgrp1["id"]
        if depth == -1:                         #Scanning all remaining sublevels
            for subgrp1 in data["subGroups"]:
                if result != -1:
                    break
                else:
                    group_id = recursive_search_subgroups(subgrp1)
 
    return result


def delete_keycloack_group(keycloak_host, keycloak_realm, access_token, group_id):
#Delete keycloak group identified by id
    header = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + access_token}
    url = "http://%s/admin/realms/%s/groups/%s" % (keycloak_host, keycloak_realm, group_id)
    response = requests.delete(url, headers=header, verify=KEYCLOAK_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error deleting keycloak group '%s': Response code %s: %s" % (group_id, response.status_code, response.text))
        raise Exception("Error deleting keycloak group '%s': Response code %s: %s" % (group_id, response.status_code, response.text))


def check_user_authorization(morpheus_host, access_token, role_list):
# Check if current user has an admin role    
    url = "https://%s/api/whoami" % (morpheus_host)
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error getting roles for current user: Response code %s: %s" % (response.status_code, response.text))
        raise Exception("Error getting roles for current user: Response code %s: %s" % (response.status_code, response.text))

    data = response.json()
    
    authorized = False    
    for role in data["user"]["roles"]:
        if role["authority"] in role_list:
            authorized = True
    return authorized


#############
# Main Code #
#############

if I_AM_SURE != CONFIRMATION_STRING:
    print("Not deleting. Enter '%s' as confirmation string." % (CONFIRMATION_STRING))
    #raise Exception("Not deleting. Enter '%s' as confirmation string." % (CONFIRMATION_STRING))
else:

    # ensure that the current script it running within a sub-tenant
    current_tenant = get_morpheus_current_tenant(MORPHEUS_HOST, MORPHEUS_TOKEN)
    if current_tenant["tenant_id"] == 1:
        print("Error: This script should NOT run within the Master Tenant!")
        raise Exception("Error: This script should NOT run within the Master Tenant!")
    MORPHEUS_TENANT = current_tenant["tenant_name"]

    # ensure current user has admin roles to run the script
    MORPHEUS_TENANT_ADMIN_ROLES.insert(0, MORPHEUS_TENANT + "_ADMIN")
    authorized_user = check_user_authorization(MORPHEUS_HOST, MORPHEUS_TOKEN, MORPHEUS_TENANT_ADMIN_ROLES)
    if authorized_user == False:
        print("Error: You must be Tenant Admin to run this script")
        raise Exception("Error: You must be Tenant Admin to run this script")

    ### Morpheus ###
    for group in MORPHEUS_GROUPS.split(","):
        group_name = group.strip()
    
        ### ServiceNow ###
        if SNOW_SKIP:
            print("Skipping the retirement of ServiceNow Tenant and group CIs.....")
        else:
            # Get tenant IDs - could potentially have duplicates
            tenant_ci_sys_ids = get_snow_tenant_ci_sys_id(SNOW_HOSTNAME, MORPHEUS_TENANT)
            # Get CMP Groups for each Tenant sys_id
            cmp_groups_to_be_deleted = []
            for tenant_id in tenant_ci_sys_ids:
                print("Found Tenant: " + tenant_id)
                tenant_groups = get_active_snow_tenant_groups_sys_ids(SNOW_HOSTNAME, tenant_id)
                for group in tenant_groups:
                    if group["name"] == group_name:
                        print("....Found Group: " + str(group))
                        cmp_groups_to_be_deleted.append(group)
            # retire Tenant Groups by adding _deleted to name and changing operational status to retired
            for group in cmp_groups_to_be_deleted:
                retire_snow_tenant_cmp_group_ci(group["name"], group["sys_id"])
        
        ### Morpheus ###
        # lookup IDs
        group_id = get_morpheus_group_id_by_name(MORPHEUS_HOST, group_name, MORPHEUS_TOKEN)
        standard_role_name = "%s_%s_USERSTD" % (MORPHEUS_TENANT, group_name.upper())
        catalog_role_name = "%s_%s_USERCTLG" % (MORPHEUS_TENANT, group_name.upper())
        standard_role_id = get_morpheus_role_id_by_name(MORPHEUS_HOST, standard_role_name, MORPHEUS_TOKEN)
        catalog_role_id = get_morpheus_role_id_by_name(MORPHEUS_HOST, catalog_role_name, MORPHEUS_TOKEN)
        # delete group
        print("Deleting Group with ID %s" % (group_id))
        delete_morpheus_object(MORPHEUS_HOST, "/api/groups/" + str(group_id), MORPHEUS_TOKEN)
        # delete standard role
        print("Deleting Role %s with ID %s" % (standard_role_name, standard_role_id))
        delete_morpheus_object(MORPHEUS_HOST, "/api/roles/" + str(standard_role_id), MORPHEUS_TOKEN)
        # delete catalog role
        print("Deleting Role %s with ID %s" % (catalog_role_name, catalog_role_id))
        delete_morpheus_object(MORPHEUS_HOST, "/api/roles/" + str(catalog_role_id), MORPHEUS_TOKEN)


    ### Keycloak ###
    if DELETE_KEYCLOAK_GROUPS == "on":
        # Generate keycloak access token
        print("Getting keycloak login token....")
        keycloak_access_token = get_keycloak_access_token(KEYCLOAK_HOST, KEYCLOAK_REALM, KEYCLOAK_REST_CLIENT_ID, KEYCLOAK_REST_CLIENT_SECRET)
        #print("keycloak access token: '%s'" % (keycloak_access_token))


        base_folder_id = get_keycloak_group_id_by_name(KEYCLOAK_HOST, KEYCLOAK_REALM, KEYCLOAK_TENANT_ROLES_BRANCH, keycloak_access_token, "", 1)
        if base_folder_id == -1:
            print("Error looking for Keycloak tenant root folder: '%s' not found! check IDM groups configuration" % (KEYCLOAK_TENANT_ROLES_BRANCH))
            quit()
        tenant_folder_name = "ruoli tenant " + MORPHEUS_TENANT
        tenant_folder_id = get_keycloak_group_id_by_name(KEYCLOAK_HOST, KEYCLOAK_REALM, tenant_folder_name, keycloak_access_token, base_folder_id, 1)
        if tenant_folder_id == -1:
            print("Keycloak folder '%s' not found: skipping removal of IDM groups. Please check manually" % (tenant_folder_name))
        else:
            for service_name in ['CMP','NAGIOS','SNOW']:
                tenant_service_folder_name = "ruoli " + service_name + " " + MORPHEUS_TENANT
                tenant_service_folder_id = get_keycloak_group_id_by_name(KEYCLOAK_HOST, KEYCLOAK_REALM, tenant_service_folder_name, keycloak_access_token, tenant_folder_id, 1)
                if tenant_service_folder_id == -1:
                    print("Keycloak Folder '%s' not found: skipping" % (tenant_service_folder_name))
                    next

                for group in MORPHEUS_GROUPS.split(","):
                    group_name = group.strip()
                    tenant_service_group_folder_name = "ruoli " + service_name + " " + MORPHEUS_TENANT + "_" + group_name
                    tenant_service_group_folder_id = get_keycloak_group_id_by_name(KEYCLOAK_HOST, KEYCLOAK_REALM, tenant_service_group_folder_name, keycloak_access_token, tenant_service_folder_id, 1)
                    if tenant_service_group_folder_id == -1:
                        print("Keycloak Folder '%s' not found: skipping" % (tenant_service_group_folder_name))
                        next
                    else:
                        print("Deleting Keycloak group '%s' with id: '%s'" % (tenant_service_group_folder_name, tenant_service_group_folder_id))
                        delete_keycloack_group(KEYCLOAK_HOST, KEYCLOAK_REALM, keycloak_access_token, tenant_service_group_folder_id)
    else:
        print("Skipping Keycloak Groups removal as requested")

print("Done.")

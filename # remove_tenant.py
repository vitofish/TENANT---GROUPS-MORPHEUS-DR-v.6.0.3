# remove_tenant.py
# Always run in MASTER TENANT
# Best effort - caught failures will not cause exceptions
#
# Date: 28 Feb 2022
# Author: Neil van Rensburg
# Email: nvanrensburg@morpheusdata.com
#
# Date: 28 Feb 2022
# Author: Neil van Rensburg
# Email: nvanrensburg@morpheusdata.com
# Change: first release (morpheus-snow integration)
#
# Date: 30 Nov 2022
# Author: Fabrizio Montanini
# Email: fabrizio.montanini@dxc.com
# Change: Resource Groups Code management
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


from datetime import datetime  
import requests
import json
#py2
#from urllib import urlencode
#py3
from urllib.parse import urlencode
import urllib3
urllib3.disable_warnings()
from morpheuscypher import Cypher


# Misc
CONFIRMATION_STRING = "YES"
TIME_STAMP = datetime.now().strftime('%Y-%m-%d')
 
#User Inputs 
MORPHEUS_TENANT = morpheus['customOptions']['tenant'].strip().upper()
#KEYCLOAK_DELETE_TENANT_CLIENT = morpheus['customOptions']['delete_client'].strip().upper()
KEYCLOAK_DELETE_TENANT_CLIENT = "ON"
I_AM_SURE = morpheus['customOptions']['IAmSureIWantToDelete']

# Morpheus Globals
MORPHEUS_HOST = morpheus['morpheus']['applianceHost']
MORPHEUS_TOKEN = morpheus['morpheus']['apiAccessToken']
MORPHEUS_HEADERS = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + MORPHEUS_TOKEN}
MORPHEUS_VERIFY_SSL_CERT = False
MORPHEUS_IDM_NAME = "Autenticazione con ARPA"

#Keycloak Globals
KEYCLOAK_REST_CLIENT_ID = "rest-client"
KEYCLOAK_REST_CLIENT_SECRET = str(Cypher(morpheus=morpheus, ssl_verify=False).get("secret/KeycloakRestClientSecret"))
KEYCLOAK_HOST = "10.156.160.62:8080/auth"

KEYCLOAK_VERIFY_SSL_CERT = False
KEYCLOAK_TENANT_ROLES_BRANCH="1. RUOLI_PER_TENANT"
KEYCLOAK_REALM = "Toscana"

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


#############
# Functions #
#############

#----- Morpheus  -----  

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


# Get Morpheus Tenant ID by Name
def get_morpheus_tenant_id_by_name(morpheus_host, tenant_name, access_token):
    url = "https://%s/api/accounts/?max=-1" % (morpheus_host)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + access_token
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error getting Tenants: Response code %s: %s" % (response.status_code, response.text))
        #raise Exception("Error getting Tenants: Response code %s: %s" % (response.status_code, response.text))
 
    data = response.json()
         
    for tenant in data["accounts"]:
        if tenant["name"] == tenant_name:
            return tenant["id"]
 
    print("Tenant %s not found..." % (tenant_name))
    #raise Exception("Tenant %s not found..." % (tenant_name))
    return 0


# Generic morpheus delete request
def delete_morpheus_object(morpheus_host, relative_url, access_token):
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + access_token
    url = "https://%s%s" % (morpheus_host, relative_url)
    response = requests.delete(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error deleting object '%s': Response code %s: %s" % (relative_url, response.status_code, response.text))
        #raise Exception("Error deleting object '%s': Response code %s: %s" % (relative_url, response.status_code, response.text))

#----- Snow -----  

# Get ServiceNow sys_id of the tenant - return list of tenant matching the name
def get_snow_tenant_ci_sys_id(snow_host, tenant_name):
    url = 'https://%s/api/now/table/u_cmdb_ci_tenant' % (snow_host)
    params = { "sysparm_query": "name=" + tenant_name + "^operational_status!=" + SNOW_OP_STATUS_RETIRED }
    response = requests.get(url, auth=(SNOW_USER, SNOW_PWD), headers=SNOW_HEADERS, params=params)
    if not response.ok:
        print("Error looking up tenant CI '%s' in ServciceNow: Response code %s: %s" % (tenant_name, response.status_code, response.text))
        #raise Exception("Error looking up tenant CI '%s' in ServciceNow: Response code %s: %s" % (tenant_name, response.status_code, response.text))
        return []

    data = response.json()
    if len(data["result"]) == 0:
        print("Operational Tenant CI '%s' not found in ServciceNow." % (tenant_name))
        #raise Exception("Operational Tenant CI '%s' not found in ServciceNow." % (tenant_name))
        return []

    if len(data["result"]) > 1:
        print("Warning: Duplicates of Operational Tenant CI '%s' not found in ServciceNow. Please cleaning up all of them...." % (tenant_name))

    tenant_sys_ids = [x['sys_id'] for x in data["result"]] 

    #print(json.dumps(tenant_sys_ids))
    return tenant_sys_ids


# Find CMP groups by Tenant sys_id
def get_snow_tenant_groups_sys_ids(snow_host, tenant_id):
    url = 'https://%s/api/now/table/u_cmdb_ci_cmpresourcegroup' % (snow_host)
    params = { "sysparm_query": "u_tenant=" + tenant_id + "^operational_status!=" + SNOW_OP_STATUS_RETIRED}
    response = requests.get(url, auth=(SNOW_USER, SNOW_PWD), headers=SNOW_HEADERS, params=params)
    if not response.ok:
        print("Error looking up CMP groups for tenant '%s' in ServciceNow: Response code %s: %s" % (tenant_id, response.status_code, response.text))
        #raise Exception("Error looking up CMP groups for tenant '%s' in ServciceNow: Response code %s: %s" % (tenant_id, response.status_code, response.text))
        return []

    data = response.json()
    if len(data["result"]) == 0:
        print("No groups found for Tenant '%s' in ServciceNow." % (tenant_id))
        #raise Exception("No groups found for Tenant '%s' in ServciceNow." % (tenant_id))
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
        print("Error updating tenant CI for tenant '%s' in ServciceNow: Response code %s: %s" % (tenant_name, response.status_code, response.text))
        #raise Exception("Error updating tenant CI for tenant '%s' in ServciceNow: Response code %s: %s" % (tenant_name, response.status_code, response.text))

    return tenant_id


# Append _deleted to the group name and change the operational status to retired
def retire_snow_tenant_cmp_group_ci(group_name, group_id):
    jbody = {"name": group_name.strip() + "_deleted_" + TIME_STAMP, "operational_status": SNOW_OP_STATUS_RETIRED }
    body = json.dumps(jbody)
    #print(body)
    url = 'https://%s/api/now/table/u_cmdb_ci_cmpresourcegroup/%s' % (SNOW_HOSTNAME, group_id)
    response = requests.put(url, auth=(SNOW_USER, SNOW_PWD), headers=SNOW_HEADERS ,data=body)
    if not response.ok:
        print("Error updating tenant CMP Group '%s' in ServciceNow: Response code %s: %s" % (group_name, response.status_code, response.text))
        #raise Exception("Error updating tenant CMP Group '%s' in ServciceNow: Response code %s: %s" % (group_name, response.status_code, response.text))

    return group_id
    url = "https://%s/api/accounts/?max=-1" % (morpheus_host)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + access_token
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error getting Tenants: Response code %s: %s" % (response.status_code, response.text))
        #raise Exception("Error getting Tenants: Response code %s: %s" % (response.status_code, response.text))
 
    data = response.json()
         
    for tenant in data["accounts"]:
        if tenant["name"] == tenant_name:
            return tenant["id"]
 
    print("Tenant %s not found..." % (tenant_name))
    #raise Exception("Tenant %s not found..." % (tenant_name))
    return 0

#----- Keycloak -----    

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


def delete_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, group_name, parent_group_id):
#Delete existing subGroup group_name that is child of parent_groupid
    child_group_id = get_keycloak_group_id_by_name(keycloak_host, keycloak_realm, group_name, keycloak_access_token, parent_group_id, 1)
    if child_group_id == -1:    #child group does not exist: nothing to do
        print("Group '%s' not found as a child of '%s'': nothing to do" % (group_name, parent_group_id))
    else:                       #delete existing child group
        print("deleting group '%s' with id: '%s'" % (group_name, child_group_id))
        header = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + access_token}
        url = "http://%s/admin/realms/%s/groups/%s" % (keycloak_host, keycloak_realm, child_group_id)
        response = requests.delete(url, headers=header, verify=KEYCLOAK_VERIFY_SSL_CERT)
        if not response.ok:
            print("Error deleting keycloak group '%s': Response code %s: %s" % (group_name, response.status_code, response.text))
            raise Exception("Error deleting keycloak group '%s': Response code %s: %s" % (group_name, response.status_code, response.text))


def delete_keycloack_client(keycloak_host, keycloak_realm, access_token, entityId):
#Delete existing keycloak client identified by client entityId
#Return -1 if client is not found
    header = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + access_token}
    url = "http://%s/admin/realms/%s/clients" % (keycloak_host, keycloak_realm)
    response = requests.get(url, headers=header, verify=KEYCLOAK_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error getting keycloak clients: Response code %s: %s" % (response.status_code, response.text))
        raise Exception("Error deleting keycloak clients: Response code %s: %s" % (response.status_code, response.text))

    data = response.json()
    for client in data:
        if client["clientId"] == entityId:
            print("Deleting keycloak client with id: %s" % (client["id"]))
            url = "http://%s/admin/realms/%s/clients/%s" % (keycloak_host, keycloak_realm, client["id"])
            response = requests.delete(url, headers=header, verify=KEYCLOAK_VERIFY_SSL_CERT)
            if not response.ok:
                print("Error deleting keycloak client: Response code %s: %s" % (response.status_code, response.text))
                raise Exception("Error deleting keycloak client: Response code %s: %s" % (response.status_code, response.text))
            else:
                return 0

    print("client '%s' not found: not deleted" % (entityId))
    return -1


def get_morpheus_tenant_id_by_name(morpheus_host, access_token, tenant_name):
#Get tenant id searching by its name
#Return -1 if tenant not found
    url = "https://%s/api/accounts/?max=-1" % (morpheus_host)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + access_token
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error getting Morpheus tenants: Response code: %s: %s" % (response.status_code, response.text))
        raise Exception("Error getting Morpheus tenants: Response code: %s: %s" % (response.status_code, response.text))

    data = response.json()

    for tenant in data["accounts"]:
        if tenant["name"] == tenant_name:
            return tenant["id"]

    print("Tenant %s not found in morpheus" % (tenant_name))
    return -1


def get_morpheus_idm_provider_settings(morpheus_host, access_token, parameter_name, tenant_id ):
#Get providerSettings.parameter for Identity connector MORPHEUS_IDM_NAME in tenant_id
#Return -1 if identity source is not found  
    url = "https://%s/api/accounts/%s/user-sources/?max=-1" % (morpheus_host, tenant_id)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + access_token
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error getting identity provider parameter %s for tenant: %s Response code %s: %s" % (parameter_name, tenant_id, response.status_code, response.text))
        raise Exception("Error getting identity provider parameter %s for tenant: '%s' Response code %s: %s" % (parameter_name, tenant_id, response.status_code, response.text))
 
    data = response.json()
         
    for src in data["userSources"]:
        if src["name"] == MORPHEUS_IDM_NAME:
            return src["providerSettings"][parameter_name]
 
    print("Parameter %s not found or Identity Source %s not existing in tenant %s..." % (parameter_name, MORPHEUS_IDM_NAME, tenant_id))
    return -1



##################
# MAIN CODE BODY #
##################

if I_AM_SURE != CONFIRMATION_STRING:
    print("Not deleting. Enter '%s' as confirmation string." % (CONFIRMATION_STRING))
    raise Exception("Not deleting. Enter '%s' as confirmation string." % (CONFIRMATION_STRING))
else:
    # ensure that the current script it running within a sub-tenant
    current_tenant = get_morpheus_current_tenant(MORPHEUS_HOST, MORPHEUS_TOKEN)
    if current_tenant["tenant_id"] != 1:
        print("Error: This script MUST be run within the Master Tenant!")
        raise Exception("Error: This script MUST be run within the Master Tenant!")
    
    ### SercviceNow ###

    if SNOW_SKIP:
        print("Skipping the retrement of ServiceNow Tenant and group CIs.....")
    else:
        # Get tenant IDs - could potentially have duplicates
        tenant_ci_sys_ids = get_snow_tenant_ci_sys_id(SNOW_HOSTNAME, MORPHEUS_TENANT)
    
        # Get CMP Groups for each Tenant sys_id
        all_cmp_groups = []
        for tenant_id in tenant_ci_sys_ids:
            print("Found Tenant: " + tenant_id)
            tenant_groups = get_snow_tenant_groups_sys_ids(SNOW_HOSTNAME, tenant_id)
            for group in tenant_groups:
                print("....Found Group: " + str(group))
                all_cmp_groups.append(group)
    
        # retire Tenants by adding _deleted to name and changing operational status to retired
        for tenant_id in tenant_ci_sys_ids:
            retire_snow_tenant_ci(MORPHEUS_TENANT, tenant_id)
    
        # retire Tenant Groups by adding _deleted to name and changing operational status to retired
        for group in all_cmp_groups:
            retire_snow_tenant_cmp_group_ci(group["name"], group["sys_id"])


    ### Keycloak ###

    # Generate keycloak access token
    print("Getting keycloak login token....")
    keycloak_access_token = get_keycloak_access_token(KEYCLOAK_HOST, KEYCLOAK_REALM, KEYCLOAK_REST_CLIENT_ID, KEYCLOAK_REST_CLIENT_SECRET)
    #print("keycloak access token: '%s'" % (keycloak_access_token))

    # Get group id for root of tenant role tree
    tenant_root_group_id = get_keycloak_group_id_by_name(KEYCLOAK_HOST, KEYCLOAK_REALM, KEYCLOAK_TENANT_ROLES_BRANCH, keycloak_access_token, "", 1)

    # Delete all groups for given tenant
    delete_keycloack_subgroup(KEYCLOAK_HOST, KEYCLOAK_REALM, keycloak_access_token, "ruoli tenant " + MORPHEUS_TENANT, tenant_root_group_id)

    if KEYCLOAK_DELETE_TENANT_CLIENT == "ON":

        #Get tenant id
        tenant_id = get_morpheus_tenant_id_by_name(MORPHEUS_HOST, MORPHEUS_TOKEN, MORPHEUS_TENANT)

        if tenant_id != -1:
            #Get entityId value from tenant identity source "Autenticazione con ARPA"
            entityId_value = get_morpheus_idm_provider_settings(MORPHEUS_HOST, MORPHEUS_TOKEN, "entityId", tenant_id)
            #print("Parameter: %s Value: %s" % ("entityId", entityId_value))

            if entityId_value != -1:    
                #Find and delete keycloak client named entityId 
                delete_keycloack_client(KEYCLOAK_HOST, KEYCLOAK_REALM, keycloak_access_token, entityId_value)

    
    ### Morpheus ###

    # lookup IDs
    tenant_id = get_morpheus_tenant_id_by_name(MORPHEUS_HOST, MORPHEUS_TOKEN, MORPHEUS_TENANT)
    tenant_role_id = get_morpheus_role_id_by_name(MORPHEUS_HOST, MORPHEUS_TENANT + "_Base_Role", MORPHEUS_TOKEN)
    # delete tenant
    print("Deleting Tenant with ID %s" % (tenant_id))
    delete_morpheus_object(MORPHEUS_HOST, "/api/accounts/" + str(tenant_id), MORPHEUS_TOKEN)
    # delete role
    print("Deleting Base Role with ID %s" % (tenant_role_id))
    delete_morpheus_object(MORPHEUS_HOST, "/api/roles/" + str(tenant_role_id), MORPHEUS_TOKEN)

    
    print("Done.")
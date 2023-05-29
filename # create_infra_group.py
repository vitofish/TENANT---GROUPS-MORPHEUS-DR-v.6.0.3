# create_infra_group.py
# DON'T run in MASTER TENANT - SUB TENANT ONLY
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
# Date: 02 Mar 2023
# Author: Fabrizio Montanini
# Email: fabrizio.montanini@dxc.com
# Change: morpheus-keycloak integration
#
# Date: 18 May 2023
# Author: Fabrizio Montanini
# Email: fabrizio.montanini@dxc.com
# Change: role management made compliant with morpheus 6.0.3 changes


import requests
import time
import json
import sys
#py2
#from urllib import urlencode
#py3
from urllib.parse import urlencode
import urllib3

urllib3.disable_warnings()
from morpheuscypher import Cypher

 
# pre-Script setup:
MORPHEUS_TENANT_CTLG_ROLE_SRC = "USER_CATALOG_TOSC"
MORPHEUS_TENANT_STD_ROLE_SRC = "USER_STD_TOSC"
KEYCLOAK_REST_CLIENT_ID = "rest-client"
KEYCLOAK_REST_CLIENT_SECRET = str(Cypher(morpheus=morpheus, ssl_verify=False).get("secret/KeycloakRestClientSecret"))
KEYCLOAK_HOST = "10.156.160.62:8080/auth"

 
#User Inputs 
#MORPHEUS_TENANT = morpheus['customOptions']['tenant'].strip().upper()
#MORPHEUS_TENANT_DESCRIPTION = morpheus['customOptions']['tenant_description'].strip()
#MORPHEUS_TENANT_INFRA_GROUPS = morpheus['customOptions']['infra_groups'].strip().upper()
LEGACY_GROUP_OPTION = morpheus['customOptions']['legacy_group_option']
if LEGACY_GROUP_OPTION == "on":
    REUSE_LEGACY = True
    try:
        LEGACY_GROUPS_LIST = morpheus['customOptions']['legacy_groups']
    except KeyError:
        LEGACY_GROUPS_LIST = ""
    if isinstance(LEGACY_GROUPS_LIST, list):
        MORPHEUS_TENANT_INFRA_GROUPS = (','.join(LEGACY_GROUPS_LIST)).strip().upper()
    else:
        MORPHEUS_TENANT_INFRA_GROUPS = LEGACY_GROUPS_LIST.strip().upper()
else:
    REUSE_LEGACY = False
    MORPHEUS_TENANT_INFRA_GROUPS = morpheus['customOptions']['new_infra_groups'].strip().upper()

#print("infra groups: \"'%s'\"" % (MORPHEUS_TENANT_INFRA_GROUPS))

MORPHEUS_TENANT_INFRA_GROUPS_CODES = morpheus['customOptions']['groups_code'].strip().upper()

#NAGIOS_TAG = morpheus['customOptions']['tenant_owner'].strip().upper()
NAGIOS_TAG_DICT = {'RTGN':'NAGIOS','CCTT':'NAGIOS','SST':'NAGIOS2'}

#Morpheus Globals
MORPHEUS_TENANT_ADMIN_ROLES = ['TENANT_ADMIN_TOSC']


#SNow Globals
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
MORPHEUS_VERIFY_SSL_CERT = False
MORPHEUS_HOST = morpheus['morpheus']['applianceHost']
MORPHEUS_TENANT_TOKEN = morpheus['morpheus']['apiAccessToken']
MORPHEUS_HEADERS = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + MORPHEUS_TENANT_TOKEN} 
MORPHEUS_IDM_NAME = "Autenticazione con ARPA"
KEYCLOAK_VERIFY_SSL_CERT = False
KEYCLOAK_LEGACY_ROLES_BRANCH="3. RUOLI_AMBIENTI_LEGACY"
KEYCLOAK_TENANT_ROLES_BRANCH="1. RUOLI_PER_TENANT"
KEYCLOAK_REALM = "Toscana"
KEYCLOAK_LOGOUT_REDIRECT_URL = "https://www.cloud.toscana.it/sct/logout/"

#############
# Functions #
#############

def get_morpheus_role_id_by_name(morpheus_host, role_name, access_token):
    url = "https://%s/api/roles/?max=-1" % (morpheus_host)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + access_token
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error getting role '%s': Response code %s: %s" % (role_name, response.status_code, response.text))
        raise Exception("Error getting role '%s': Response code %s: %s" % (role_name, response.status_code, response.text))
 
    data = response.json()
         
    for role in data["roles"]:
        if role["authority"] == role_name:
            return role["id"]
 
    print("Tenant base role %s not found..." % (role_name))
    raise Exception("Tenant base role %s not found..." % (role_name))


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

 
def get_snow_tenant_object_by_name(tenant_name):

    url='https://%s/api/now/table/u_cmdb_ci_tenant' % (SNOW_HOSTNAME)
    query_params = { "sysparm_query": "name=" + tenant_name + "^operational_status!=" + SNOW_OP_STATUS_RETIRED }
    response = requests.get(url, auth=(SNOW_USER, SNOW_PWD), headers=SNOW_HEADERS, params=query_params)
    if not response.ok:
        print("Error creating tenant CI for tenant '%s'in ServciceNow: Response code %s: %s" % (tenant_name, response.status_code, response.text))
        raise Exception("Error creating tenant CI for tenant '%s'in ServciceNow: Response code %s: %s" % (tenant_name, response.status_code, response.text))

    data = response.json()
    if len(data["result"]) == 0:
        print("Error: Operational Tenant '%s' not found in ServciceNow." % (tenant_name))
        raise Exception("Error: Operational Tenant '%s 'not found in ServciceNow." % (tenant_name))
    elif len(data["result"]) > 1:
        print("Error: Duplicate Tenant '%s' found in ServciceNow." % (tenant_name))
        raise Exception("Error: Duplicate Tenant '%s' found in ServciceNow." % (tenant_name))
    else:
        return_object = { 'tenant_snow_sysid': data["result"][0]['sys_id'], 'sub_system': data["result"][0]['u_sottosistema_cctt'], 'core_company': data["result"][0]['company']['value'] }
        return return_object


# 30/11/2022: added group_code parameter for Service Now Resource Group
def create_snow_cmp_group_record(tenant_sys_id, group, sub_system, core_company, group_code):
    jbody = {"name": group, "u_tenant": tenant_sys_id, "u_sottosistema_cctt": sub_system, "company": core_company, "u_codice_resource_group": group_code}
    body=json.dumps(jbody)
    #print(body)
    url = 'https://%s/api/now/table/u_cmdb_ci_cmpresourcegroup' % (SNOW_HOSTNAME)
    response = requests.post(url, auth=(SNOW_USER, SNOW_PWD), headers=SNOW_HEADERS ,data=body)
    if not response.ok:
        print("Error creating group '%s' record for tenant '%s'in ServciceNow: Response code %s: %s" % (tenant_sys_id, group, response.status_code, response.text))
        raise Exception("Error creating group '%s' record for tenant '%s'in ServciceNow: Response code %s: %s" % (tenant_sys_id, group, response.status_code, response.text))

    # data = response.json()
    # #print(data)
    # group_sys_id = data['result']['sys_id']
    # return group_sys_id
  
    # Check if Snow Group has been created or correctly moved into the tenant
    # Loop search to let Snow business rules complete if legacy group is detected
    for i in range(1,5):
        found = False
        snow_grp_sys_id = 0

        url = 'https://%s/api/now/table/u_cmdb_ci_cmpresourcegroup?name=%s&u_tenant=%s' % (SNOW_HOSTNAME, group, tenant_sys_id)
        response = requests.get(url, auth=(SNOW_USER, SNOW_PWD), headers=SNOW_HEADERS)
        if not response.ok:
            print("Error getting id for group '%s' record of tenant '%s'in ServiceNow: Response code %s: %s" % (tenant_sys_id, group, response.status_code, response.text))
            raise Exception("Error getting id for group '%s' record of tenant '%s'in ServiceNow: Response code %s: %s" % (tenant_sys_id, group, response.status_code, response.text))

        data = response.json()
        #print(data)

        for item in data['result']:
            if item["name"].lower() == group.lower():
                snow_grp_sys_id = item["sys_id"]
                #print(item["sys_id"])
                found = True
                break
        if found:
            break
        print("Waiting 2 sec to check if Snow Resource Group is created...")
        time.sleep(2)

    if snow_grp_sys_id == 0:
        print("Error: Snow Group with name '%s' not found in tenant_id: '%s'" % (group, tenant_sys_id))
        raise Exception("Error: Snow Group with name '%s' not found in tenant_id: '%s'" % (group, tenant_sys_id))
    else:
        #print("Snow Group created with sys_id: '%s'" % (snow_grp_sys_id))
        return snow_grp_sys_id


#30/11/2022: added group_code parameter for Morpheus Infra Group
def create_morpheus_group(morpheus_host, access_token, group_name, group_code):
    url = "https://%s/api/groups" % (morpheus_host)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + (access_token)
    b = {"group": {"name": group_name, "code": group_code, "location": None}}
    body = json.dumps(b)
    response = requests.post(url, headers=MORPHEUS_HEADERS, data=body, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error creating infrastructure group '%s': Response code %s: %s" % (group_name, response.status_code, response.text))
        raise Exception("Error creating infrastructure group '%s': Response code %s: %s" % (group_name, response.status_code, response.text))
    data = response.json()
    return data["group"]["id"]


def create_morpheus_role(morpheus_host, access_token, role_name, base_role_id, role_type):
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + (access_token)
    url = "https://%s/api/roles" % (morpheus_host)
    b = {"role": {"authority": role_name, "description": "", "baseRoleId": base_role_id, "roleType": role_type }}
    body = json.dumps(b)
    response = requests.post(url, headers=MORPHEUS_HEADERS, data=body, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error creating role '%s': Response code %s: %s" % (role_name, response.status_code, response.text))
        raise Exception("Error creating role '%s': Response code %s: %s" % (role_name, response.status_code, response.text))
 
    data = response.json()
    return data["role"]["id"]
 

def set_morpheus_role_groups_default(morpheus_host, access_token, role_id, access):
 
    url = "https://%s/api/roles/%s/update-permission" % (morpheus_host, role_id)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + (access_token)
    b = {"permissionCode": "ComputeSite", "access": access}
    body = json.dumps(b)
    response = requests.put(url, headers=MORPHEUS_HEADERS, data=body, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error updating default permission for role with id %s to 'read' group access: Response code %s: %s" % (role_id, response.status_code, response.text))
        raise Exception("Error updating default permission for role with id %s to 'read' group access: Response code %s: %s" % (role_id, response.status_code, response.text))
    data = response.json()


def set_morpheus_role_group_access(morpheus_host, access_token, role_id, group_id, access):
 
    url = "https://%s/api/roles/%s/update-group" % (morpheus_host, role_id)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + (access_token)
    b = {"groupId": group_id, "access": access}
    body = json.dumps(b)
    response = requests.put(url, headers=MORPHEUS_HEADERS, data=body, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error updating role(%s) group(%s) access(%s): Response code %s: %s" % (role_id, group_id, access, response.status_code, response.text))
        raise Exception("Error updating role(%s) group(%s) access(%s): Response code %s: %s" % (role_id, group_id, access, response.status_code, response.text))
    data = response.json()
 

def get_morpheus_idm_by_name(morpheus_host, access_token, idm_name):

    url = "https://%s/api/user-sources/?max=-1" % (morpheus_host)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + (access_token)
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error looking up identity source '%s': Response code %s: %s" % (idm_name, response.status_code, response.text))
        raise Exception("Error looking up identity source '%s': Response code %s: %s" % (idm_name, response.status_code, response.text))
    data = response.json()

    for idm in data["userSources"]:
        if idm["name"] == idm_name:
            return idm["id"]

    print("Identity source '%s' not found." % (idm_name))
    raise Exception("Identity source '%s' not found." % (idm_name))


def update_morpheus_saml_provider(morpheus_host, access_token, idm_id, idm_name, role_mappings):
 
    url = "https://%s/api/user-sources/%s" % (morpheus_host, idm_id)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + (access_token) 
 
    #b = {"userSource": {}}
    b = {"roleMappingNames": role_mappings }
    body = json.dumps(b)
    response = requests.put(url, headers=MORPHEUS_HEADERS, data=body, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error updating SAML IDM provider '%s': Response code %s: %s" % (idm_name, response.status_code, response.text))
        raise Exception("Error updating SAML IDM provider '%s': Response code %s: %s" % (idm_name, response.status_code, response.text))


def input_sanity_checks(morpheus_host, access_token, group_names_csv, group_codes_csv):

    # 17/03/2023: Added control to check for empty strings in Group Names
    # Check group names in INFRAGROUPS are not empty string
    for grp in group_names_csv.split(","):
        if grp == "":
            print("Input Error: Group Name cannot be empty string")
            raise Exception("Input Error: Group Name cannot be empty string")

    # Check that names do not contain spaces
    for infra_group in group_names_csv.split(','):
        if ' ' in infra_group.strip() or infra_group.strip() == "":
            print("Infra Group name '%s' contains spaces or is blank. Not allowed." % (infra_group))
            raise Exception("Infra Group name '%s' contains spaces or is blank. Not allowed." % (infra_group))
 
    for infra_group_code in group_codes_csv.split(','):
        if ' ' in infra_group_code.strip() or infra_group_code.strip() == "":
            print("Infra Group name '%s' contains spaces or is blank. Not allowed." % (infra_group_code))
            raise Exception("Infra Group name '%s' contains spaces or is blank. Not allowed." % (infra_group_code))    

    # 30/11/2022: Added control to check group_code is set for every Resource Group
    # Check INFRA_GROUPS and INFRAGROUP_CODES have the same number of elements
    if len(group_names_csv.split(",")) > len(group_codes_csv.split(",")):
        print("Error creating groups: each resource group must have a code")
        raise Exception("Error creating groups: each resource group must have a code")

    # 30/11/2022: Added control to check group_code length is max 4 chars
    # Check codes in INFRAGROUP_CODES have max lenght 4 chars
    for code in group_codes_csv.split(","):
        if len(code.strip()) > 3:
            print("Error, code lenght must be max 3 chars, wrong code: " +code.strip())
            raise Exception("Error, code lenght must be max 3 chars, wrong code: " +code.strip())

    # 02/12/2022: Added control to check duplicates in input
    # Check if any duplicate entry in input
    for input_csv in [group_names_csv, group_codes_csv]:
       INPUT_LIST=input_csv.split(",")
       SPLIT_LIST=[]
       for elem in INPUT_LIST:
           SPLIT_LIST.append(elem.strip())
       if len(INPUT_LIST) != len(set(SPLIT_LIST)):
          print("duplicates entries found in input for groups or group codes")
          raise Exception("duplicates entries found in input for groups or group codes")

    # 02/12/2022: Added control to check existing objects
    # Check if Group Names or Group Codes are already used in this tenant
    url = "https://%s/api/groups/?max=-1" % (morpheus_host)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + access_token
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error getting groups for tenant: Response Code %s: %s" % (response.status_code, response.text))
        raise Exception("Error getting groups for tenant: Response Code %s: %s" % (response.status_code, response.text))
    data = response.json()
    # print(json.dumps(data, indent=4))

    for group in group_names_csv.split(","):
        group_index = group_names_csv.split(",").index(group)
        group_code = group_codes_csv.split(",")[group_index].strip()
        group_name = group.strip()
             
        for group in data["groups"]:
            if group["name"] == group_name:
                print("Tenant group name %s already used in this tenant..." % (group_name))
                raise Exception("Tenant group name %s already used in this tenant..." % (group_name))
            elif group["code"] == group_code:
                print("Tenant group code %s already used in this tenant..." % (group_code))
                raise Exception("Tenant group code %s already used in this tenant..." % (group_code))

#---- keycloak integration functions ----

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
#Depends on:
# - get_keycloak_access_token

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


def create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, group_name, parent_group_id):
#Create new subGroup group_name as child of parent_groupid if it does not exist
#Returns group ID of new subGroup or group ID of existing subGroup with same name
#Depends on:
# - get_keycloak_access_token
# - get_keycloak_group_id_by_name

    child_group_id = get_keycloak_group_id_by_name(KEYCLOAK_HOST, KEYCLOAK_REALM, group_name, keycloak_access_token, parent_group_id, 1)
    if child_group_id == -1:    #child group does not exist: create and return group ID
        url = "http://%s/admin/realms/%s/groups/%s/children" % (keycloak_host, keycloak_realm, parent_group_id)
        header = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + access_token}
        b = {"name": group_name}
        body = json.dumps(b)    
        response = requests.post(url, headers=header, data=body, verify=KEYCLOAK_VERIFY_SSL_CERT)
        if not response.ok:
            print("Error creating keycloak group '%s': Response code %s: %s" % (group_name, response.status_code, response.text))
            raise Exception("Error creating keycloak group '%s': Response code %s: %s" % (group_name, response.status_code, response.text))
        return get_keycloak_group_id_by_name(KEYCLOAK_HOST, KEYCLOAK_REALM, group_name, keycloak_access_token, parent_group_id, 1)
    else:                       #child group exist: skip creation and return group ID
        return child_group_id


def move_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, group_name, group_id, parent_group_id):
#Move existing subGroup (group_name, group_id) as child of parent_groupid
#Depends on:
# - get_keycloak_access_token

    url = "http://%s/admin/realms/%s/groups/%s/children" % (keycloak_host, keycloak_realm, parent_group_id)
    header = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + access_token}
    b = {"id": group_id, "name": group_name}
    body = json.dumps(b)    
    response = requests.post(url, headers=header, data=body, verify=KEYCLOAK_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error moving keycloak group '%s': Response code %s: %s" % (group_name, response.status_code, response.text))
        raise Exception("Error moving keycloak group '%s': Response code %s: %s" % (group_name, response.status_code, response.text))


def rename_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, new_group_name, group_id):
#Rename existing subGroup (group_name, group_id) as child of parent_groupid
#Depends on:
# - get_keycloak_access_token

    url = "http://%s/admin/realms/%s/groups/%s" % (keycloak_host, keycloak_realm, group_id)
    header = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + access_token}
    b = {"name": new_group_name}
    body = json.dumps(b)    
    response = requests.put(url, headers=header, data=body, verify=KEYCLOAK_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error renaming keycloak group '%s': Response code %s: %s" % (new_group_name, response.status_code, response.text))
        raise Exception("Error renaming keycloak group '%s': Response code %s: %s" % (new_group_name, response.status_code, response.text))


def create_keycloack_groups_for_morpheus_infragroup(keycloak_host, keycloak_realm, access_token, tenant_name, infra_groups_list):
#Create Keycloak group hierachy for new infra groups in morpheus tenant
#Existing groups are not modified: only missing groups are created
#If REUSE_LEGACY == True, search for SNOW legacy groups ad move them to tenant subtree then rename it adding tenant name
#Depends on:
# - get_keycloak_access_token
# - get_keycloak_group_id_by_name
# - create_keycloack_subgroup
# - rename_keycloack_subgroup
# - move_keycloack_subgroup

    keycloak_tenant_base_name="ruoli tenant " + tenant_name
    tenant_base_id = get_keycloak_group_id_by_name(keycloak_host, keycloak_realm, keycloak_tenant_base_name, access_token, "")
    if tenant_base_id == -1:
        print("Creating tenant folder: '%s'" % ("ruoli tenant " + tenant_name))
        keycloak_tenant_base_id = get_keycloak_group_id_by_name(keycloak_host, keycloak_realm, KEYCLOAK_TENANT_ROLES_BRANCH, access_token, "")
        tenant_base_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "ruoli tenant " + tenant_name, keycloak_tenant_base_id)

    print("Creating group hierarchy for tenant '%s'" % (tenant_name))

    #create CMP groups
    print("Creating folder: '%s'" % ("ruoli CMP " + tenant_name))
    cmp_base_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "ruoli CMP " + tenant_name, tenant_base_id)
    print("Creating role  :   '%s'" % ("CMP_" + tenant_name))
    child_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "CMP_" + tenant_name, cmp_base_id)
    print("Creating role  :   '%s'" % ("CMP_" + tenant_name + "_ADMIN"))
    child_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "CMP_" + tenant_name + "_ADMIN", cmp_base_id)
    for resgroup in infra_groups_list.split(','):
        resgroup = resgroup.strip()
        print("Creating folder:   '%s'" % ("ruoli CMP " + tenant_name + "_" + resgroup))
        parent_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "ruoli CMP " + tenant_name + "_" + resgroup, cmp_base_id)
        for role in "_USERCTLG", "_USERSTD":
            print("Creating role  :      '%s'" % ("CMP_" + tenant_name + "_" + resgroup + role))
            child_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "CMP_" + tenant_name + "_" + resgroup + role, parent_id)

    #create NAGIOS groups
    print("Creating folder: '%s'" % ("ruoli NAGIOS " + tenant_name))
    nagios_base_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "ruoli NAGIOS " + tenant_name, tenant_base_id)
    #print("Creating role  :   '%s'" % (NAGIOS_TAG + "_" + tenant_name + "_USER"))
    #child_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, NAGIOS_TAG + "_" + tenant_name + "_USER", nagios_base_id)
    for resgroup in infra_groups_list.split(','):
        resgroup = resgroup.strip()
        print("Creating folder:   '%s'" % ("ruoli NAGIOS " + tenant_name + "_" + resgroup))
        parent_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "ruoli NAGIOS " + tenant_name + "_" + resgroup, nagios_base_id)
        print("Creating role  :      '%s'" % (NAGIOS_TAG + "_" + tenant_name + "_" + resgroup + "_USER"))
        child_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, NAGIOS_TAG + "_" + tenant_name + "_" + resgroup + "_USER", parent_id)

    #create SNOW groups
    snow_base_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "ruoli SNOW " + tenant_name, tenant_base_id)
    print("Creating folder: '%s'" % ("ruoli SNOW " + tenant_name))
    child_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "SNOW_" + tenant_name + "_DEC", snow_base_id)
    print("Creating role  :   '%s'" % ("SNOW_" + tenant_name + "_DEC"))
    for resgroup in infra_groups_list.split(','):
        resgroup = resgroup.strip()
        parent_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "ruoli SNOW " + tenant_name + "_" + resgroup, snow_base_id)
        print("Creating folder:   '%s'" % ("ruoli SNOW " + tenant_name + "_" + resgroup))
        legacy_root_id = get_keycloak_group_id_by_name(keycloak_host, keycloak_realm, KEYCLOAK_LEGACY_ROLES_BRANCH, access_token, "")
        reused_legacy_group = False
        for role in "_RESPONSABILE", "_USERSTD":
            if REUSE_LEGACY:
                new_group_id = get_keycloak_group_id_by_name(keycloak_host, keycloak_realm, "SNOW_" + tenant_name + "_" + resgroup + role, access_token, parent_id, 1)
                legacy_group_id = get_keycloak_group_id_by_name(keycloak_host, keycloak_realm, "SNOW_" + resgroup + role, access_token, legacy_root_id)
                if new_group_id == -1 and legacy_group_id != -1:
                    reused_legacy_group = True
                    move_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "SNOW_" + resgroup + role, legacy_group_id, parent_id)
                    rename_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "SNOW_" + tenant_name + "_" + resgroup  + role, legacy_group_id)
                    print("Reusing role   :      '%s'" % ("SNOW_" + resgroup + role))
                else:
                    child_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "SNOW_" + tenant_name + "_" + resgroup + role, parent_id)
                    print("Creating role  :      '%s'" % ("SNOW_" + tenant_name + "_" + resgroup + role))
            else:
                child_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "SNOW_" + tenant_name + "_" + resgroup + role, parent_id)
                print("Creating role  :      '%s'" % ("SNOW_" + tenant_name + "_" + resgroup + role))
        if reused_legacy_group:
            legacy_group_root_id = get_keycloak_group_id_by_name(keycloak_host, keycloak_realm, "ruoli SNOW " + resgroup, access_token, legacy_root_id)
            if legacy_group_root_id != -1:
                rename_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "ruoli SNOW " + resgroup + "_migrated", legacy_group_root_id)


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


##################
# MAIN CODE BODY #
##################

# ensure that the current script it running within a sub-tenant
current_tenant = get_morpheus_current_tenant(MORPHEUS_HOST, MORPHEUS_TENANT_TOKEN)
if current_tenant["tenant_id"] == 1:
    print("Error: This script should NOT run within the Master Tenant!")
    raise Exception("Error: This script should NOT run within the Master Tenant!")

tenant_name = current_tenant["tenant_name"]

# ensure current user has admin roles to run the script
MORPHEUS_TENANT_ADMIN_ROLES.insert(0, tenant_name + "_ADMIN")
authorized_user = check_user_authorization(MORPHEUS_HOST, MORPHEUS_TENANT_TOKEN, MORPHEUS_TENANT_ADMIN_ROLES)
if authorized_user == False:
    print("Error: You must be Tenant Admin to run this script")
    raise Exception("Error: You must be Tenant Admin to run this script")

if 1 == 1:

    input_sanity_checks(MORPHEUS_HOST, MORPHEUS_TENANT_TOKEN, MORPHEUS_TENANT_INFRA_GROUPS, MORPHEUS_TENANT_INFRA_GROUPS_CODES)

    # Get the Tenant Admin Role Id 
    print("Get the Tenant User Admin Role Id....")
    tenant_admin_role_id = get_morpheus_role_id_by_name(MORPHEUS_HOST, tenant_name.upper() + "_ADMIN", MORPHEUS_TENANT_TOKEN)
    print("Get the Tenant Catalog User SOURCE Role Id....")
    catalog_role_base_id = get_morpheus_role_id_by_name(MORPHEUS_HOST, MORPHEUS_TENANT_CTLG_ROLE_SRC, MORPHEUS_TENANT_TOKEN)
    print("Get the Tenant Standard User SOURCE Role Id....")
    standard_role_base_id = get_morpheus_role_id_by_name(MORPHEUS_HOST, MORPHEUS_TENANT_STD_ROLE_SRC, MORPHEUS_TENANT_TOKEN)

    # Dict to store role mappings for IDM
    idm_role_mappings = {} 
    # Add admin role IDM mapping
    idm_role_mappings[tenant_admin_role_id] = "CMP_" + tenant_name.upper() + "_ADMIN"
    
    #Loop through infrastrcure groups to create
    print("Looping through infra groups to create....")
    for group in MORPHEUS_TENANT_INFRA_GROUPS.split(","):
        group_index = MORPHEUS_TENANT_INFRA_GROUPS.split(",").index(group)
        group_code = MORPHEUS_TENANT_INFRA_GROUPS_CODES.split(",")[group_index].strip()
        group_name = group.strip()

        # Create Infra Group
        print(".....creating infra group " + group_name, "with code " +group_code)
        group_id = create_morpheus_group(MORPHEUS_HOST, MORPHEUS_TENANT_TOKEN, group_name, group_code)
    
        # Create standard and catalog roles for tenant
        print("............creating tenant roles for infra group " + group_name)
        tenant_catalog_role_name = "%s_%s_USERCTLG" % (tenant_name.upper(), group_name.upper())
        tenant_standard_role_name = "%s_%s_USERSTD" % (tenant_name.upper(), group_name.upper())
        tenant_catalog_role_id = create_morpheus_role(MORPHEUS_HOST, MORPHEUS_TENANT_TOKEN, tenant_catalog_role_name, catalog_role_base_id, "user")
        tenant_standard_role_id = create_morpheus_role(MORPHEUS_HOST, MORPHEUS_TENANT_TOKEN, tenant_standard_role_name, standard_role_base_id, "user")
        set_morpheus_role_groups_default(MORPHEUS_HOST, MORPHEUS_TENANT_TOKEN, tenant_catalog_role_id, "none")
        set_morpheus_role_groups_default(MORPHEUS_HOST, MORPHEUS_TENANT_TOKEN, tenant_standard_role_id, "none")
    
        # Assign relevant group access to tenant roles
        print("............assign role access for infra group " + group_name)
        set_morpheus_role_group_access(MORPHEUS_HOST, MORPHEUS_TENANT_TOKEN, tenant_catalog_role_id, group_id, "full")
        set_morpheus_role_group_access(MORPHEUS_HOST, MORPHEUS_TENANT_TOKEN, tenant_standard_role_id, group_id, "read")
        set_morpheus_role_group_access(MORPHEUS_HOST, MORPHEUS_TENANT_TOKEN, tenant_admin_role_id, group_id, "full")
    
        # Add role IDM mappings
        idm_role_mappings[tenant_catalog_role_id] = "CMP_" + tenant_catalog_role_name
        idm_role_mappings[tenant_standard_role_id] = "CMP_" + tenant_standard_role_name
    
        # Add Group CMP record in SNow
        if SNOW_SKIP:
            print("Skipping the creation of ServiceNow Tenant and group CIs.....")
        else:
            snow_tenant_obj = get_snow_tenant_object_by_name(tenant_name)        
            # 30/11/2022: changed to add group_code in Service Now
            #create_snow_cmp_group_record(snow_tenant_obj["tenant_snow_sysid"], group_name, snow_tenant_obj['sub_system'], snow_tenant_obj['core_company'])
            group_sys_id = create_snow_cmp_group_record(snow_tenant_obj["tenant_snow_sysid"], group_name, snow_tenant_obj['sub_system'], snow_tenant_obj['core_company'], group_code)
            print("Created group '%s' with code '%s' and id '%s' in ServiceNow" % (group_name, group_code, group_sys_id))

    print("Updating SAML Identity Provider for tenant....")
    idm_id = get_morpheus_idm_by_name(MORPHEUS_HOST, MORPHEUS_TENANT_TOKEN, MORPHEUS_IDM_NAME)
    update_morpheus_saml_provider(MORPHEUS_HOST, MORPHEUS_TENANT_TOKEN, idm_id, MORPHEUS_IDM_NAME, idm_role_mappings)

    # Generate keycloak access token 
    print("Getting keycloak login token....")
    keycloak_access_token = get_keycloak_access_token(KEYCLOAK_HOST, KEYCLOAK_REALM, KEYCLOAK_REST_CLIENT_ID, KEYCLOAK_REST_CLIENT_SECRET)
    #print("keycloak access token: '%s'" % (keycloak_access_token))


    # CREAZIONE STRUTTURA PER NUOVI RESOURCE GROUP MORPHEUS
    snow_tenant_obj = get_snow_tenant_object_by_name(tenant_name)
    NAGIOS_TAG = NAGIOS_TAG_DICT.get(snow_tenant_obj['sub_system'].upper(), 'NAGIOS')
    create_keycloack_groups_for_morpheus_infragroup(KEYCLOAK_HOST, KEYCLOAK_REALM, keycloak_access_token, tenant_name, MORPHEUS_TENANT_INFRA_GROUPS)

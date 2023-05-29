# tenant_onboard.py
# Always run in MASTER TENANT
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
import json
import time
import re
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
MORPHEUS_TENANT_ADMIN_ROLE_SRC = "TENANT_ADMIN_TOSC"
MORPHEUS_TENANT_DEFAULT_ROLE = "USER_STD_TOSC"
MORPHEUS_TENANT_BASE_ROLE = "TENANT_BASE_ROLE_TOSC"
MORPHEUS_SAML_PUB_KEY = str(Cypher(morpheus=morpheus, ssl_verify=False).get("secret/dxcsamlpubkey"))
SVC_MORPHEUS_VMWARE_SECRET = str(Cypher(morpheus=morpheus, ssl_verify=False).get("secret/SVC_Morpheus_VMWARE"))

KEYCLOAK_CLIENT_ID = "rest-client"
KEYCLOAK_CLIENT_SECRET = str(Cypher(morpheus=morpheus, ssl_verify=False).get("secret/KeycloakRestClientSecret"))
KEYCLOAK_HOST = "10.156.160.62:8080/auth"


# User Inputs
MORPHEUS_TENANT = morpheus['customOptions']['tenant'].strip().upper()
MORPHEUS_TENANT_DESCRIPTION = morpheus['customOptions']['tenant_description'].strip()
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
    REUSE_LEGACY = True
    MORPHEUS_TENANT_INFRA_GROUPS = morpheus['customOptions']['new_infra_groups'].strip().upper()

#print("infra groups: \"'%s'\"" % (MORPHEUS_TENANT_INFRA_GROUPS))

MORPHEUS_TENANT_INFRA_GROUPS_CODES = morpheus['customOptions']['groups_code'].strip().upper()
MORPHEUS_TENANT_SUBDOMAIN = MORPHEUS_TENANT
SUB_SYSTEM = morpheus['customOptions']['sottosistema'].strip()
CORE_COMPANY = morpheus['customOptions']['coreCompany'].strip()

#NAGIOS_TAG = morpheus['customOptions']['tenant_owner'].strip().upper()
NAGIOS_TAG_DICT = {'RTGN':'NAGIOS','CCTT':'NAGIOS','SST':'NAGIOS2'}
NAGIOS_TAG = NAGIOS_TAG_DICT.get(SUB_SYSTEM.upper(), 'NAGIOS')


#Tenant Globals
MORPHEUS_TENANT_ADMIN_PASSWORD = str(Cypher(morpheus=morpheus, ssl_verify=False).get("secret/defaultpwd"))
MORPHEUS_TENANT_ADMIN_EMAIL = "tenantadmin@dxc.it"
MORPHEUS_TENANT_ADMIN_LASTNAME = "Admin"

MORPHEUS_CLUSTER_USER_PASSWORD = str(Cypher(morpheus=morpheus, ssl_verify=False).get("secret/clusteruserpwd"))
MORPHEUS_CLUSTER_USER_ROLE_SRC = "TENANT_ADMIN_TOSC"
MORPHEUS_CLUSTER_USER_EMAIL = "ClusterUser@morpheusdata.com"
MORPHEUS_CLUSTER_USER_USERNAME = "ClusterUser"
MORPHEUS_CLUSTER_USER_LASTNAME = "User"
MORPHEUS_CLUSTER_USER_FIRSTNAME = "Cluster"

SAML_REDIRECT_URL = "https://" + KEYCLOAK_HOST + "/realms/Toscana/protocol/saml"
SAML_LOGOUT_URL = "https://" + KEYCLOAK_HOST + "/realms/Toscana/protocol/saml"
SAML_INCLUDE_REQUEST_PARAM = False

 
# Morpheus Globals
MORPHEUS_VERIFY_SSL_CERT = False
MORPHEUS_HOST = morpheus['morpheus']['applianceHost']
MORPHEUS_MASTER_TENANT_TOKEN = morpheus['morpheus']['apiAccessToken']
MORPHEUS_HEADERS = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + MORPHEUS_MASTER_TENANT_TOKEN}
MORPHEUS_IDM_NAME = "Autenticazione con ARPA"

#SNow Globals
SNOW_HEADERS = { "Content-Type": "application/json", "Accept": "application/json" }
SNOW_HOSTNAME = "regionetoscanatest.service-now.com"
SNOW_USER = 'morpheus'
SNOW_PWD = str(Cypher(morpheus=morpheus, ssl_verify=False).get("secret/dxcsnowpass"))

if 'skip_snow_operations' in morpheus['customOptions']:
    SNOW_SKIP = bool(morpheus['customOptions']['skip_snow_operations'])
else:
    SNOW_SKIP = False

# Keycloak Globals
KEYCLOAK_VERIFY_SSL_CERT = False
KEYCLOAK_LEGACY_ROLES_BRANCH="3. RUOLI_AMBIENTI_LEGACY"
KEYCLOAK_TENANT_ROLES_BRANCH="1. RUOLI_PER_TENANT"
KEYCLOAK_REALM = "Toscana"
KEYCLOAK_LOGOUT_REDIRECT_URL = "https://www.cloud.toscana.it/sct/logout/"

#############
# Functions #
#############


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


def get_morpheus_clouds_list(morpheus_host, access_token):
    url = "https://%s/api/zones/?max=-1" % (morpheus_host)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + access_token
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error getting clouds list: Response code %s: %s" % (response.status_code, response.text))
        raise Exception("Error getting clouds list: Response code %s: %s" % (response.status_code, response.text))
 
    data = response.json()

    clouds = []     
    for cloud in data["zones"]:
        clouds.append({ "id": cloud["id"], "name": cloud["name"] })

    return clouds;    
 

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
 
 
def get_morpheus_idm_id_by_name(morpheus_host, idm_name, tenant_name, access_token):
    url = "https://%s/api/user-sources/?max=-1" % (morpheus_host)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + access_token
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error getting identity provider '%s': Response code %s: %s" % (idm_name, response.status_code, response.text))
        raise Exception("Error getting identity provider '%s': Response code %s: %s" % (idm_name, response.status_code, response.text))
 
    data = response.json()
         
    for src in data["userSources"]:
        if src["name"] == idm_name and src["account"]["name"] == tenant_name:
            return src["id"]
 
    print("Identity provider %s not found for tenant %s..." % (idm_name, tenant_name))
    raise Exception("Identity provider %s not found for tenant %s..." % (idm_name, tenant_name))
 
 
def create_morpheus_tenant(morpheus_host, tenant_name, tenant_description, sub_domain, role_id, access_token):
    url = "https://%s/api/accounts" % (morpheus_host)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + access_token         
    b = {"account": {"name": tenant_name, "subdomain": sub_domain, "description": tenant_description,"role": {"id": int(role_id)}, "currency": "EUR"}}
    body = json.dumps(b)
    response = requests.post(url, headers=MORPHEUS_HEADERS, data=body, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error creating tenant '%s': Response code %s: %s" % (tenant_name, response.status_code, response.text))
        raise Exception("Error creating tenant '%s': Response code %s: %s" % (tenant_name, response.status_code, response.text))
 
    data = response.json()      
    tenant_id = data['account']['id']
    return tenant_id
 
 
def create_morpheus_tenant_user(morpheus_host, tenant_id, username, firstname, lastname, email, tenant_user_role_id, access_token, passwd):
    #log("Creating subtenant admin user")
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + access_token
    url = "https://%s/api/accounts/%s/users" % (morpheus_host, tenant_id)
    b = {"user": {"username": username }}
    b["user"]["email"] = email
    b["user"]["firstName"] = firstname
    b["user"]["lastName"] = lastname 
    b["user"]["password"] = passwd
    b["user"]["roles"] = [{"id": tenant_user_role_id}]
    body=json.dumps(b)
    response = requests.post(url, headers=MORPHEUS_HEADERS, data=body, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error creating tenant user '%s': Response code %s: %s" % (username, response.status_code, response.text))
        raise Exception("Error creating tenant user '%s': Response code %s: %s" % (username, response.status_code, response.text))
 
    data = response.json()
    return data["user"]["id"]
 
 
def get_morpheus_access_token(morpheus_host, tenant_name, tenant_id, user_name, password):
    header = {"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"}
    url = "https://%s/oauth/token?grant_type=password&scope=write&client_id=morph-api" % (morpheus_host)
    user = "%s\\%s" % (tenant_id, user_name)
    b = {'username': user, 'password': password}
    body=urlencode(b)
    response = requests.post(url, headers=header, data=body, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error getting tenant '%s' access token: Response code %s: %s" % (tenant_name, response.status_code, response.text))
        raise Exception("Error getting tenant '%s' access token: Response code %s: %s" % (tenant_name, response.status_code, response.text))
 
    data = response.json()
    access_token = data['access_token']
    return access_token
 
 
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
 
 
def assign_morpheus_role_to_user(morpheus_host, access_token, role_id, user_id):
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + (access_token)
    url = "https://%s/api/users/%s" % (morpheus_host, user_id)
    b = {"user": {"roles": {"id": role_id }}}
    body = json.dumps(b)
    response = requests.put(url, headers=MORPHEUS_HEADERS, data=body, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error assigning role '%s' to user '%s: Response code %s: %s" % (role_id, user_id, response.status_code, response.text))
        raise Exception("Error assigning role '%s' to user '%s: Response code %s: %s" % (role_id, user_id, response.status_code, response.text))
 
    return True
 
 
def clear_tenant_groups(morpheus_host, access_token):
    url = "https://%s/api/groups/?max=-1" % (morpheus_host)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + (access_token)
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    data = response.json()
 
    for i in data['groups']:
        url="https://%s/api/groups/%s" % (morpheus_host, i["id"])
        response = requests.delete(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
        if not response.ok:
            print("Error removing existing infrastructure group with id %s from tenant: Response code %s: %s" % (i["id"], response.status_code, response.text))
            raise Exception("Error removing existing infrastructure group with id %s from tenant: Response code %s: %s" % (i["id"], response.status_code, response.text))
 
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


def set_morpheus_role_clouds_default(morpheus_host, access_token, role_id, access):
 
    url = "https://%s/api/roles/%s/update-permission" % (morpheus_host, role_id)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + (access_token)
    b = {"permissionCode": "ComputeZone", "access": access}
    body = json.dumps(b)
    response = requests.put(url, headers=MORPHEUS_HEADERS, data=body, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error updating default permission for role with id %s to 'read' cloud access: Response code %s: %s" % (role_id, response.status_code, response.text))
        raise Exception("Error updating default permission for role with id %s to 'read' cloud access: Response code %s: %s" % (role_id, response.status_code, response.text))
    data = response.json()
 
 
def set_morpheus_tenant_role_cloud_access_by_suffix(morpheus_host, access_token, tenant_role_id, cloud_suffix, clouds_list):

    cloud_suffix_length = len(cloud_suffix) * -1
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + (access_token)
    url = "https://%s/api/roles/%s/update-cloud" % (morpheus_host, tenant_role_id)
    for cloud in clouds_list:
        x = re.search("^.*[^a-zA-Z0-9][a-zA-Z0-9]+$", cloud["name"])
        if x and cloud["name"][cloud_suffix_length:] == cloud_suffix:
            #print("Cloud " + cloud["name"] + " should be added")
            b = {"cloudId": cloud["id"], "access": "full"}
        else:
            b = {"cloudId": cloud["id"], "access": "none"}
 
        body = json.dumps(b)
        response = requests.put(url, headers=MORPHEUS_HEADERS, data=body, verify=MORPHEUS_VERIFY_SSL_CERT)
        if not response.ok:
            print("Error updating cloud access to '%s' for role with id %s: Response code %s: %s" % (cloud["id"], tenant_role_id, response.status_code, response.text))
            raise Exception("Error updating cloud access to '%s' for role with id %s: Response code %s: %s" % (cloud["id"], tenant_role_id, response.status_code, response.text))


def set_morpheus_role_group_access(morpheus_host, access_token, role_id, group_id, access):
 
    url = "https://%s/api/roles/%s/update-group" % (morpheus_host, role_id)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + (access_token)
    b = {"groupId": group_id, "access": access}
    body = json.dumps(b)
    response = requests.put(url, headers=MORPHEUS_HEADERS, data=body, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error updating role(%s) group(%s) access(%s): Response code %s: %s" % (role_id, group_id, access, response.status_code, response.text))
        raise Exception("Error updating role(%s) group(%s) access(%s): Response code %s: %s" % (role_id, group_id, access, response.status_code, response.text))


def get_morpheus_tenant_id_by_name(morpheus_host, tenant_name, access_token):
 
    url = "https://%s/api/accounts/?max=-1" % (morpheus_host)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + (access_token)
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error getting id for tenant '%s': Response code %s: %s" % (tenant_name, response.status_code, response.text))
        raise Exception("Error getting id for tenant '%s': Response code %s: %s" % (tenant_name, response.status_code, response.text))
 
    data = response.json()
    for tenant in data["accounts"]:
        if tenant["name"] == tenant_name:
            return tenant["id"]
 
    print("tenant '%s' not found." % (tenant_name))
    raise Exception("tenant '%s' not found." % (tenant_name))
 
 
def get_morpheus_groups(morpheus_host, access_token):
    url = "https://%s/api/groups/?max=-1" % (morpheus_host)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + (access_token)
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error getting groups: Response code %s: %s" % (response.status_code, response.text))
        raise Exception("Error getting groups: Response code %s: %s" % (response.status_code, response.text))
 
    data = response.json()
    group_ids = [x["id"] for x in data["groups"] if 1 == 1]
    return group_ids
   

def create_morpheus_cypher_secret(morpheus_host, access_token, key, token):
    url = "https://%s/api/cypher/secret/%s?type=string&ttl=0" % (morpheus_host, key)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + (access_token)
    response = requests.put(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT, data=json.dumps({ "value": token }))
    if not response.ok:
        print("Error creating cypher secret: Response code %s: %s" % (response.status_code, response.text))
        raise Exception("Error creating cypher secret: Response code %s: %s" % (response.status_code, response.text))
   
 
def create_morpheus_saml_provider(morpheus_host, access_token, tenant_id, role_mappings, tenant_name, default_role_id):
 
    url = "https://%s/api/accounts/%s/user-sources" % (morpheus_host, tenant_id)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + (access_token) 
 
    b = {"userSource": { "type": "saml", "name": MORPHEUS_IDM_NAME, "config": {} }}
    b["userSource"]["defaultAccountRole"] = {}
    b["userSource"]["defaultAccountRole"]["id"] = default_role_id
    #b["userSource"]["allowCustomMappings"] = Tru
    b["userSource"]["config"]["url"] = SAML_REDIRECT_URL
    b["userSource"]["config"]["doNotIncludeSAMLRequest"] = SAML_INCLUDE_REQUEST_PARAM
    b["userSource"]["config"]["logoutUrl"] = SAML_LOGOUT_URL
    b["userSource"]["config"]["roleAttributeName"] = "memberOf"
    b["userSource"]["config"]["requiredAttributeValue"] = "CMP_" + tenant_name.upper()
    b["roleMappingNames"] = role_mappings
    b["userSource"]["config"]["doNotValidateSignature"] = False
    b["userSource"]["config"]["forceAuthn"] = False
    b["userSource"]["config"]["publicKey"] = MORPHEUS_SAML_PUB_KEY
 
    body = json.dumps(b)
    response = requests.post(url, headers=MORPHEUS_HEADERS, data=body, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error creating SAML provider on tenant '%s': Response code %s: %s" % (tenant_id, response.status_code, response.text))
        raise Exception("Error creating SAML provider on tenant '%s': Response code %s: %s" % (tenant_id, response.status_code, response.text))
    data = response.json()
    #print(data)
    saml_provider_id = data['userSource']['id']
    print(".....SAML provider id is: '%s'" %(saml_provider_id ))

    #Set forceAuthn = False for the new SAML provider
    url = "https://%s/api/accounts/%s/user-sources/%s" % (morpheus_host, tenant_id, saml_provider_id)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + (access_token)
    b = {"userSource": {"config": {"forceAuthn": False}}}
    body = json.dumps(b)
    response = requests.put(url, headers=MORPHEUS_HEADERS, data=body, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error enabling SSO in SAML provider on tenant '%s': Response code %s: %s" % (tenant_id, response.status_code, response.text))
        raise Exception("Error enabling SSO in SAML provider on tenant '%s': Response code %s: %s" % (tenant_id, response.status_code, response.text))


def input_sanity_checks(morpheus_host, tenant_name, group_names_csv, group_codes_csv):

    # 17/03/2023: Added control to check for empty strings in Group Names
    # Check group names in INFRAGROUPS are not empty string
    for grp in group_names_csv.split(","):
        if grp == "":
            print("....Input Error: Group Name cannot be empty string")
            raise Exception("....Input Error: Group Name cannot be empty string")

    # 30/11/2022: Added control to check lenght of tenant name (Max 4 chars)
    # Check tenant name lenght is <= 4 chars
    if len(tenant_name) > 4:
        print("....Error: Tenant name must be Max 4 chars")
        raise Exception("....Error: Tenant name must be Max 4 chars")

    # Check that names do not contain spaces
    if ' ' in tenant_name or tenant_name == "":
        print("....Tenant name '%s' contains spaces or is blank. Not allowed." % (tenant_name))
        raise Exception("....Tenant name '%s' contains spaces or is blank. Not allowed." % (tenant_name))

    for infra_group in group_names_csv.split(','):
        if ' ' in infra_group.strip() or infra_group.strip() == "":
            print("....Infra Group name '%s' contains spaces or is blank. Not allowed." % (infra_group))
            raise Exception("....Infra Group name '%s' contains spaces or is blank. Not allowed." % (infra_group))
 
    for infra_group_code in group_codes_csv.split(','):
        if ' ' in infra_group_code.strip() or infra_group_code.strip() == "":
            print("....Infra Group name '%s' contains spaces or is blank. Not allowed." % (infra_group_code))
            raise Exception("....Infra Group name '%s' contains spaces or is blank. Not allowed." % (infra_group_code))    

    # 30/11/2022: Added control to check group_code is set for every Resource Group
    # Check INFRA_GROUPS and INFRAGROUP_CODES have the same number of elements
    if len(group_names_csv.split(",")) > len(group_codes_csv.split(",")):
        print("....Error creating groups: each resource group must have a code")
        raise Exception("....Error creating groups: each resource group must have a code")

    # 30/11/2022: Added control to check group_code length is max 4 chars
    # Check codes in INFRAGROUP_CODES have max lenght 4 chars
    for code in group_codes_csv.split(","):
        if len(code.strip()) > 3:
            print("....Error, code lenght must be max 3 chars, wrong code: " +code.strip())
            raise Exception("....Error, code lenght must be max 3 chars, wrong code: " +code.strip())

    # 02/12/2022: Added control ti check duplicates in input
    # Check if any duplicate entry in input
    for input_csv in [group_names_csv, group_codes_csv]:
       INPUT_LIST=input_csv.split(",")
       SPLIT_LIST=[]
       for elem in INPUT_LIST:
           SPLIT_LIST.append(elem.strip())
       if len(INPUT_LIST) != len(set(SPLIT_LIST)):
          print("....Duplicates entries found in input for groups or group codes")
          raise Exception("....Duplicates entries found in input for groups or group codes")

 
def create_snow_tenant_ci(tenant_name):
    jbody = {"name": MORPHEUS_TENANT, "short_description": MORPHEUS_TENANT_DESCRIPTION, "company": CORE_COMPANY, "u_sottosistema_cctt": SUB_SYSTEM}
    body = json.dumps(jbody)
    #print(body)
    url = 'https://%s/api/now/table/u_cmdb_ci_tenant' % (SNOW_HOSTNAME)
    response = requests.post(url, auth=(SNOW_USER, SNOW_PWD), headers=SNOW_HEADERS, data=body)
    if not response.ok:
        print("Error creating tenant CI for tenant '%s' in ServiceNow: Response code %s: %s" % (tenant_name, response.status_code, response.text))
        raise Exception("Error creating tenant CI for tenant '%s' in ServiceNow: Response code %s: %s" % (tenant_name, response.status_code, response.text))

    data = response.json()
    #print(data)
    tenant_sys_id = data['result']['sys_id']
    return tenant_sys_id

 
# 30/11/2022: added group_code parameter for Service Now Resource Group
def create_snow_cmp_group_record(tenant_sys_id, group, group_code):
    jbody = {"name": group, "u_tenant": tenant_sys_id, "u_sottosistema_cctt": SUB_SYSTEM, "company": CORE_COMPANY, "u_codice_resource_group": group_code}
    body = json.dumps(jbody)
    #print(body)
    url = 'https://%s/api/now/table/u_cmdb_ci_cmpresourcegroup' % (SNOW_HOSTNAME)
    response = requests.post(url, auth=(SNOW_USER, SNOW_PWD), headers=SNOW_HEADERS ,data=body)
    if not response.ok:
        print("Error creating group '%s' record for tenant '%s' in ServiceNow: Response code %s: %s" % (tenant_sys_id, group, response.status_code, response.text))
        raise Exception("Error creating group '%s' record for tenant '%s' in ServiceNow: Response code %s: %s" % (tenant_sys_id, group, response.status_code, response.text))

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
        print("Error renaming keycloak group '%s': Response code %s: %s" % (group_name, response.status_code, response.text))
        raise Exception("Error renaming keycloak group '%s': Response code %s: %s" % (group_name, response.status_code, response.text))


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
    print("....'%s'" % ("ruoli CMP " + tenant_name))
    cmp_base_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "ruoli CMP " + tenant_name, tenant_base_id)
    print("........'%s'" % ("CMP_" + tenant_name))
    child_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "CMP_" + tenant_name, cmp_base_id)
    print("........'%s'" % ("CMP_" + tenant_name + "_ADMIN"))
    child_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "CMP_" + tenant_name + "_ADMIN", cmp_base_id)
    for resgroup in infra_groups_list.split(','):
        resgroup = resgroup.strip()
        print("........'%s'" % ("ruoli CMP " + tenant_name + "_" + resgroup))
        parent_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "ruoli CMP " + tenant_name + "_" + resgroup, cmp_base_id)
        for role in "_USERCTLG", "_USERSTD":
            print("............'%s'" % ("CMP_" + tenant_name + "_" + resgroup + role))
            child_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "CMP_" + tenant_name + "_" + resgroup + role, parent_id)

    #create NAGIOS groups
    print("....'%s'" % ("ruoli NAGIOS " + tenant_name))
    nagios_base_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "ruoli NAGIOS " + tenant_name, tenant_base_id)
    print("........'%s'" % (NAGIOS_TAG + "_" + tenant_name + "_USER"))
    child_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, NAGIOS_TAG + "_" + tenant_name + "_USER", nagios_base_id)
    for resgroup in infra_groups_list.split(','):
        resgroup = resgroup.strip()
        print("........'%s'" % ("ruoli NAGIOS " + tenant_name + "_" + resgroup))
        parent_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "ruoli NAGIOS " + tenant_name + "_" + resgroup, nagios_base_id)
        print("............'%s'" % (NAGIOS_TAG + "_" + tenant_name + "_" + resgroup + "_USER"))
        child_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, NAGIOS_TAG + "_" + tenant_name + "_" + resgroup + "_USER", parent_id)

    #create SNOW groups
    snow_base_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "ruoli SNOW " + tenant_name, tenant_base_id)
    print("....'%s'" % ("ruoli SNOW " + tenant_name))
    child_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "SNOW_" + tenant_name + "_DEC", snow_base_id)
    print("........'%s'" % ("SNOW_" + tenant_name + "_DEC"))
    for resgroup in infra_groups_list.split(','):
        resgroup = resgroup.strip()
        parent_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "ruoli SNOW " + tenant_name + "_" + resgroup, snow_base_id)
        print("........'%s'" % ("ruoli SNOW " + tenant_name + "_" + resgroup))
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
                    print("............'%s' (migrated from legacy)" % ("SNOW_" + resgroup + role))
                else:
                    child_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "SNOW_" + tenant_name + "_" + resgroup + role, parent_id)
                    print("............'%s'" % ("SNOW_" + tenant_name + "_" + resgroup + role))
            else:
                child_id = create_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "SNOW_" + tenant_name + "_" + resgroup + role, parent_id)
                print("............'%s'" % ("SNOW_" + tenant_name + "_" + resgroup + role))
        if reused_legacy_group:
            legacy_group_root_id = get_keycloak_group_id_by_name(keycloak_host, keycloak_realm, "ruoli SNOW " + resgroup, access_token, legacy_root_id)
            if legacy_group_root_id != -1:
                rename_keycloack_subgroup(keycloak_host, keycloak_realm, access_token, "ruoli SNOW " + resgroup + "_migrated", legacy_group_root_id)


def create_keycloak_object_for_tenant(keycloak_host, keycloak_realm, access_token, tenant_name, tenant_entity_id, tenant_ap_acs_url, infra_groups_list):
#Create Keycloak client and group hierarchy for new tenant and its infra groups
#Depends on:
# - get_keycloak_access_token
# - get_keycloak_group_id_by_name
# - create_keycloack_subgroup
# - rename_keycloack_subgroup
# - move_keycloack_subgroup
# - create_keycloack_groups_for_morpheus_infragroup

    print("creating keycloak client '%s' for tenant '%s'" % (tenant_entity_id, tenant_name))

    #create keycloak client
    url = "http://%s/admin/realms/%s/clients" % (keycloak_host, keycloak_realm)
    header = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + access_token}
    b = {"clientId": tenant_entity_id, "name": "tenant " + tenant_name, "description": MORPHEUS_TENANT_DESCRIPTION, "redirectUris": [tenant_ap_acs_url], "protocol": "saml", "frontchannelLogout": True, "enabled": True, "attributes": {}}
    b["attributes"]["saml.assertion.signature"] = True
    b["attributes"]["saml.server.signature"] = True
    b["attributes"]["saml.signature.algorithm"] = "RSA_SHA256"
    b["attributes"]["saml_name_id_format"] = "username"
    b["attributes"]["saml.server.signature.keyinfo.xmlSigKeyInfoKeyNameTransformer"] = "NONE"
    b["attributes"]["saml.force.post.binding"] = True
    b["attributes"]["saml_assertion_consumer_url_post"] = tenant_ap_acs_url
    b["attributes"]["saml_single_logout_service_url_redirect"] = KEYCLOAK_LOGOUT_REDIRECT_URL
    b["attributes"]["saml.client.signature"] = False
    body = json.dumps(b)
    #print(json.dumps(body, indent=4))
    response = requests.post(url, headers=header, data=body, verify=KEYCLOAK_VERIFY_SSL_CERT)
    if not response.ok:
        print("Error creating keycloak client for '%s': Response code %s: %s" % (tenant_name, response.status_code, response.text))
        raise Exception("Error creating keycloak client for '%s': Response code %s: %s" % (tenant_name, response.status_code, response.text))

    #get client ID of the new client
    url = "http://%s/admin/realms/%s/clients" % (keycloak_host, keycloak_realm)
    header = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + access_token}
    response = requests.get(url, headers=header, verify=KEYCLOAK_VERIFY_SSL_CERT)
    if not response.ok:
        print(".....Error creating keycloak clients list: Response code %s: %s" % (response.status_code, response.text))
        raise Exception(".....Error creating keycloak clients list: Response code %s: %s" % (response.status_code, response.text))
    data = response.json()
    for client in data:
        if client["clientId"] == tenant_entity_id:
            client_id = client["id"]
            break

    print("creating keycloak attribute mappers for client '%s'" % (tenant_entity_id))

    #add client attribute mapper for Surname
    url = "http://%s/admin/realms/%s/clients/%s/protocol-mappers/models" % (keycloak_host, keycloak_realm, client_id)
    header = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + access_token}
    b = {"name": "X500 surname", "protocol": "saml", "protocolMapper": "saml-user-property-mapper", "consentRequired": False, "config": {}}
    b["config"]["attribute.nameformat"] = "Basic"
    b["config"]["user.attribute"] = "lastName"
    b["config"]["friendly.name"] = "surname"
    b["config"]["attribute.name"] = "surname"
    body = json.dumps(b)
    response = requests.post(url, headers=header, data=body, verify=KEYCLOAK_VERIFY_SSL_CERT)
    if not response.ok:
        print(".....Error creating keycloak client mappers: Response code %s: %s" % (response.status_code, response.text))
        raise Exception(".....Error creating keycloak client mappers: Response code %s: %s" % (response.status_code, response.text))

    print(".....created client attribute mapper for Surname")

    #add client attribute mapper for email
    url = "http://%s/admin/realms/%s/clients/%s/protocol-mappers/models" % (keycloak_host, keycloak_realm, client_id)
    header = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + access_token}
    b = {"name": "X500 email", "protocol": "saml", "protocolMapper": "saml-user-property-mapper", "consentRequired": False, "config": {}}
    b["config"]["attribute.nameformat"] = "Basic"
    b["config"]["user.attribute"] = "email"
    b["config"]["friendly.name"] = "mail"
    b["config"]["attribute.name"] = "emailAddress"
    body = json.dumps(b)
    response = requests.post(url, headers=header, data=body, verify=KEYCLOAK_VERIFY_SSL_CERT)
    if not response.ok:
        print(".....Error creating keycloak client mappers: Response code %s: %s" % (response.status_code, response.text))
        raise Exception(".....Error creating keycloak client mappers: Response code %s: %s" % (response.status_code, response.text))

    print(".....created client attribute mapper for email")

    #add client attribute mapper for givenName
    url = "http://%s/admin/realms/%s/clients/%s/protocol-mappers/models" % (keycloak_host, keycloak_realm, client_id)
    header = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + access_token}
    b = {"name": "X500 givenName", "protocol": "saml", "protocolMapper": "saml-user-property-mapper", "consentRequired": False, "config": {}}
    b["config"]["attribute.nameformat"] = "Basic"
    b["config"]["user.attribute"] = "firstName"
    b["config"]["friendly.name"] = "givenName"
    b["config"]["attribute.name"] = "givenName"
    body = json.dumps(b)
    response = requests.post(url, headers=header, data=body, verify=KEYCLOAK_VERIFY_SSL_CERT)
    if not response.ok:
        print(".....Error creating keycloak client mappers: Response code %s: %s" % (response.status_code, response.text))
        raise Exception(".....Error creating keycloak client mappers: Response code %s: %s" % (response.status_code, response.text))

    print(".....created client attribute mapper for givenName")

    #add client attribute mapper for Group
    url = "http://%s/admin/realms/%s/clients/%s/protocol-mappers/models" % (keycloak_host, keycloak_realm, client_id)
    header = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + access_token}
    b = {"name": "Group", "protocol": "saml", "protocolMapper": "saml-group-membership-mapper", "consentRequired": False, "config": {}}
    b["config"]["attribute.nameformat"] = "Basic"
    b["config"]["single"] = True
    b["config"]["full.path"] = False
    b["config"]["attribute.name"] = "memberOf"
    body = json.dumps(b)
    response = requests.post(url, headers=header, data=body, verify=KEYCLOAK_VERIFY_SSL_CERT)
    if not response.ok:
        print(".....Error creating keycloak client mappers: Response code %s: %s" % (response.status_code, response.text))
        raise Exception(".....Error creating keycloak client mappers: Response code %s: %s" % (response.status_code, response.text))

    print(".....created client attribute mapper for Group")

    print("Creating keycloak client-role '%s' for client '%s'" % (tenant_name, tenant_entity_id))

    #create keycloak client-role for new client as tenant_name
    url = "http://%s/admin/realms/%s/clients/%s/roles" % (keycloak_host, keycloak_realm, client_id)
    header = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + access_token}
    b = {"name": tenant_name, "composite": "false", "clientRole": "true"}
    body = json.dumps(b)
    #print(json.dumps(body, indent=4))
    response = requests.post(url, headers=header, data=body, verify=KEYCLOAK_VERIFY_SSL_CERT)
    if not response.ok:
        print(".....Error creating keycloak client-role '%s' for '%s': Response code %s: %s" % (tenant_name, tenant_entity_id, response.status_code, response.text))
        raise Exception(".....Error creating keycloak client-role '%s' for '%s': Response code %s: %s" % (tenant_name, tenant_entity_id, response.status_code, response.text))    

    #get client-role id created for the new client as tenant_name
    url = "http://%s/admin/realms/%s/clients/%s/roles" % (keycloak_host, keycloak_realm, client_id)
    header = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + access_token}
    response = requests.get(url, headers=header, data=body, verify=KEYCLOAK_VERIFY_SSL_CERT)
    if not response.ok:
        print(".....Error getting keycloak client-role id: Response code %s: %s" % (response.status_code, response.text))
        raise Exception(".....Error getting keycloak client-role id: Response code %s: %s" % (response.status_code, response.text))    
    data = response.json()
    for clientrole in data:
        if clientrole["name"] == tenant_name:
            clientrole_id = clientrole["id"]
            #print(clientrole_id)
            break

    #create IDM group hierarchy for the new tenant

    print("Creating Keycloak artifacts")

    create_keycloack_groups_for_morpheus_infragroup(keycloak_host, keycloak_realm, access_token, tenant_name, infra_groups_list)

    print("mapping keycloak client-role '%s' to group '%s'" % (tenant_name, "CMP_" + tenant_name))

    #map client-role to IDM CMP_<tenant> group
    keycloak_tenant_base_id = get_keycloak_group_id_by_name(keycloak_host, keycloak_realm, KEYCLOAK_TENANT_ROLES_BRANCH, access_token, "")
    cmp_tenant_group_id = get_keycloak_group_id_by_name(keycloak_host, keycloak_realm, "CMP_" + tenant_name, access_token, keycloak_tenant_base_id)
    url = "http://%s/admin/realms/%s/groups/%s/role-mappings/clients/%s" % (keycloak_host, keycloak_realm, cmp_tenant_group_id, client_id)
    header = {"Content-Type":"application/json","Accept":"application/json","Authorization": "Bearer " + access_token}
    b = [{"id": clientrole_id, "name": tenant_name}]
    body = json.dumps(b)
    #print(json.dumps(body, indent=4))
    response = requests.post(url, headers=header, data=body, verify=KEYCLOAK_VERIFY_SSL_CERT)
    if not response.ok:
        print(".....Error creating keycloak client-role '%s' for '%s': Response code %s: %s" % (tenant_name, tenant_entity_id, response.status_code, response.text))
        raise Exception(".....Error creating keycloak client-role '%s' for '%s': Response code %s: %s" % (tenant_name, tenant_entity_id, response.status_code, response.text))       


#---- functions to get morpheus tenant parameters for keycloak integration ----

def get_morpheus_idm_provider_settings(morpheus_host, access_token, parameter_name, tenant_id ):
#Get providerSettings.parameter for Identity connector MORPHEUS_IDM_NAME in tenant_id    
    url = "https://%s/api/accounts/%s/user-sources/?max=-1" % (morpheus_host, tenant_id)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + access_token
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print(".....Error getting identity provider parameter %s for tenant: %s Response code %s: %s" % (parameter_name, tenant_id, response.status_code, response.text))
        raise Exception(".....Error getting identity provider parameter %s for tenant: '%s' Response code %s: %s" % (parameter_name, tenant_id, response.status_code, response.text))
 
    data = response.json()
         
    for src in data["userSources"]:
        if src["name"] == MORPHEUS_IDM_NAME:
            return src["providerSettings"][parameter_name]
 
    print(".....Parameter %s not found for Identity Source %s in tenant %s..." % (parameter_name, MORPHEUS_IDM_NAME, tenant_id))
    raise Exception(".....Parameter %s not found for Identity Source %s in tenant %s..." % (parameter_name, MORPHEUS_IDM_NAME, tenant_id))

def get_morpheus_idm_provider_id(morpheus_host, access_token, tenant_id ):
#Get Provider id for Identity connector MORPHEUS_IDM_NAME in tenant_id    
    url = "https://%s/api/accounts/%s/user-sources/?max=-1" % (morpheus_host, tenant_id)
    MORPHEUS_HEADERS["Authorization"] = "Bearer " + access_token
    response = requests.get(url, headers=MORPHEUS_HEADERS, verify=MORPHEUS_VERIFY_SSL_CERT)
    if not response.ok:
        print(".....Error getting identity provider parameter %s for tenant: %s Response code %s: %s" % (parameter_name, tenant_id, response.status_code, response.text))
        raise Exception(".....Error getting identity provider parameter %s for tenant: '%s' Response code %s: %s" % (parameter_name, tenant_id, response.status_code, response.text))
 
    data = response.json()
         
    for src in data["userSources"]:
        if src["name"] == MORPHEUS_IDM_NAME:
            return src["id"]
 
    print(".....Error getting Identity Provider ID for Identity Source %s in tenant %s..." % (MORPHEUS_IDM_NAME, tenant_id))
    raise Exception(".....Error getting Identity Provider ID for Identity Source %s in tenant %s..." % (MORPHEUS_IDM_NAME, tenant_id))
 
##################
# MAIN CODE BODY #
##################

print("\nOutput Log:")
print("-----------\n")

# ensure that the current script it running within a sub-tenant
current_tenant = get_morpheus_current_tenant(MORPHEUS_HOST, MORPHEUS_MASTER_TENANT_TOKEN)
if current_tenant["tenant_id"] != 1:
    print("Error: This script MUST be run within the Master Tenant!")
    raise Exception("Error: This script MUST be run within the Master Tenant!")


skip_morpheus = False

if skip_morpheus:
    print("Skipping the creation of Morpheus artefacts...")
else:

    print("Checking input....")
    input_sanity_checks(MORPHEUS_HOST, MORPHEUS_TENANT, MORPHEUS_TENANT_INFRA_GROUPS, MORPHEUS_TENANT_INFRA_GROUPS_CODES)
    print(".....OK")

    print("\nWorking on Morpheus:\n")
    # Create tenant base role
    print("Creating subtenant '%s' from base role...." % (MORPHEUS_TENANT))
    tenant_base_role_source_id = get_morpheus_role_id_by_name(MORPHEUS_HOST, MORPHEUS_TENANT_BASE_ROLE, MORPHEUS_MASTER_TENANT_TOKEN)
    tenant_base_role_id = create_morpheus_role(MORPHEUS_HOST, MORPHEUS_MASTER_TENANT_TOKEN, MORPHEUS_TENANT + "_Base_Role", tenant_base_role_source_id, "account")
 
    # Update tenant base role by sub-system suffix
    set_morpheus_role_clouds_default(MORPHEUS_HOST, MORPHEUS_MASTER_TENANT_TOKEN, tenant_base_role_id, "read")
    clouds_list = get_morpheus_clouds_list(MORPHEUS_HOST, MORPHEUS_MASTER_TENANT_TOKEN)
    set_morpheus_tenant_role_cloud_access_by_suffix(MORPHEUS_HOST, MORPHEUS_MASTER_TENANT_TOKEN, tenant_base_role_id, SUB_SYSTEM, clouds_list)

    #create tenant
    tenant_id = create_morpheus_tenant(MORPHEUS_HOST, MORPHEUS_TENANT, MORPHEUS_TENANT_DESCRIPTION, MORPHEUS_TENANT_SUBDOMAIN, tenant_base_role_id, MORPHEUS_MASTER_TENANT_TOKEN)
 
    # Create tenant admin user and cluster user from multi-tenant role
    print("Creating initial subtenant admin user....")
    initial_tenant_admin_role_id = get_morpheus_role_id_by_name(MORPHEUS_HOST, MORPHEUS_TENANT_ADMIN_ROLE_SRC, MORPHEUS_MASTER_TENANT_TOKEN)
    tenant_admin_username = "%s_%s" % (MORPHEUS_TENANT.upper(), "ADMIN")
    initial_tenant_user_id = create_morpheus_tenant_user(MORPHEUS_HOST, tenant_id, tenant_admin_username, tenant_admin_username, MORPHEUS_TENANT_ADMIN_LASTNAME, MORPHEUS_TENANT_ADMIN_EMAIL, initial_tenant_admin_role_id, MORPHEUS_MASTER_TENANT_TOKEN, MORPHEUS_TENANT_ADMIN_PASSWORD)
    initial_tenant_cluseruser_id = create_morpheus_tenant_user(MORPHEUS_HOST, tenant_id, MORPHEUS_CLUSTER_USER_USERNAME, MORPHEUS_CLUSTER_USER_FIRSTNAME, MORPHEUS_CLUSTER_USER_LASTNAME, MORPHEUS_CLUSTER_USER_EMAIL, initial_tenant_admin_role_id, MORPHEUS_MASTER_TENANT_TOKEN, MORPHEUS_CLUSTER_USER_PASSWORD)

    # Generate tenant admin access token 
    print("Getting subtenant login token and base role IDs....")
    tenant_access_token = get_morpheus_access_token(MORPHEUS_HOST, MORPHEUS_TENANT, tenant_id, MORPHEUS_TENANT + "_ADMIN", MORPHEUS_TENANT_ADMIN_PASSWORD)

    # create secrets for SNOW, KEYCLOAK and VMWARE
    create_morpheus_cypher_secret(MORPHEUS_HOST, tenant_access_token, "dxcsnowpass", SNOW_PWD)
    create_morpheus_cypher_secret(MORPHEUS_HOST, tenant_access_token, "KeycloakRestClientSecret", KEYCLOAK_CLIENT_SECRET)
    create_morpheus_cypher_secret(MORPHEUS_HOST, tenant_access_token, "SVC_Morpheus_VMWARE", SVC_MORPHEUS_VMWARE_SECRET)

    # lookup source role ids in subtenant for new role creation
    catalog_role_base_id = get_morpheus_role_id_by_name(MORPHEUS_HOST, MORPHEUS_TENANT_CTLG_ROLE_SRC, tenant_access_token)
    standard_role_base_id = get_morpheus_role_id_by_name(MORPHEUS_HOST, MORPHEUS_TENANT_STD_ROLE_SRC, tenant_access_token)
    admin_role_base_id = get_morpheus_role_id_by_name(MORPHEUS_HOST, MORPHEUS_TENANT_ADMIN_ROLE_SRC, tenant_access_token)
    
    # Dict to store role mappings for IDM
    idm_role_mappings = {}
    
    # Delete any groups that may have been automatically or otherwise created
    print("Deleting any existing subtenant infra groups....")
    clear_tenant_groups(MORPHEUS_HOST, tenant_access_token)
    
    # Create the Tenant Admin role and assign to initial admin user
    print("Creating tenant admin role from base role and assigning to tenant admin....")
    tenant_admin_role_id = create_morpheus_role(MORPHEUS_HOST, tenant_access_token, MORPHEUS_TENANT + "_ADMIN", admin_role_base_id, "user")
    #set_morpheus_role_groups_default(MORPHEUS_HOST, tenant_access_token, tenant_admin_role_id, "full")
    #assign_morpheus_role_to_user(MORPHEUS_HOST, tenant_access_token, tenant_admin_role_id, initial_tenant_user_id)
    
    # Add admin role IDM mapping
    idm_role_mappings[tenant_admin_role_id] = "CMP_" + MORPHEUS_TENANT + "_ADMIN"
    
    # Loop through infrastructure groups to create
    # 30/11/2022: Changed to set Infra Group Code in morpheus
    print("Looping through infra groups to create....")
    for group in MORPHEUS_TENANT_INFRA_GROUPS.split(","):
        group_index = MORPHEUS_TENANT_INFRA_GROUPS.split(",").index(group)
        group_code = MORPHEUS_TENANT_INFRA_GROUPS_CODES.split(",")[group_index].strip()
        group_name = group.strip()
    
        # Create Infra Group
        print(".....creating infra group " + group_name, "with code " +group_code)
        group_id = create_morpheus_group(MORPHEUS_HOST, tenant_access_token, group_name, group_code)
    
        # Create standard and catalog roles for tenant
        print("............creating tenant roles for infra group " + group_name)
        tenant_catalog_role = "%s_%s_USERCTLG" % (MORPHEUS_TENANT.upper(), group_name.upper())
        tenant_standard_role = "%s_%s_USERSTD" % (MORPHEUS_TENANT.upper(), group_name.upper())
        tenant_catalog_role_id = create_morpheus_role(MORPHEUS_HOST, tenant_access_token, tenant_catalog_role, catalog_role_base_id, "user")
        tenant_standard_role_id = create_morpheus_role(MORPHEUS_HOST, tenant_access_token, tenant_standard_role, standard_role_base_id, "user")
        set_morpheus_role_groups_default(MORPHEUS_HOST, tenant_access_token, tenant_catalog_role_id, "none")
        set_morpheus_role_groups_default(MORPHEUS_HOST, tenant_access_token, tenant_standard_role_id, "none")
    
        # Assign relevant group access to tenant roles
        print("............assign role access for infra group " + group_name)
        set_morpheus_role_group_access(MORPHEUS_HOST, tenant_access_token, tenant_catalog_role_id, group_id, "full")
        set_morpheus_role_group_access(MORPHEUS_HOST, tenant_access_token, tenant_standard_role_id, group_id, "read")
        set_morpheus_role_group_access(MORPHEUS_HOST, tenant_access_token, tenant_admin_role_id, group_id, "full")
    
        # Add role IDM mappings
        idm_role_mappings[tenant_catalog_role_id] = "CMP_" + tenant_catalog_role
        idm_role_mappings[tenant_standard_role_id] = "CMP_" + tenant_standard_role
    
    
    # Lookup default IDM role and create IDM provider
    print("Creating SAML Identity Provider for tenant....")
    default_role_id = get_morpheus_role_id_by_name(MORPHEUS_HOST, MORPHEUS_TENANT_DEFAULT_ROLE, tenant_access_token)
    create_morpheus_saml_provider(MORPHEUS_HOST, MORPHEUS_MASTER_TENANT_TOKEN, tenant_id, idm_role_mappings, MORPHEUS_TENANT, default_role_id)
    set_morpheus_role_groups_default(MORPHEUS_HOST, tenant_access_token, default_role_id, "read")


if SNOW_SKIP:
    print("Skipping the creation of ServiceNow Tenant and group CIs.....")
else:
    print("\nWorking on ServiceNow:\n")
    # Create tenant record in ServiceNow
    print("Creating ServiceNow Tenant CI.....")
    tenant_sys_id = create_snow_tenant_ci(MORPHEUS_TENANT)
    print(".....Created tenant '%s' with id '%s' in ServiceNow" % (MORPHEUS_TENANT, tenant_sys_id))

    # #Loop through infrastructure groups to add to ServiceNow

    # print("Creating ServiceNow Group Objects.....")
    # for group in MORPHEUS_TENANT_INFRA_GROUPS.split(","):
    #     group_sys_id = create_snow_cmp_group_record(tenant_sys_id, group.strip())
    #     print("Created group '%s' with id '%s' in ServiceNow" % (group.strip(), group_sys_id))

    # 30/11/2022: changed to add group_code in Service Now
    print("Creating ServiceNow Group Objects.....")   
    for group in MORPHEUS_TENANT_INFRA_GROUPS.split(","):
        group_index = MORPHEUS_TENANT_INFRA_GROUPS.split(",").index(group)
        group_code = MORPHEUS_TENANT_INFRA_GROUPS_CODES.split(",")[group_index].strip()
        group_name=group.strip()
        group_sys_id = create_snow_cmp_group_record(tenant_sys_id, group_name, group_code)
        print(".....Created group '%s' with code '%s' and id '%s' in ServiceNow" % (group_name, group_code, group_sys_id))

skip_keycloak = False

if skip_keycloak:
    print("\nSkipping the creation of Keycloak artefacts...\n")
else:
    print("\nWorking on Keycloak:\n")
    # Generate keycloak access token
    print("Getting keycloak login token....")
    keycloak_access_token = get_keycloak_access_token(KEYCLOAK_HOST, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET)
    #print("keycloak access token: '%s'" % (keycloak_access_token))
    
    #print(tenant_id)
    print("Getting Morpheus SAML Identity Provider's parameters ")
    entityId_value = get_morpheus_idm_provider_settings(MORPHEUS_HOST, MORPHEUS_MASTER_TENANT_TOKEN, "entityId", tenant_id)
    print(".....Parameter: %s Value: %s" % ("entityId", entityId_value))
    acsUrl_value = get_morpheus_idm_provider_settings(MORPHEUS_HOST, MORPHEUS_MASTER_TENANT_TOKEN, "acsUrl", tenant_id)
    print(".....Parameter: %s Value: %s" % ("acsUrl", acsUrl_value))
    IdentityProviderID = get_morpheus_idm_provider_id(MORPHEUS_HOST, MORPHEUS_MASTER_TENANT_TOKEN, tenant_id)

    create_keycloak_object_for_tenant(KEYCLOAK_HOST, KEYCLOAK_REALM, keycloak_access_token, MORPHEUS_TENANT, entityId_value, acsUrl_value, MORPHEUS_TENANT_INFRA_GROUPS)

print("\nDone.\n")

print("Next Steps:\n")
print("To enable SSO to new tenant:")
#print("  - Ensure that  \'Force Authn\' is unset in \'Advanced Options\' of Identity Source \'%s\' of tenant %s" % (MORPHEUS_IDM_NAME, MORPHEUS_TENANT))
print("  - Set morpheus.tenant.redirect.%s=%s in \'Configuration Properties SCT\' section of https://www.cloud.toscana.it/portal/" % (MORPHEUS_TENANT, IdentityProviderID))

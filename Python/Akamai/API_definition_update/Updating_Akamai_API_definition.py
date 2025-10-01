import argparse
import requests
import json
import yaml
import os
import base64
import boto3
from botocore.exceptions import ClientError
from akamai.edgegrid import EdgeGridAuth


options_call = {
    'options': {
        'responses': {
            '200': {
                'description': 'Successful operation '
            }
        }
    }
}
#function to use command line arguments
def commandline_pars():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('-vck', '--check_version', action='store_true', help='This will allow you to check the current version and if it is locked or not')
    argparser.add_argument('-capi', '--clone_API', action='store_true', help='This will clone what ever version you select')
    argparser.add_argument('-update', '--update_def', action='store_true', help='This will update the API definition')
    argparser.add_argument('-sinPush', '--single_api_push', action='store_true', help='This will push your changes to one environment, STAGING or PRODUCTION')
    argparser.add_argument('-bothPush', '--both_env_api_push', action='store_true', help='This will push your changes to both environments, STAGING or PRODUCTION')
    argparser.add_argument('-apiId', '--api_ID', metavar='API_ID', help='This is the API definition ID')
    argparser.add_argument('-verNum', '--ver_Num', metavar='ver_Num', help='This is the API version Number')
    argparser.add_argument('-filepath', '--file_path', type=str, help='We are looking for the swagger file pat')
    argparser.add_argument('-envir', '--environment', metavar='environment', help='This is the environment you wish to activate: STAGING or PRODUCTION ')
    argparser.add_argument('-env1', '--environment1', metavar='environment1', help='This is the environment you wish to activate: STAGING or PRODUCTION ')
    argparser.add_argument('-env2', '--environment2', metavar='environment2', help='This is the environment you wish to activate: STAGING or PRODUCTION ')
    return argparser.parse_args()
# Function reads and encodes the swagger in base64 
def read_json_file_to_base64(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        swagger_data = json.load(file)
    opt_check = add_options(swagger_data)
    swagger_str = json.dumps(opt_check)
    base64_encoded = base64.b64encode(swagger_str.encode('utf-8')).decode('utf-8')
    return base64_encoded
#Function to read Swagger File (Json or Yaml). Also encodes swagger in base64
def read_swagger_file_encode(file_path):
    file_extension = os.path.splitext(file_path)[-1].lower()
    if file_extension == ".json":
        with open(file_path, 'r', encoding='utf-8') as file:
            swagger_data = json.load(file)
        opt_check = add_options(swagger_data)
        swagger_str = json.dumps(opt_check)
        base64_encoded = base64.b64encode(swagger_str.encode('utf-8')).decode('utf-8')
        return base64_encoded
    
    elif file_extension ==".yaml" or file_extension ==".yml":
        with open(file_path, 'r', encoding='utf-8') as file:
            swagger_data = yaml.safe_load(file)
        opt_check = add_options(swagger_data)
        swagger_str = yaml.dump(opt_check)
        base64_encoded = base64.b64encode(swagger_str.encode('utf-8')).decode('utf-8')
        return base64_encoded
    else:
        raise ValueError("Unsupported file format. Only Json and YamL are supported.")
# Function to add options call to paths in Swagger file.
def add_options(swagger_file):
    paths_values = list(swagger_file["paths"].keys())
    for path in paths_values:
        path_opt = list(swagger_file["paths"][path].keys())
        if 'options'not in path_opt:
            swagger_file["paths"][path].update(options_call)
    #print(swagger_file)
    return swagger_file
#Function to recall secret from AWS secret Manger
def get_secret():
    secret_name = "TODO#_add secrt_name"
    region_name = "TODO#_add_region name(us-east-1)"

    # Create a Secrets Manager client
    session = boto3.session.Session()
    login = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    # Create an STS client
    sts_client = session.client('sts')
    
    # Assume the role
    response = sts_client.assume_role(
        RoleArn='TODO#_Add_roleARn_niumber',
        RoleSessionName='AssumeRoleSession'
    )
    
    # Extract temporary credentials
    credentials = response['Credentials']  
    
    # Create a new session using the temporary credentials
    assumed_role_session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )
    
    # Create a Secrets Manager client using the assumed role session
    assumed_role_client = assumed_role_session.client(
        service_name='secretsmanager',
        region_name=region_name
    )
    
    try:
        get_secret_value_response = assumed_role_client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # For a list of exceptions thrown, see
        # https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
        raise e

    secret = json.loads(get_secret_value_response['SecretString'])
    
    return secret
# Function for creating the Auth header for Akamai API
def auth_header():
    aws_secrets = get_secret()
    # Now you can pull individual values
    client_secret = aws_secrets.get('client_secret')
    access_token = aws_secrets.get('access_token')
    client_token = aws_secrets.get('client_token')
    
    request = requests.Session()
    request.auth = EdgeGridAuth(
        access_token = access_token,
        client_token = client_token,
        client_secret = client_secret
        )
    return request
# Function to filter data out of Json response for VersionCheck
def json_filter(data):
    output = []
    for version in data['apiVersions']:
        output.append(f"Ver# : {version['versionNumber']}")
        output.append(f"Is Version Locked: {version['isVersionLocked']}")
        output.append(f"Version {version['versionNumber']} is based on: {version['basedOn']}")
        output.append(f'Active in STAGING: {version['stagingStatus']}')
        output.append(f'Active in PROD: {version['productionStatus']}')
    return (output)
# Function to check the current version numbers and if they are locked or not. 
def versionCheck (api_ID):
    data = get_secret()
    host = data.get('host')
    url = f"https://{host}/api-definitions/v2/endpoints/{api_ID}/versions"
    request = auth_header()
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }
    response = request.get(url, headers=headers)
    response = response.text
    data = json.loads(response)
    filter_data = json_filter(data)
    for data in filter_data:
        print(data)
# Function to create a New API version if all current ones are locked
def clone_api (api_ID, apiVerNum):
    data = get_secret()
    host = data.get('host')
    
    url = f"https://{host}/api-definitions/v2/endpoints/{api_ID}/versions/{apiVerNum}/cloneVersion"
    
    request = auth_header()
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }
    response = request.post(url, headers=headers)
    print(response.text)
# Function to update API definition in Akamai
def update_akamai_api_definition(swagger_path, api_id, ver_Num):
    data = get_secret()
    host = data.get('host')
    #swagger_data = read_json_file_to_base64(swagger_path)
    swagger_data = read_swagger_file_encode(swagger_path)
    #print(type(swagger_data))
    url = f"https://{host}/api-definitions/v2/endpoints/{api_id}/versions/{ver_Num}/file"
        
    payload = {
        "importFileFormat": "swagger",
        "importFileSource": "BODY_BASE64",
        "importFileContent": swagger_data,
        "contractId": "TODO#Add_Akamai_contarat_ID",
        "groupId": "TODO#_Add_group_ID" 
        }
    request = auth_header()
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
        }
    response = request.post(url, json=payload, headers=headers)
    print(response.text)
# Function to Push API definition to one environment
def single_API_Push(api_id, version_num, environment):
    data = get_secret()
    host = data.get('host')
    print('We are trying the single push')
    url = f"https://{host}/api-definitions/v2/endpoints/{api_id}/versions/{version_num}/activate"
    
    payload = { "networks": [environment] }
    request = auth_header()
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
        }
    response = request.post(url, json=payload, headers=headers)
    print(response.text)
# Function to Push the API definition to both environment
def both_env_API_Push(api_id, version_num, envir1, envir2):
    data = get_secret()
    host = data.get('host')
    print('We are trying to push to Both Environments')
    url = f"https://{host}/api-definitions/v2/endpoints/{api_id}/versions/{version_num}/activate"
    
    payload = { "networks": [envir1, envir2 ] }
    request = auth_header()
    headers = {
        "accept": "application/json",
        "content-type": "application/json"
        }
    response = request.post(url, json=payload, headers=headers)
    print(response.text)
# Function is the logic for the rest of the script. 
def main():
    args = commandline_pars()
    
    # Access the arguments
    version_check = args.check_version
    cloneApi = args.clone_API
    update_def = args.update_def
    api_ID = args.api_ID
    apiVerNum = args.ver_Num
    file_path = args.file_path
    single_push = args.single_api_push
    envir = args.environment
    both_env_push = args.both_env_api_push
    env1 = args.environment1
    env2 = args.environment2
        
    if version_check == True:
        if api_ID is not None:
                versionCheck(api_ID)
                
    if cloneApi == True:
        if api_ID is not None:
            if apiVerNum is not None: 
                clone_api(api_ID, apiVerNum)
            
    if file_path is not None:
        print(file_path)
    
    if update_def == True:
        if api_ID is not None:
            if apiVerNum is not None:
                if file_path is not None:
                    update_akamai_api_definition(file_path, api_ID, apiVerNum)
                    
    if single_push is not None:
        if api_ID is not None:
            if apiVerNum is not None:
                if envir is not None:
                    envir = envir.upper()
                    single_API_Push(api_ID, apiVerNum, envir)
                    
    if both_env_push is not None:
        if api_ID is not None:
            if apiVerNum is not None:
                if env1 is not None:
                    if env2 is not None:
                        if env2 == env1:
                            print('Both environments are the same. They need to be different')
                        else:
                            env1 = env1.upper()
                            env2 = env2.upper()
                            both_env_API_Push(api_ID, apiVerNum, env1, env2)
            
if __name__ == "__main__":
    main()

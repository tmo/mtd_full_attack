
import argparse
# import nmap
import time, sys, random
import subprocess
import logging
# import os
# replaces os
# import subprocess
import threading

from helpers import post_processing, create_output_folder, get_ip_from_dig
from network_scanning import nmap_scan
from vulnerability_scanning import *
from attacks import *
from probing import guess_mtd_interval, probe_signal, evaluate_interval

logging.basicConfig(level=logging.INFO)

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

def full_attack(trials=1, hosts=None,  cookie=None, group_name=None, 
                interval_vars=None):
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
        if(interval_vars and interval_vars[0] > 0.0):
            wait_time = interval_vars[0] - ((time.time() - interval_vars[1])%interval_vars[0]) + 0.5
            print("TIMING:: waiting for next {}".format(wait_time))
            time.sleep(wait_time)
            print("TIMING:: continuing")
            sys.stdout.flush()
        try:
            print("---- Trial " + str(i) + ",  " +  time.strftime("%Y%m%d_%H%M%S"))
            start = time.time()
            if not cookie:
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
                    "success":False
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
            if w_result["success"]==False:
                print("No vuln found, restarting")
                vuln_scan_results = {
                    "stage":2,
                    "time":0, 
                    "settings": "",
                    "results":{},
                    "success":False
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
            print("---- END, total time (sec) " + str(end-start) + ", " +  \
                time.strftime("%Y%m%d_%H%M%S"), file=sys.stderr)
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
        sys.stderr.flush()
            


def main(args):
    # Start Probing
    hosts, ip = get_ip_from_dig()
    data_lock = threading.Lock()
    interval, next_time = -1,-1
    ret_vars = [-1, -1]
    th = threading.Thread(target=guess_mtd_interval, args=(ip, hosts, 
                                            ret_vars, next_time, data_lock))
    th.start()

    # make group directory
    group = time.strftime("%Y%m%d_%H%M%S",time.gmtime(time.time()))
    group = "int_mtd_drop_60_NW_24_attack_sql_stop" 
    create_output_folder(group)



    print("---- STARTING " + time.strftime("%Y%m%d_%H%M%S"))
    print("stage, time, command, result, success")
    full_attack(trials=None, hosts=None, cookie=None, group_name=group,
                    interval_vars=ret_vars) 


if __name__ == '__main__':
    parser = arg_parser()
    args = parser.parse_args(sys.argv[1:])

    # so I don't have to pass it in commandline
    ip, raw = get_ip_from_dig()
    args.nw_scan_addr = ip
    args.addr = raw


    main(args)

# import sys
import argparse
# import nmap
import time
import logging
# import os
# replaces os
# import subprocess

from helpers import post_processing
from network_scanning import nmap_scan
from vulnerability_scanning import *
from attacks import *

logging.basicConfig(level=logging.DEBUG)
logging.basicConfig(filename='log/debug.log', level=logging.debug)

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

def execute_attacks(result, ip, cookie):
    vuls = result["results"]
    for key in vuls.keys():
        if (key == "Commands execution"):
            print(key, len(vuls[key]), type(vuls[key]))
            attack_manual_command_exec_passwd(vuls[list(vuls.keys())[0]][0], 
                                                ip, cookie)

        
def main(argv):
    parser = arg_parser()
    args = parser.parse_args(argv)

    vuls = get_wapiti_results("./results/made_results.json")
    result = {
        "stage":2,
        "time":0, 
        "settings": "",
        "results":vuls,
    }
    execute_attacks(result, "http://192.168.40.132", 
                    cookie=get_cookie_contents("./resources/cook2.json"))

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

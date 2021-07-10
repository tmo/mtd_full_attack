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


def main(argv):
    parser = arg_parser()
    args = parser.parse_args(argv)

    # cookie_file = get_cookie()
    # wapiti_scan(os_output=True)

    result = wapiti_scan(modules=all)
    post_processing(2, [result])

    # vuls = get_wapiti_results("./results/20210709_2207.json")
    # result = {
    #     "stage":2,
    #     "time":0, 
    #     "settings": "",
    #     "results":vuls
    # }
    # post_processing(2, [result, result])

    #wapiti_scan()

    # result = nmap_scan()
    # post_processing(1, [
    #     result, 
    #     nmap_scan(print_output=False, hosts = "192.168.40.*")
    # ])


if __name__ == '__main__':
    main(sys.argv[1:])

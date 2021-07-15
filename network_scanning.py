import nmap
import time
import logging
import sys, os

from helpers import get_output_file_name

def nmap_scan(hosts=None, args=None, print_output=True, os_output=False,
                group_name=None):
    if not hosts:
        # hosts = "192.168.20.*"
        logging.error("No host given")
        sys.exit()
    if not args:
        args = "--unprivileged -sn"
    logging.debug("Stage 1 nmap scanning started...")

    nm = nmap.PortScanner()
    start = time.time()
    r = nm.scan(hosts=hosts, arguments=args)
    end = time.time()

    # os_input = "nmap {} {}".format(args, hosts)
    # log_file = get_output_file_name(time.time(), "nmap_osout", group_name)
    # if not os_output:
    #     os_input += " > " + log_file
    # start = time.time()
    # r = os.system(os_input)
    # end = time.time()

   
    if print_output:
        print("1,{},{},{}".format(end-start, "nmap {} {}".format(args, hosts),
        nm.all_hosts()))
    result = {
        "stage":1,
        "time":end-start, 
        "settings":"nmap {} {}".format(args, hosts),
        "results":nm.all_hosts()
    }
    return result
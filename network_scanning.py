import nmap
import time
import logging

def nmap_scan(hosts=None, args=None, print_output=True):
    if not hosts:
        hosts = "192.168.20.*"
    if not args:
        args = "--unprivileged -sn"
    logging.debug("Stage 1 nmap scanning started...")

    nm = nmap.PortScanner()
    start = time.time()
    r = nm.scan(hosts=hosts, arguments=args)
    end = time.time()

    # start = time.time()
    # r = os.system("nmap {} {}".format(args, hosts))
    # end = time.time()
    # print("{}".format(end-start))
   
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
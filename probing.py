import time, sys, random
import subprocess
import logging

from network_scanning import nmap_scan

def probe_signal(starting_ip = None, scan_range=None):
    # ip = "192.168.40.132"
    ip = starting_ip

    """ psudo code
    try connection,
    if failed, do an nmap scan
    if not failed, retry in 10 seconds

    consider itnervals of 30s to several hours

    have an array of fulfilled or dropped to look at
   

    should do this in a thread and then update the scan wait time from this 
    thread to be used in the other thread

    if  current_time < next_ shuffle time:
        while current_time < shuffle time:
            wait
    else:
        wait shuffle_interval
    
    """

    status = []
    start_time = time.time()
    while True:
        # For testing connection dropping out
        if time.time() - start_time > 30: 
            # random.randrange(0,100)/100 < 0.2:
            start_time = time.time()
            ip = "192.168.40.133"
            print("changed ip")

        out = subprocess.check_output(['nmap', '-sn', ip]).decode("utf-8")
        third_line = out.split("\n")[2]

        if (third_line[0] == "H"):
            status += [time.time()]
            print("host is up")
            time.sleep(random.randrange(5, 30))
        elif (third_line[0] == "N"):
            status += [-1]
            print("Host Down")
    
            # if status == 0 rescan nmap fully
            result = nmap_scan(print_output=True, hosts = scan_range)
            ip = result["results"][0]
            # TO DO find no result

        else:
            print("unexpected error")
        print(status)
# [-1, 1630235591.5199296, 1630235610.5907724, -1, 1630235625.7998238, 1630235631.852075, 1630235641.9081788, -1, 1630235660.8186579, 1630235671.8782792, -1, 1630235700.6990523]

        
        
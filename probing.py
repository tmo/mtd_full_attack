import time, sys, random
import subprocess
import logging

from network_scanning import nmap_scan
from helpers import get_ip_from_dig

def guess_mtd_interval(starting_ip, scan_range, interval, next_time, data_lock):
    status_1, times_1 = [], []
    idx = 0

    while True:
        idx += 1    
        try:
            status_1, times_1 = probe_signal(starting_ip, scan_range, status_1, times_1)
            ret_interval, ret_next_time = evaluate_interval(status_1, times_1)
        except Exception as e:
            print("ERROR:{}".format(e))
        with data_lock:
            interval[0]  = ret_interval
            interval[1] = ret_next_time
        sys.stdout.flush()

def probe_signal(starting_ip = None, scan_range=None, status=None, times=None):
    # ip = "192.168.40.132" # RM
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
    (need to return/modify 2 things)
    
    """

    start_time = time.time()
    idx  = 0
    out = subprocess.check_output(['nmap', '-sn', ip]).decode("utf-8")
    print(out)
    while idx < 15:
        idx += 1

        print("PROBING::: scanning {}".format(ip))
        sys.stdout.flush()
        
        times += [time.time()]
        out = subprocess.check_output(['nmap', '-sn', ip]).decode("utf-8")
        third_line = out.split("\n")[2]
        
        if (third_line[0] == "H"):
            status += [1]
            print("PROBING::: host is up")
            
            wait_time = random.randrange(5, 30)
            print("PROBING::: waiting {} seconds".format(wait_time))
            sys.stdout.flush()
            time.sleep(wait_time) #(5,30)
        elif (third_line[0] == "N"):
            status += [-1]
            print("PROBING::: Host Down")
            sys.stdout.flush()
        
            # if status == 0 rescan nmap fully
            # if space searched same as space from mtd then won't need to do this
            scan_range, _ = get_ip_from_dig()

            result = nmap_scan(print_output=False, hosts = scan_range)
            print("PROBING::: {}".format(result))
            ip = result["results"][0]

        else:
            print("PROBING::: unexpected error")
        
        print("PROBING::: probes left ", idx)
        sys.stdout.flush()

    print("PROBING::: {}".format(status))
    print("PROBING::: {}".format(times))
    sys.stdout.flush()
    return status, times

def evaluate_interval(status_list, times_list):
    """ 
    Calculate mtd interval based on status list containing the time if 
    the host is up or -1 when the host was down
    """
    # interval should be average of times between -1s
    # next time should be a do time + some interval
    # the list may need to be come a dictionary, or two lists
    status_list_2, times_list_2 = [],[]
    for i in range(1, len(status_list)):
        if status_list[i]==status_list[i-1] and status_list[i]==-1:
            pass
        else:
            status_list_2 += [status_list[i]]
            times_list_2 += [times_list[i]]
    status_list, times_list = status_list_2, times_list_2
    global initial_time

    # get location of drop outs
    drop_outs = [i for i,x in enumerate(status_list) if x==-1]


    time_differences = []
    for i in range(len(drop_outs)-1):
        time_differences += [times_list[drop_outs[i+1]] - times_list[drop_outs[i]]]


    # ignore first one which may be innacruate because probing may start randomly
    if len(time_differences[1:]) > 2:
        # remove outliers
        import statistics
        s = statistics.stdev(time_differences)
        m = statistics.mean(time_differences)
        time_differences = [time_dif for time_dif in time_differences if time_dif > (m-1.5*s)]

        interval =  sum(time_differences[1:])/len(time_differences[1:])
    else:
        print("PROBING::: Err interval dev by 0")
        interval = -1
    print("PROBING::: Interval is {}".format(interval))

    # also need a starting time
    # get time of last drop out
    last_drop = times_list[drop_outs[-1]]
    
    next_time = last_drop + interval
    print("PROBING::: Next trigger time is {}".format(next_time))

    return interval, next_time




        
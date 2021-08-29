import time, sys, random
import subprocess
import logging

from network_scanning import nmap_scan

def probe_signal(starting_ip = None, scan_range=None):
    ip = "192.168.40.132" # RM
    # ip = starting_ip

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

    status, times = [], []
    start_time = time.time()
    while True:
        # RM
        # For testing connection dropping out
        if time.time() - start_time > 30: 
            # random.randrange(0,100)/100 < 0.2:
            start_time = time.time()
            ip = "192.168.40.133"
            print("changed ip")

        out = subprocess.check_output(['nmap', '-sn', ip]).decode("utf-8")
        third_line = out.split("\n")[2]

        if (third_line[0] == "H"):
            status += [1]
            print("host is up")
            time.sleep(random.randrange(5, 30))
        elif (third_line[0] == "N"):
            status += [-1]
            print("Host Down")
    
            # if status == 0 rescan nmap fully
            result = nmap_scan(print_output=True, hosts = scan_range)
            ip = result["results"][0]
            ip = "192.168.40.132" # RM
            # TO DO find no result

        else:
            print("unexpected error")
        times += [time.time()]
        print(status)

def evaluate_interval(status_list):
    """ 
    Calculate mtd interval based on status list containing the time if 
    the host is up or -1 when the host was down
    """
    status_list = [-1, 1, 1, -1, 1, 1, 1, -1, 1, 1, -1, 1]
    times_list = [ 1630235591.5199296-5, 1630235591.5199296, 1630235610.5907724, 1630235625.7998238-5, 1630235625.7998238, 1630235631.852075, 1630235641.9081788, 1630235660.8186579-5, 1630235660.8186579, 1630235671.8782792, 1630235700.6990523-5, 1630235700.6990523]
    # status_list = [-1, 1630235591.5199296, 1630235610.5907724, -1, 1630235625.7998238, 1630235631.852075, 1630235641.9081788, -1, 1630235660.8186579, 1630235671.8782792, -1, 1630235700.6990523]
    # interval should be average of times between -1s
    # next time should be a do time + some interval
    # the list may need to be come a dictionary, or two lists

    # get location of drop outs
    drop_outs = [i for i,x in enumerate(status_list) if x==-1]

    # there is a nicer way to do this
    # nope not wihtout numpy, probably this if fine. I'll check the efficiency later
    time_differences = []
    for i in range(len(drop_outs)-1):
        # print(drop_outs[i+1], drop_outs[i])
        time_differences += [times_list[drop_outs[i+1]-1] - times_list[drop_outs[i]+1]]

    # time_differences = [times_list[drop_outs[i+1]-1] - times_list[drop_outs[i]+1] for i,x  in enumerate(drop_outs[:-1])]


    interval =  sum(time_differences)/len(time_differences)
    print("Interval is {}".format(interval))

    # also need a starting time

    #get time of last drop out
    last_drop = times_list[drop_outs[-1]]

    next_time = last_drop + interval


    print("Next trigger time is {}".format(next_time))
        
        
import sys
import argparse
import nmap
import time
import logging
import os
# replaces os
import subprocess

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

def post_processing(stage, results):
    """
    Take results and extract the total attacks launched to attacks with a 
    a result, time to succeed if success

    Assumes all results have same settings
    For stage 1 considers scans launched not number of ips checked (which has 
        to be extracted from settings)
    """
    logging.debug("Post processing...")
    print("pp")
    if stage != 1 and stage != 2:
        logging.error("Only stage 1 and 2 scan post processing is supported")

    scans_launched = 0
    successes = 0
    times_to_success = []
    average_TTS = 0
    for result in results: 
        scans_launched += 1
        # determine if successful
        if(stage == 1 ): # nmap
            if (len(result["results"]) > 0):
                successes += 1
                times_to_success.append(result["time"])
        elif stage == 2: # TODO wapiti, but should make this a keyword
            # number of vuleranbilities in total
            # attack successful if this is not 0
            num_results = 0
            for key in result["results"].keys():
                num_results += len(result["results"][key])
            logging.info("Total number of wapiti results is {}".format(num_results))
            success = True if num_results > 0 else False
            if (success):
                successes += 1
                times_to_success.append(result["time"])

    
    average_TTS = sum(times_to_success)/len(times_to_success)
    print("Scans Launched, Sucesses, Averae TTS")
    print(scans_launched, successes, average_TTS)
    

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


def wapiti_scan(host=None, cookie=None, exclude=None,
                print_output=True, os_output=False):
    if not host:
        host = "http://192.168.40.132/dvwa/"
    if not exclude:
        exclude = host+"logout.php"
        # exclude = "http://192.168.40.132/dvwa/logout.php"
    if not cookie:
        cookie = get_cookie()
    scan_time = time.strftime("%Y%m%d_%H%m")
    result_file = "./results/{}.json".format(scan_time)
    # TODO add --flush-session
    osinput = "wapiti  -u  {host} -c {cookie} -x {exclude} -m {modules} " + \
                "-f {format} -o {output} --flush-session"
    osinput = osinput.format(
        host = host,
        cookie = cookie,
        exclude = exclude,
        modules = "sql,xss",
        format = "json",
        output = result_file
    )
    print(exclude)
    osinput_mod = osinput
    if not os_output:
        osinput_mod += "> ./results/osoutout"
    logging.info("Running command... " + osinput_mod)
    start = time.time()
    r = os.system(osinput_mod)
    end = time.time()
    if print_output:
        print("2,{},{},{}".format(end-start, osinput,
        result_file))
    
    result = {
        "stage":2,
        "time":end-start, 
        "settings": osinput,
        "results":get_wapiti_results(result_file)
    }
    return result

def get_wapiti_results(result_file):
    with open(result_file, 'r') as f:      
        content = eval(f.read())
    vuls = content["vulnerabilities"]
    #print(vuls.keys())
    #print(len(vuls))
    
    ## number of vulnerabilities in each catagory
    #for key in vuls.keys():
    #    print(key, len(vuls[key]), type(vuls[key]))
    #print(vuls[list(vuls.keys())[0]][0].keys())

    return vuls


def get_cookie():
    # TODO take in host ect
    cookie_file = "cook2.json"
    host = "http://192.168.40.132/dvwa/login.php"
    osinput = "wapiti-getcookie -c {cookie} -u  {host}"
    osinput = osinput.format(
        host = "http://192.168.40.132/dvwa/login.php",
        cookie = cookie_file,
    )
    logging.info("Running command... " + osinput)
    r = subprocess.Popen(["wapiti-getcookie", "-c", cookie_file, "-u", host], 
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    out = r.communicate(input=b"0\nadmin\npassword\n\n")

    # Set security to low
    import json
    with open("./"+cookie_file, 'r') as f:  
        content = json.load(f)    
        content[list(content.keys())[0]]["/dvwa"]["security"]["value"]="low"
    with open("./"+cookie_file, 'w') as f:  
        json.dump(content, f)
    return cookie_file

def main(argv):
    parser = arg_parser()
    args = parser.parse_args(argv)

    # cookie_file = get_cookie()
    # wapiti_scan(os_output=True)

    # result = wapiti_scan()
    # post_processing(2, [result, result])

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

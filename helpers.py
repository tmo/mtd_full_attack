import logging
import time, os, sys

logging.basicConfig(level=logging.DEBUG)


def post_processing(stage_in, results):
    """
    Take results and extract the total attacks launched to attacks with a 
    a result, time to succeed if success

    Assumes all results have same settings
    For stage 1 considers scans launched not number of ips checked (which has 
        to be extracted from settings)
    """
    logging.debug("Post processing...")

    # if stage != 1 and stage != 2 and stage != 3:
    #     logging.error("Only stage 1, 2, and 3 scan post processing is supported")

    scans_launched = 0
    successes = 0
    times_to_success = []
    average_TTS = 0
    stage = stage_in
    for result in results: 
        if stage_in == -1:
            if result[0]["stage"]:
                stage = result[0]["stage"]
            elif result["stage"]:
                stage=result["stage"]
            else:
                logging.error("Input does not have a stage")
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
            # logging.info("Total number of wapiti results is {}".format(num_results))
            success = True if num_results > 0 else False
            if (success):
                successes += 1
                times_to_success.append(result["time"])
        elif stage == 3:
            # uses success parameter in stage3 result dict so not specific to attack
            if type(result) == type([]):
                logging.warn("Treating each list as a separate attack")
                # TODO for now just acting as if one lement in list
                logging.warn("{} atacks (should be 1 for now".format(len(result)))
                num_successes = 0
                for attack_result in result:
                    if attack_result and attack_result["success"]:
                        num_successes += 1
                        times_to_success.append(attack_result["time"])
                if num_successes > 0:
                    successes += 1
            elif result["success"]:
                successes += 1
                times_to_success.append(result["time"])
    try:
        average_TTS = sum(times_to_success)/len(times_to_success)
    except:
        average_TTS = -1
    print("Scans Launched, Sucesses, Average TTS", file=sys.stderr)
    print("{},{},{}".format(scans_launched, successes, average_TTS), file=sys.stderr)
    return successes
   
def get_output_file_name(file_time_flt, name, group=None):
    """
    ./results/date/[group]/name_time
    """
    file_time = time.gmtime(file_time_flt)
    date_folder = time.strftime("%Y%m%d", file_time)
    scan_time_str = time.strftime("%Y%m%d_%H%M%S",file_time)
    if group:
        return "./results/{}/{}/{}_{}".format(
            date_folder, group, name, scan_time_str)
    else:
        return "./results/{}/{}_{}".format(
            date_folder, name, scan_time_str)


def create_output_folder(group=None):
    date_folder = time.strftime("%Y%m%d", time.gmtime(time.time()))
    if group:
        file_dir = "./results/{}/{}/".format(date_folder, group)
    else:
        file_dir = "./results/{}/".format(date_folder)
    if not os.path.exists(file_dir):
        os.makedirs(file_dir)


def get_ip_from_dig():
    start = time.time()
    os.system("dig @10.1.0.100 www.mj.uq.dslab.com +short > ./resources/ip")

    with open("./resources/ip", 'r') as f:      
        ip = f.read()

    # ip = ip[::-1].split(".",1)[1][::-1]+".*"
    ip_space = ip.strip() + "/24"
    end = time.time()
    logging.info("Got ip space {} from dig in time {}".format(ip_space, end-start))
    return ip_space, ip.strip()
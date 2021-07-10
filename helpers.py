import logging

logging.basicConfig(level=logging.DEBUG)


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
   
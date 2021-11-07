# MTD Attack Experiments
*Software Engineering Honours Thesis Project*  
***Security Evaluation of Moving Target Defences***  

This is the implementation used in experiments in the honours thesis ``"Security Evaluation of Moving Target Defences"``. 

This code was used to run attack experiments.  
The project is organised as follows:


* `main.py`  - contains the main code for running experiments, including experiment settings and connecting information from different attack phases. 
    
* `network_scanning.py` - contains the NMAP scanning and formatting of results.
    
* `vulnerability_scanning.py` - contains the attacks for vulnerability scanning using Wapiti web application vulnerability scanner.
    
* `attacks.py` - contains the exploitation code for vulnerability exploitation.
    
* `probing.py` - contains the code for probing a host and calculating the MTD interval and next interval time. 
    
* `helpers.py` - contains functions for organising and post-processing data. 



The program environment is provided as a Pipfile.
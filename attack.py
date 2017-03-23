# Suppress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import json

from scapy.all import *

# Get target ip from user @ runtime
def setup():
    
    target_ip = raw_input("Give target ip: ")                               # Get target ip
    print("Performing attack given target ip: {0}\n".format(target_ip))     # Log target

    # Load source ips from json
    with open('source_ips.json') as source_ips_file:
        sources = json.load(source_ips_file)

    # Attack the target ip
    attack(target_ip, sources)

# Attack the target ip with each of the source ips
def attack(target_ip, sources):
    return 0

# Suppress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

# Setup listening filter
filter = "tcp port 53"

# Catch packet
def process_dns(packet):
    dns = packet[DNS]
    if dns
        print("Got packet\n")


# Sniff for packets based on filter
sniff(filter=filter, prn=process_dns)

# Suppress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

# Setup listening filter
filter = "tcp port 53"

# Catch packet
def process_dns(packet):
    print("Got packet---\n")
    print(packet.summary())
    
# Sniff for packets based on filter
sniff(filter=filter, prn=process_dns)

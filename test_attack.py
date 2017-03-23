# Suppress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import json

from scapy.all import *

# Destination settings
source_server = ""
target_server = ""
port = 53

# Build test packet to catch


# Attack the target ip with each of the source ips
def attack():

    # Log target
    print("Performing attack on ip: {0}".format(target_server))

    # Create dummy tcp packet
    tcp_pkt = Ether() / IP(dst=target_server) / TCP(dport=port)

    # Send 10 attack packets
    for x in range(0, 10):
        sendp(tcp_pkt)

# Attack the target ip
attack()

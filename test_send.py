# Suppress Scapy IPv6 warning
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import *

# Destination settings
source_server = ""
target_server = ""
port = 53

# Build test packet to catch
tcp_pkt = Ether(src=source_server) / IP(dst=server) / TCP(dport=port)
print("Sending test packet...\n----")
print(tcp_pkt.summary())
sendp(tcp_pkt)

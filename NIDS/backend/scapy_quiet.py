"""Configure Scapy logging before the library is first imported."""

import logging
import warnings

# Step 1: Suppress libpcap/Npcap warnings — offline PCAP lab does not need them.
warnings.filterwarnings("ignore", module="scapy")
logging.getLogger("scapy").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

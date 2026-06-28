"""Launch the ScapyNIDS Dash GUI."""

import logging
import warnings

# Step 1: Silence Scapy load warnings before any backend/gui import pulls in scapy.
warnings.filterwarnings("ignore", module="scapy")
logging.getLogger("scapy").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from gui.app import main

if __name__ == "__main__":
    main()

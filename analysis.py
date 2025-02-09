import sys
import pathlib
import re

from scapy.all import rdpcap
from scapy.all import *
from scapy.layers.http import HTTP, HTTPRequest

PCAP_FILE = pathlib.Path("result.pcap")
XSS_PATTERNS = [
    "<script>.*<\\/script>",
    "alert\\(.*\\)",
    "<img.*onerror=.*>",
    "document.cookie"
]


def main():
    if not PCAP_FILE.is_file():
        print(f"{PCAP_FILE} is not found!")
        sys.exit(-1)
    
    packages = rdpcap(PCAP_FILE.__str__())
    
    i = 0
    for pkt in packages:
        i += 1  # Номер пакета в PCAP файле
        if pkt.haslayer("Raw") and pkt.haslayer('TCP'):
            data = pkt["Raw"].load.decode(errors='ignore')
            if data:
                for pattern in XSS_PATTERNS:
                    if re.match(pattern, data, flags=re.DOTALL):
                        print(f"Potential XSS founded in {i} packet! Pattern: {pattern}")
                        break


if __name__ == "__main__":
    main()

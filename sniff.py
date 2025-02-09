import pathlib

from scapy.all import sniff, wrpcap

PCAP_FILE = pathlib.Path("result.pcap")


def pkt_callback(pkt):
    print(pkt)


def main():
    packets = sniff(
        iface="Ethernet1",
        prn=pkt_callback,
        filter="tcp port 80",
        timeout=30
    )
    
    wrpcap(PCAP_FILE.__str__(), packets)


if __name__ == "__main__":
    main()

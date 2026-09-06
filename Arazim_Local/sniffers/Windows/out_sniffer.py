import sys
from scapy.all import IP, Raw, ICMP, Ether, sendp, conf
import pydivert
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from utils.network_stats import *
from sniffers.constants import *
from manager.constants import G2_ROUTER_MAC


def bpf_filter(network_stats: NetworkStats) -> str:
    # Logic:
    # 1. Source must be my_ip
    # 2. Destination must be within the subnet/mask
    # 3. Destination must NOT be the router_ip
    my_ip = network_stats.my_ip
    base_addr = network_stats.get_base_addr()
    subnet_mask = network_stats.subnet_mask
    router_ip = network_stats.router_ip
    return f"src host {my_ip} and dst net {base_addr} mask {subnet_mask} and not dst host {router_ip}"


def sniffer(network_stats):
    bpf = bpf_filter(network_stats)
    print(f"Scapy filter: {bpf}")
    print("STARTED OUT SNIFFER")
    sniff(filter=bpf, prn=lambda pack: handle_packet(pack, network_stats), store=False)


def handle_packet(packet, network_stats):
    if IP not in packet:
        return
    dst_ip = packet[IP].dst
    icmp_payload = PAYLOAD_MAGIC + bytes(packet[IP])
    icmp_packet = (
        IP(src=dst_ip, dst=network_stats.router_ip)
        / ICMP(type=8, code=0)
        / Raw(load=icmp_payload)
    )
    # On some Windows hosts scapy's L3 send() can't consult the ARP cache / do
    # ARP, so it egresses the frame with a broadcast dst MAC (ff:ff:ff:ff:ff:ff),
    # which the G2 router drops. Send at L2 with an explicit Ethernet header
    # addressed to the (constant) router MAC so the wrapper always reaches the
    # gateway that reflects it back to the peer.
    frame = Ether(dst=G2_ROUTER_MAC, src=network_stats.my_mac) / icmp_packet
    sendp(frame, iface=network_stats.default_device, verbose=False)


def main():
    network_stats = NetworkStats.get_stats()
    if network_stats is None:
        print("network stats is not initialized!")
    sniffer(network_stats)


if __name__ == "__main__":
    print("a" * 1000)
    main()

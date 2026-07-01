import os
import sys

from scapy.all import  sniff, send
from scapy.layers.inet import IP, ICMP

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from sniffers.constants import PAYLOAD_MAGIC
from utils import network_stats

class Out_Sniffer:
    tun_fd = None 
    def __init__(self, target_subnet,target_subnet_mask, my_ip, network_interface, default_gateway, tun_fd):
        self.target_subnet = target_subnet
        self.target_subnet_mask = target_subnet_mask
        self.my_ip = my_ip
        self.network_interface = network_interface
        self.default_gateway = default_gateway
        Out_Sniffer.tun_fd = tun_fd

    def start_sniff(self):
        fd = Out_Sniffer.tun_fd
        while 1:
            try:
                packet_bytes = os.read(fd, 2048)
                ip_packet = IP(packet_bytes) 
                self.encapsulate_and_send(packet_bytes)
            
            except BlockingIOError:
                continue
                

    def encapsulate_and_send(self, pkt):
        try:
            if IP not in pkt:
                return
            #adding into icmp payload, with magic
            full_packet_bytes = bytes(pkt[IP])
            payload = PAYLOAD_MAGIC + full_packet_bytes
            wrapper_pkt = IP(dst=self.default_gateway, src=pkt[IP].dst) / ICMP(type=8) / payload
            send(wrapper_pkt, verbose=0, iface=self.network_interface)

        except Exception as e:
            print("Error in encapsulate_and_send:", e)


if __name__ == "__main__":
    pass
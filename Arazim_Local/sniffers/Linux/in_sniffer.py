import sys
import os
from scapy.all import sniff, send, Raw, conf, L3RawSocket, defragment
from scapy.layers.inet import IP, TCP

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from sniffers.constants import PAYLOAD_MAGIC
from utils import network_stats
from sniffers.sniffers_utils import sniff_assembled

conf.L3socket = L3RawSocket

def real_ip_to_local(ip):
    ind = ip.find(".")
    if ind == -1:
        raise ValueError("Invalid IP")
    return "127" + ip[ind:]

class In_Sniffer:
    tun_fd = None
    def __init__(self, our_ip, default_gateway, sniff_iface, lo_iface, tun_fd):
        self.our_ip = our_ip
        self.default_gateway = default_gateway
        self.sniff_iface = sniff_iface
        self.lo_iface = lo_iface
        self.bpf_filter = f"dst host {our_ip} and src {default_gateway} and ip"
        In_Sniffer.tun_fd = tun_fd

    def start_sniff(self):
        """
        sniff(
            filter=self.bpf_filter,
            iface=self.sniff_iface,
            prn=self.handle_packet,
            store=0,
        )
        """
        sniff_assembled(
            filter=self.bpf_filter, iface=self.sniff_iface, prn=self.decapsulate_and_inject
        )

    def decapsulate_and_inject(self, pkt):
        """
        Takes an ICMP echo packet, checks that the magic is there,
        and injects the "raw" part into loopback.
        """
        tun_fd = In_Sniffer.tun_fd
        try:
            # make sure its our magic
            if pkt[Raw].load[: len(PAYLOAD_MAGIC)] != PAYLOAD_MAGIC:
                return
            # get the raw, without magic (og packet)
            decapsulated = IP(pkt[Raw].load[len(PAYLOAD_MAGIC) :])
            #del decapsulated[IP].chksum
            #del decapsulated[IP].len
            #if TCP in decapsulated:
             #   del decapsulated[TCP].chksum

            os.write(tun_fd, bytes(decapsulated))
        except Exception as e:
            print(e)

            
if __name__ == "__main__":
    pass
import os
import sys
import select
import logging

from scapy.all import sendp
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from sniffers.constants import PAYLOAD_MAGIC

logger = logging.getLogger("arazim.out_sniffer")

# How long select() blocks before we re-check the stop event.
_SELECT_TIMEOUT = 0.5
# Max bytes to read from the TUN in one go (comfortably above the interface MTU).
_TUN_READ_SIZE = 65535


class Out_Sniffer:
    """
    Reads outgoing IP packets from the TUN device and tunnels them to a peer by
    abusing the router as an ICMP reflector: we send an echo request whose
    source is spoofed to the peer's IP and whose destination is the gateway, so
    the router bounces the echo reply (carrying our payload) to that peer.
    """

    def __init__(
        self,
        target_subnet,
        target_subnet_mask,
        my_ip,
        network_interface,
        default_gateway,
        router_mac,
        my_mac,
        tun_fd,
    ):
        self.target_subnet = target_subnet
        self.target_subnet_mask = target_subnet_mask
        self.my_ip = my_ip
        self.network_interface = network_interface
        self.default_gateway = default_gateway
        self.router_mac = router_mac
        self.my_mac = my_mac
        self.tun_fd = tun_fd

    def start_sniff(self, stop_event):
        """
        Loop reading raw IP packets from the TUN and tunnelling them until
        ``stop_event`` is set. Uses select() so an idle TUN does not spin the
        CPU and so the loop wakes up promptly to notice the stop event.
        Intended to be run inside its own thread.
        """
        fd = self.tun_fd
        logger.info("out-sniffer started, reading from TUN fd=%d", fd)
        while not stop_event.is_set():
            try:
                readable, _, _ = select.select([fd], [], [], _SELECT_TIMEOUT)
                if fd not in readable:
                    continue
                packet_bytes = os.read(fd, _TUN_READ_SIZE)
                if not packet_bytes:
                    continue
                ip_packet = IP(packet_bytes)
                self.encapsulate_and_send(ip_packet)
            except BlockingIOError:
                continue
            except OSError as e:
                if stop_event.is_set():
                    break
                logger.error("error reading from TUN: %s", e)
            except Exception:
                logger.exception("unexpected error in out-sniffer loop")
        logger.info("out-sniffer stopped")

    def encapsulate_and_send(self, pkt):
        try:
            if IP not in pkt:
                return
            # embed the full original IP packet (with a magic marker) as the
            # ICMP echo payload
            full_packet_bytes = bytes(pkt[IP])
            payload = PAYLOAD_MAGIC + full_packet_bytes
            # Spoof the source as the peer we want to reach and aim the wrapper
            # at the gateway; the router reflects the echo reply (and payload)
            # back to that peer. See In_Sniffer for the receiving side.
            #
            # We send at L2 with sendp() and an explicit Ethernet header so the
            # frame always egresses the real NIC toward the router, regardless
            # of the routing table (L3 send() ignores iface= and would route the
            # gateway-bound wrapper back into the TUN).
            wrapper_pkt = (
                Ether(dst=self.router_mac, src=self.my_mac)
                / IP(dst=self.default_gateway, src=pkt[IP].dst)
                / ICMP(type=8)
                / payload
            )
            sendp(wrapper_pkt, verbose=0, iface=self.network_interface)
        except Exception:
            logger.exception("error in encapsulate_and_send")


if __name__ == "__main__":
    pass

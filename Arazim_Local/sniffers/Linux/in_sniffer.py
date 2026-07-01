import sys
import os
import logging

from scapy.all import Raw
from scapy.layers.inet import IP

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from sniffers.constants import PAYLOAD_MAGIC
from sniffers.sniffers_utils import make_async_sniffer

logger = logging.getLogger("arazim.in_sniffer")


class In_Sniffer:
    """
    Sniffs the reflected ICMP echo-replies coming back from the router, strips
    the magic + ICMP wrapper, and writes the original IP packet back into the
    TUN device so the local stack delivers it as if it arrived normally.
    """

    def __init__(self, our_ip, default_gateway, sniff_iface, tun_fd):
        self.our_ip = our_ip
        self.default_gateway = default_gateway
        self.sniff_iface = sniff_iface
        self.tun_fd = tun_fd
        # The router reflects our spoofed echo request back to us as an echo
        # reply, so the wrapper we care about is addressed FROM the gateway TO us.
        self.bpf_filter = f"dst host {our_ip} and src host {default_gateway} and ip"
        self._sniffer = None

    def start_sniff(self, stop_event):
        """
        Start sniffing on a background AsyncSniffer thread and block until
        ``stop_event`` is set, then tear the sniffer down cleanly. Intended to
        be run inside its own thread.
        """
        self._sniffer = make_async_sniffer(
            self.bpf_filter, self.sniff_iface, self.decapsulate_and_inject
        )
        self._sniffer.start()
        logger.info(
            "in-sniffer started (iface=%s, filter=%r)",
            self.sniff_iface,
            self.bpf_filter,
        )
        try:
            while not stop_event.is_set():
                if not self._sniffer.running:
                    logger.error("in-sniffer stopped unexpectedly")
                    stop_event.set()
                    break
                stop_event.wait(0.5)
        finally:
            self.stop_sniff()

    def stop_sniff(self):
        if self._sniffer is not None and self._sniffer.running:
            try:
                self._sniffer.stop()
                self._sniffer.join()
                logger.info("in-sniffer stopped")
            except Exception:
                logger.exception("error while stopping in-sniffer")

    def decapsulate_and_inject(self, pkt):
        """
        Takes a reflected ICMP echo-reply, verifies our magic, and writes the
        embedded original IP packet into the TUN device. The embedded packet is
        written verbatim, so its checksums are already valid - do NOT recompute
        them (unlike the loopback variant, which rewrites addresses).
        """
        try:
            if Raw not in pkt:
                return
            load = bytes(pkt[Raw].load)
            # make sure it is our magic
            if load[: len(PAYLOAD_MAGIC)] != PAYLOAD_MAGIC:
                return
            # strip the magic to recover the original IP packet
            decapsulated = IP(load[len(PAYLOAD_MAGIC):])
            os.write(self.tun_fd, bytes(decapsulated))
        except OSError as e:
            logger.error("failed writing decapsulated packet to TUN: %s", e)
        except Exception:
            logger.exception("failed to decapsulate incoming packet")


if __name__ == "__main__":
    pass

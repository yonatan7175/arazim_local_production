import sys
import os
import fcntl
import struct
import signal
import logging
import threading
import subprocess

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from utils.network_stats import NetworkStats
from sniffers.constants import TUN_NAME
from in_sniffer import In_Sniffer
from out_sniffer import Out_Sniffer

logger = logging.getLogger("arazim.tun")

# TUN constants
TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# ip route metric preferred for our TUN route
PREFERRED_METRIC = "20"

# How long to wait for the sniffer threads to join on shutdown.
_THREAD_JOIN_TIMEOUT = 5


def create_tun_interface(interface_name=b"tun%d"):
    if isinstance(interface_name, str):
        interface_name = interface_name.encode("utf-8")
    tun_fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    try:
        ifr = struct.pack("16sH", interface_name, IFF_TUN | IFF_NO_PI)
        actual_name_bytes = fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    except OSError:
        os.close(tun_fd)
        raise
    assigned_name = actual_name_bytes[:16].strip(b"\x00").decode("utf-8")
    logger.info("allocated TUN interface: %s", assigned_name)
    return tun_fd, assigned_name


def configure_interface(name, ip_cidr):
    subprocess.run(["ip", "addr", "add", ip_cidr, "dev", name], check=True)
    subprocess.run(["ip", "link", "set", "dev", name, "up"], check=True)
    logger.info("interface %s is UP with IP %s", name, ip_cidr)


def configure_routing_table(name, net_stats):
    base_addr = net_stats.get_base_addr()
    target_net = f"{base_addr}/{net_stats.subnet_cidr}"

    # Drop the auto-created kernel route first to avoid a conflict, then add
    # ours with an explicit (preferred) metric so LAN traffic goes via the TUN.
    subprocess.run(["ip", "route", "del", target_net, "dev", name], check=False)
    subprocess.run(
        [
            "ip", "route", "add", target_net,
            "dev", name,
            "proto", "kernel",
            "scope", "link",
            "src", net_stats.my_ip,
            "metric", PREFERRED_METRIC,
        ],
        check=True,
    )
    logger.info("route added: %s dev %s metric %s", target_net, name, PREFERRED_METRIC)


def cleanup_routing_table(name, net_stats):
    """Best-effort removal of the route we added (the TUN itself disappears
    once its fd is closed since it is not persistent)."""
    try:
        base_addr = net_stats.get_base_addr()
        target_net = f"{base_addr}/{net_stats.subnet_cidr}"
        subprocess.run(["ip", "route", "del", target_net, "dev", name], check=False)
    except Exception:
        logger.exception("failed to clean up routing table")


def run_in_sniffer(tun_fd, net_stats, stop_event):
    sniffer = In_Sniffer(
        net_stats.my_ip, net_stats.router_ip, net_stats.default_device, tun_fd
    )
    sniffer.start_sniff(stop_event)


def run_out_sniffer(tun_fd, net_stats, stop_event):
    sniffer = Out_Sniffer(
        net_stats.my_ip,
        net_stats.subnet_mask,
        net_stats.my_ip,
        net_stats.default_device,
        net_stats.router_ip,
        tun_fd,
    )
    sniffer.start_sniff(stop_event)


def main():
    stop_event = threading.Event()

    def _handle_signal(signum, _frame):
        # NOTE: SIGKILL/SIGSTOP cannot be caught; this covers the catchable
        # termination signals (Ctrl+C, `kill`, terminal hangup).
        logger.info("received signal %s, shutting down", signal.Signals(signum).name)
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _handle_signal)

    tun_fd = None
    name = None
    net_stats = None
    threads = []
    try:
        net_stats = NetworkStats.get_stats()
        if net_stats is None:
            logger.error("failed to gather network stats; aborting")
            return 1

        ip_cidr = f"{net_stats.my_ip}/{net_stats.subnet_cidr}"
        logger.info("subnet is %s", ip_cidr)

        tun_fd, name = create_tun_interface(TUN_NAME)
        configure_interface(name, ip_cidr)
        configure_routing_table(name, net_stats)

        threads = [
            threading.Thread(
                target=run_in_sniffer,
                args=(tun_fd, net_stats, stop_event),
                name="in-sniffer",
            ),
            threading.Thread(
                target=run_out_sniffer,
                args=(tun_fd, net_stats, stop_event),
                name="out-sniffer",
            ),
        ]
        for t in threads:
            t.start()

        logger.info("sniffers running; press Ctrl+C to stop")
        # Block the main thread until a signal arrives or a worker dies.
        while not stop_event.is_set():
            if not all(t.is_alive() for t in threads):
                logger.error("a sniffer thread exited unexpectedly; shutting down")
                stop_event.set()
                break
            stop_event.wait(0.5)

    except subprocess.CalledProcessError as e:
        logger.error("network configuration command failed: %s", e)
        return 1
    except Exception:
        logger.exception("fatal error while starting sniffers")
        return 1
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=_THREAD_JOIN_TIMEOUT)
        if name is not None and net_stats is not None:
            cleanup_routing_table(name, net_stats)
        if tun_fd is not None:
            try:
                os.close(tun_fd)
            except OSError as e:
                logger.error("failed to close TUN fd: %s", e)
        logger.info("shutdown complete")

    return 0


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    if os.geteuid() != 0:
        sys.exit("Please run as root/sudo.")
    sys.exit(main())

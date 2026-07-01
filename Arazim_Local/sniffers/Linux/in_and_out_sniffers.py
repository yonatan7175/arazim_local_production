import sys
import os
import fcntl
import struct
import subprocess
from scapy.layers.inet import *

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from sniffers.sniffers_utils import *
from utils import network_stats
from sniffers.constants import PAYLOAD_MAGIC, TUN_NAME
from in_sniffer import In_Sniffer
from out_sniffer import Out_Sniffer

#TUN constants
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000


def create_tun_interface(interface_name=b'tun%d'):
    tun_fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
    ifr = struct.pack('16sH', interface_name, IFF_TUN | IFF_NO_PI)
    actual_name_bytes = fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    assigned_name = actual_name_bytes[:16].strip(b'\x00').decode('utf-8')
    print(f"Successfully allocated interface: {assigned_name}")
    return tun_fd, assigned_name

def configure_interface(name, ip_cidr):
    subprocess.run(['sudo', 'ip', 'addr', 'add', ip_cidr, 'dev', name], check=True)
    subprocess.run(['sudo', 'ip', 'link', 'set', 'dev', name, 'up'], check=True)
    print(f"Interface {name} is UP with IP {ip_cidr}")

def configure_routing_table(name, net_stats: network_stats):
    ip_address = net_stats.my_ip
    base_addr = net_stats.get_base_addr()
    target_net = f"{base_addr}/{net_stats.subnet_cidr}"
    subprocess.run([
    'sudo', 'ip', 'route', 'del', target_net, 'dev', name
    ], check=False)

    # 2. Add the route explicitly with your metric
    PREFERRED_METRIC = "20" 
    subprocess.run([
        'sudo', 'ip', 'route', 'add', target_net,
        'dev', name,
        'proto', 'kernel',
        'scope', 'link',
        'src', ip_address,
        'metric', PREFERRED_METRIC
        ], check=True)
    

def in_sniffer(tun_fd: int, net_stats: network_stats):
    """
    def main():
    stats = network_stats.NetworkStats.get_stats()
    if stats is None:
        print("Networks stats failed, closing sniffer")
        exit(0)
    in_sniffer = In_Sniffer(
        stats.my_ip, stats.router_ip, stats.default_device, stats.loopback_device
    )
    in_sniffer.start_sniff()

    """
    in_sniffer = In_Sniffer(net_stats.my_ip, net_stats.router_ip, net_stats.default_device, tun_fd)
    in_sniffer.sniff()
    pass


def out_sniffer(tun_fd: int, net_stats: network_stats):
    """
    def main():
    stats = network_stats.NetworkStats.get_stats()
    if stats is None:
        print("Networks stats failed, closing sniffer")
        exit(0)
    sniffer = Out_Sniffer(stats.my_ip, stats.subnet_mask, stats.my_ip, stats.default_device, stats.router_ip, tun_fd)
    sniffer.start_sniff()


    """
    out_sniffer = Out_Sniffer(net_stats.my_ip, net_stats.subnet_mask, net_stats.my_ip, net_stats.default_device, net_stats.router_ip, tun_fd)
    out_sniffer.start_sniff()

    pass

def main():
    #make sure we are running on root privalege
    
    try:
        fd = None
        net_stats = network_stats()
        ip_cidr = f"{net_stats.my_ip}/{net_stats.subnet_cidr}"
        print(f"subnet is {ip_cidr}")
        fd, name = create_tun_interface(TUN_NAME)
        configure_interface(name, ip_cidr)
        configure_routing_table()

    except Exception as exp:
        print(exp)
        print("closing in and out sniffer")
        sys.exit(-1)



if __name__ == "__main__":
    if os.geteuid() != 0:
        sys.exit("Please run as root/sudo.")
    main()
import subprocess
import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from utils import network_stats

def real_ip_to_local(ip):
    ind = ip.find(".")
    if ind == -1:
        raise ValueError("Invalid IP")
    return "127" + ip[ind:]


def disable_rst(subnet):
    disable_recv = ("sudo iptables -A OUTPUT "
    "-p tcp --tcp-flags RST RST "
    f"-d {subnet} -j DROP"
    )
    subprocess.run(disable_recv, shell=True, check=True)

    disable_send =  ("sudo iptables -A OUTPUT"
    f" -s {subnet} "
    "-p tcp --tcp-flags RST RST -j DROP"
    )
    subprocess.run(disable_send, shell=True, check=True)

if __name__ == "__main__":
    #netstats = network_stats.NetworkStats.get_stats()
    #subnet_str = f"{real_ip_to_local(netstats.get_base_addr())}/{netstats.network.prefixlen}"
    #disable_rst(subnet_str)
    pass
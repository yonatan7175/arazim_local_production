import subprocess
import platform
import psutil
from scapy.all import *
import ipaddress
from scapy.layers.l2 import getmacbyip


class NetworkStats:
    def __init__(self):
        self.my_ip, self.router_ip, self.default_device = self._get_ips_and_def_device()
        self.subnet_mask = self._get_subnet_mask(self.router_ip)
        self.subnet_cidr = ipaddress.IPv4Network(f"0.0.0.0/{self.subnet_mask}").prefixlen
        self.network = ipaddress.IPv4Network(
            f"{self.my_ip}/{self.subnet_mask}", strict=False
        )
        self.my_mac = self.get_my_mac(self.my_ip)
        self.router_mac = self.get_router_mac(self.router_ip)
        self.loopback_device = self.get_loopback_device()
        # check everything is initialized and not None
        if any(value is None for value in self.__dict__.values()):
            print(self.__dict__)
            raise ValueError("One or more network attributes failed to initialize.")

    def in_subnet(self, ip_addr):
        return ipaddress.IPv4Address(ip_addr) in self.network

    def get_base_addr(self):
        """Returns the mathematically correct network address (e.g., 172.16.158.0)"""
        return str(self.network.network_address)

    def get_router_mac(self, router_ip):
        router_mac = getmacbyip(router_ip)
        if router_mac is None:
            router_mac = "00:09:0f:09:00:1a"
        return router_mac

    def get_my_mac(self, my_ip):
        iface = conf.ifaces.get(self.default_device)
        if iface:
            return iface.mac
        return None

    def _get_ips_and_def_device(self):
        res = conf.route.route("8.8.8.8")
        # res usually returns (interface_name, local_ip, gateway_ip)
        iface_obj = res[0]
        my_ip = res[1]
        router_ip = res[2]

        # Handle cases where Scapy returns an interface object instead of a string
        iface_name = getattr(iface_obj, "name", str(iface_obj))

        return my_ip, router_ip, iface_name

    def _get_subnet_mask(self, router_ip):
        # get subnet mask
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((router_ip, 1))
        local_ip = s.getsockname()[0]
        s.close()

        interfaces = psutil.net_if_addrs()
        for _, addresses in interfaces.items():
            for addr in addresses:
                if addr.address == local_ip:
                    return addr.netmask
        return None

    def get_loopback_device(self):
        for name, iface in conf.ifaces.items():
            # 1. Check if it's named like a loopback (Mac/Linux/Unix)
            if name.lower().startswith("lo") or "loopback" in name.lower():
                return name

            # 2. Check the IP (with a safety check for None)
            if hasattr(iface, "ip") and iface.ip and iface.ip.startswith("127."):
                return name

            # 3. Check for the 'LOOPBACK' flag (Internal Scapy/OS flag)
            if (
                hasattr(iface, "flags") and iface.flags & 0x8
            ):  # 0x8 is usually the LOOPBACK flag
                return name

        # Absolute fallback based on OS
        return "lo0" if platform.system() == "Darwin" else "lo"

    @classmethod
    def get_stats(cls):
        try:
            return cls()
        except Exception as e:
            print(e)
            return None


if __name__ == "__main__":
    stats = NetworkStats.get_stats()
    print(f"My IP: {stats.my_ip}")
    print(f"Router IP: {stats.router_ip}")
    print(f"Default Device: {stats.default_device}")
    print(f"Subnet Mask: {stats.subnet_mask}")
    print(f"My MAC: {stats.my_mac}")
    print(f"Router MAC: {stats.router_mac}")
    print(f"Network Base Address: {stats.get_base_addr()}")

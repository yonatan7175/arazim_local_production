import sys
import os

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
from utils.network_stats import NetworkStats
from utils.Windows.arp_table_stats import WindowsArpManager


def clear_arp_cache():
    WindowsArpManager.clear_cache()


def main():
    clear_arp_cache()


if __name__ == "__main__":
    pass
    #main()

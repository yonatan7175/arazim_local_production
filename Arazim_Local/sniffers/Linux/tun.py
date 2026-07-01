import os
import fcntl
import struct
import subprocess

# Import Scapy components for Layer 3 and Layer 4 parsing
from scapy.layers.inet import IP, ICMP, TCP

# --- Global Configurations ---
IP_ADDRESS = "172.30.53.226"
SUBNET_MASK = "20"
SUBNET_CIDR = f"{IP_ADDRESS}/{SUBNET_MASK}"
# The target network for the routing table adjustment
TARGET_NETWORK = f"172.30.48.0/{SUBNET_MASK}"

# Linux constants for TUN/TAP allocation
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000  # Do not provide packet information header

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

if __name__ == "__main__":
    fd = None
    try:
        fd, name = create_tun_interface(b'G2_pro_interface')
        configure_interface(name, SUBNET_CIDR)
        
        print(f"Configuring routing table for {TARGET_NETWORK} on {name}...")
        
        # 1. Delete the default kernel-created route to avoid conflicts
        subprocess.run([
            'sudo', 'ip', 'route', 'del', TARGET_NETWORK, 'dev', name
        ], check=False)

        # 2. Add the route explicitly with your metric
        PREFERRED_METRIC = "20" 
        subprocess.run([
            'sudo', 'ip', 'route', 'add', TARGET_NETWORK,
            'dev', name,
            'proto', 'kernel',
            'scope', 'link',
            'src', IP_ADDRESS,
            'metric', PREFERRED_METRIC
        ], check=True)
        
        print(f"Route added successfully with metric {PREFERRED_METRIC}!")
        print("Listening for Ping (ICMP) and TCP Connection Requests... Press Ctrl+C to exit.")
        
        while True:
            try:
                # 1. Read the raw Layer 3 packet from the TUN interface
                packet_bytes = os.read(fd, 2048)
                
                # 2. Parse it with Scapy
                ip_packet = IP(packet_bytes)
                
                # --- HANDLE ICMP (PING) PACKETS ---
                if ip_packet.haslayer(ICMP):
                    icmp_layer = ip_packet[ICMP]
                    
                    if icmp_layer.type == 8: # Echo Request
                        print(f"\n[ICMP REQUEST] {ip_packet.src} -> {ip_packet.dst}")
                        print(f"    └─ ID: {icmp_layer.id} | Seq: {icmp_layer.seq} | TTL: {ip_packet.ttl}")
                        
                        # Auto-reply to pings
                        reply_ip = IP(src=ip_packet.dst, dst=ip_packet.src)
                        reply_icmp = ICMP(type=0, id=icmp_layer.id, seq=icmp_layer.seq)
                        reply_packet = reply_ip / reply_icmp / icmp_layer.payload
                        os.write(fd, bytes(reply_packet))
                        print(f"    └─>> [SENT PING REPLY]")

                # --- HANDLE TCP PACKETS ---
                elif ip_packet.haslayer(TCP):
                    tcp_layer = ip_packet[TCP]
                    
                    # Look for connection initialization requests (SYN flag is set)
                    # flags == 2 or checking if 'S' is in the string representation of flags
                    flag_string = tcp_layer.underlayer.sprintf("%TCP.flags%")
                    
                    if "S" in flag_string and "A" not in flag_string:
                        print(f"\n[TCP SYN REQUEST] {ip_packet.src}:{tcp_layer.sport} -> {ip_packet.dst}:{tcp_layer.dport}")
                        print(f"    └─ Seq: {tcp_layer.seq} | Window: {tcp_layer.window} | Flags: {flag_string}")
                    else:
                        # Optional: Print other general TCP traffic flowing through
                        print(f"[TCP Traffic] {ip_packet.src}:{tcp_layer.sport} -> {ip_packet.dst}:{tcp_layer.dport} | Flags: {flag_string}")
                        
            except BlockingIOError:
                continue
                
    except KeyboardInterrupt:
        print("\nClosing interface.")
    finally:
        if fd is not None:
            os.close(fd)


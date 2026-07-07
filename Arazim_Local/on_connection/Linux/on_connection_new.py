import os
import sys
import subprocess

def is_tun_installed() -> bool:
    """
    Checks if the TUN device driver/module is available on Linux.
    """
    tun_device_path = "/dev/net/tun"
    if os.path.exists(tun_device_path):
        return True

    try:
        with open("/proc/modules", "r") as f:
            if "tun" in f.read():
                return True
    except FileNotFoundError:
        pass

    return False


def has_tun_permissions() -> bool:
    """
    Verifies if the current user has read/write permissions to the TUN device.
    """
    tun_device_path = "/dev/net/tun"
    if os.path.exists(tun_device_path):
        return os.access(tun_device_path, os.R_OK | os.W_OK)
    return False


def install_tun() -> bool:
    """
    Attempts to load the TUN kernel module and create the /dev/net/tun node.
    Requires root privileges.
    """
    print("\n[!] Attempting to install and configure TUN...")

    # 1. Check for root privileges (required for modprobe and mknod)
    if os.geteuid() != 0:
        print("[-] Error: Root privileges are required to configure TUN.")
        print("    Please run this script with sudo: sudo python3 script.py")
        return False

    # 2. Attempt to load the kernel module
    print("    -> Loading 'tun' kernel module (modprobe tun)...")
    result = subprocess.run(["modprobe", "tun"], capture_output=True, text=True)
    
    if result.returncode != 0:
        print("[-] Error: Failed to load 'tun' kernel module.")
        print("    The module might not be compiled into your kernel or installed on this system.")
        print(f"    Details: {result.stderr.strip()}")
        return False

    # 3. Create the device node directory if it doesn't exist
    tun_dir = "/dev/net"
    tun_dev = "/dev/net/tun"

    if not os.path.exists(tun_dir):
        print(f"    -> Creating directory {tun_dir}...")
        try:
            os.makedirs(tun_dir, exist_ok=True)
        except Exception as e:
            print(f"[-] Error creating directory: {e}")
            return False

    # 4. Create the character device node
    if not os.path.exists(tun_dev):
        print(f"    -> Creating character device {tun_dev} (mknod)...")
        # mknod /dev/net/tun c 10 200
        # 'c' = character device, '10' = standard misc major, '200' = standard tun minor
        result = subprocess.run(["mknod", tun_dev, "c", "10", "200"], capture_output=True, text=True)
        
        if result.returncode != 0:
            print("[-] Error: Failed to create TUN device node.")
            print(f"    Details: {result.stderr.strip()}")
            return False
            
        # Optional: Set permissions so non-root processes in specific groups can use it
        print("    -> Setting basic permissions (chmod 666)...")
        os.chmod(tun_dev, 0o666)
    else:
        print(f"    -> Device {tun_dev} already exists.")

    print("[+] TUN successfully installed and configured!")
    return True


if __name__ == "__main__":
    if sys.platform != "linux":
        print(f"[-] Error: This script is explicitly configured for Linux. Detected: {sys.platform}")
        sys.exit(1)

    print("Checking for Linux TUN device driver...")
    
    if is_tun_installed():
        print("[+] Success: TUN driver/module is already installed and available.")
        if has_tun_permissions():
            print("[+] Success: Current user has permission to read/write to /dev/net/tun.")
        else:
            print("[-] Warning: TUN is installed, but you lack permissions. Try running your app as root (sudo).")
    else:
        print("[-] Warning: TUN driver could not be detected.")
        install_tun()
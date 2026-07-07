import os
import sys
import subprocess
import platform
import ctypes
from constants import *


def is_admin():
    try:
        # Check for Windows Admin
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        # Check for Linux/Mac Root (UID 0)
        return os.geteuid() == 0


def run_as_admin():
    if is_admin():
        # Already admin, nothing to do
        return

    print("Requesting administrative privileges...")

    if platform.system() == "Windows":
        # Re-run the script with the 'runas' verb (triggers UAC)
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
    else:
        # Re-run with sudo for Linux/Mac
        subprocess.check_call(["sudo", sys.executable] + sys.argv)

    sys.exit()


def get_platform():
    os_name = platform.system()
    is_64bit = sys.maxsize > 2**32

    if os_name == "Windows":
        return WINDOWS_X64 if is_64bit else WINDOWS_X86
    elif os_name == "Darwin":
        return MAC_OS
    elif os_name == "Linux":
        return LINUX_OS
    else:
        return UNKNOWN_OS


def main():
    run_as_admin()
    platform_type = get_platform()
    if platform_type == UNKNOWN_OS:
        print("Unsupported operating system.")
        exit(1)
    print(f"Detected platform: {platform_type}")
    permanent_dir = os.path.join(OS_TO_PROGRAM_FILES[platform_type], "Arazim_Local")
    manager_path = os.path.join(permanent_dir, "manager", "manager.py")
    subprocess.Popen([sys.executable, manager_path])


if __name__ == "__main__":
    main()

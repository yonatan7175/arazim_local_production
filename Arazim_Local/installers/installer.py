import os
import sys
import shutil
import subprocess
import platform
import ctypes
from constants import *
from add_desktop_icon import add_desktop_icon, add_linux_bin_launcher
from dep_checker import has_dependencies
from installer_utils import get_platform

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


def set_program_dir(platform):
    if platform not in OS_TO_PROGRAM_FILES:
        print("not supported platform")
        exit(1)

    current_dir = os.path.dirname(os.path.abspath(__file__))
    arazim_local_dir = os.path.join(current_dir, "..")

    # --- THIS IS THE CRITICAL CHANGE ---
    # We take "C:\Program Files" and turn it into "C:\Program Files\Arazim_Local"
    target_dir = os.path.join(OS_TO_PROGRAM_FILES[platform], "Arazim_Local")
    # -----------------------------------

    try:
        print(f"Source: {arazim_local_dir}")
        print(f"Target: {target_dir}")

        # Now it will create the "Arazim Local" folder inside Program Files
        shutil.copytree(arazim_local_dir, target_dir, dirs_exist_ok=True)
        print("Copy Successful!")
        return target_dir
    except Exception as e:
        print(f"unable to copy ARAZIM LOCAL dir!!! Error: {e}")
        exit(-1)


def main():
    platform = get_platform()
    if not has_dependencies(platform):
        return
    run_as_admin()
    if platform == UNKNOWN_OS:
        print("Unsupported operating system.")
        exit(1)
    print(f"Detected platform: {platform}")
    project_dir = set_program_dir(platform)
    if platform == LINUX_OS:
        add_linux_bin_launcher(project_dir)
    add_desktop_icon(platform, project_dir)


if __name__ == "__main__":
    main()

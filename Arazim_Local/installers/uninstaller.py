import shutil
import time
import os
import sys
CUR_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.join(CUR_DIR, "..")
sys.path.append(CUR_DIR)
sys.path.append(os.path.join(PARENT_DIR, "utils"))
from manager_utils import kill_manager, is_manager_running
from add_desktop_icon import get_desktop_icon_path, get_linux_bin_launcher_path
from installer_utils import get_platform
from constants import LINUX_OS, OS_TO_PROGRAM_FILES

INSTALL_DIR_NAME = "Arazim_Local"


def get_install_dir():
    """The canonical location the installer copies the project to."""
    base = OS_TO_PROGRAM_FILES.get(get_platform())
    if not base:
        return None
    return os.path.normpath(os.path.join(base, INSTALL_DIR_NAME))


def remove_desktop_icon():
    try:
        icon_path = get_desktop_icon_path()
    except Exception as e:
        print(f"Could not locate desktop icon: {e}")
        return
    if icon_path and os.path.exists(icon_path):
        os.remove(icon_path)


def remove_bin_launcher():
    if get_platform() != LINUX_OS:
        return
    launcher_path = get_linux_bin_launcher_path()
    if os.path.exists(launcher_path):
        try:
            os.remove(launcher_path)
        except OSError as e:
            print(f"Could not remove {launcher_path}: {e}")


def uninstall_project():
    kill_manager()
    remove_desktop_icon()
    remove_bin_launcher()
    while is_manager_running():
        time.sleep(0.1)  # wait for manager to stop running

    install_dir = get_install_dir()
    running_dir = os.path.normpath(os.path.abspath(PARENT_DIR))

    if install_dir is None:
        print("Unsupported platform; not deleting any files.")
        return
    if not os.path.isdir(install_dir):
        print(f"Install directory not found ({install_dir}); nothing to delete.")
        return

    # SAFETY: only ever delete the installed copy. If this uninstaller is being
    # run from anywhere else (e.g. a source/dev checkout), refuse - otherwise we
    # would wipe the directory we happen to be running from.
    if running_dir != install_dir:
        print(
            "Refusing to delete files.\n"
            f"  running from : {running_dir}\n"
            f"  install dir  : {install_dir}\n"
            "This looks like a source checkout, not the installed copy. "
            "Run the uninstaller from the installed location to remove it."
        )
        return

    shutil.rmtree(install_dir)
    print(f"Removed {install_dir}")


if __name__ == "__main__":
    uninstall_project()

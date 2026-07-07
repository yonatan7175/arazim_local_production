import os
import sys
from constants import *
from installer_utils import get_platform

def get_desktop_icon_path(platform=get_platform()):
    if platform == LINUX_OS:
        import pwd
        real_user = os.environ.get("SUDO_USER")
        if not real_user:
            raise RuntimeError("This script must be run with sudo")

        user_info = pwd.getpwnam(real_user)
        home_dir = user_info.pw_dir

        desktop_dir = os.path.join(home_dir, "Desktop")
        return os.path.join(desktop_dir, "my_app.desktop")
    elif platform in [WINDOWS_X64, WINDOWS_X86]:
        home_dir = os.path.expanduser("~")
        desktop_dir = os.path.join(home_dir, "Desktop")
        return os.path.join(desktop_dir, "ARAZIM_LOCAL.bat")
    
def get_linux_bin_launcher_path():
    return LINUX_LAUNCHER_PATH


def add_linux_bin_launcher(project_dir):
    """
    Install /bin/arazim_local: a small shell launcher that

      1. ensures it runs as root (re-invoking itself through sudo if not), and
      2. runs the dashboard normally (in the foreground).

    Only the dashboard path is baked in (its install location is fixed); the
    Python interpreter is resolved from the system's PATH at run time rather
    than hardcoded.
    """
    dashboard_path = os.path.join(project_dir, "dashboard", "dashboard.pyw")

    launcher_content = f"""#!/bin/bash
# Arazim Local launcher (installed by installer.py). Do not edit by hand.

# 1) Require root. -E preserves DISPLAY/XAUTHORITY so the pygame GUI can still
#    reach the user's X session after escalating.
if [ "$(id -u)" -ne 0 ]; then
    exec sudo -E "$0" "$@"
fi

# 2) Resolve the system's Python at run time instead of a fixed path.
PYTHON="$(command -v python3 || command -v python)"
if [ -z "$PYTHON" ]; then
    echo "arazim_local: no python interpreter found on PATH" >&2
    exit 1
fi

# 3) Run the dashboard.
"$PYTHON" "{dashboard_path}"
"""

    with open(LINUX_LAUNCHER_PATH, "w") as f:
        f.write(launcher_content)
    os.chmod(LINUX_LAUNCHER_PATH, 0o755)
    print(f"[+] Installed launcher: {LINUX_LAUNCHER_PATH}")


def add_linux(dashboard_path):
    import pwd
    real_user = os.environ.get("SUDO_USER")
    if not real_user:
        raise RuntimeError("This script must be run with sudo")

    user_info = pwd.getpwnam(real_user)
    home_dir = user_info.pw_dir

    desktop_dir = os.path.join(home_dir, "Desktop")
    desktop_file = os.path.join(desktop_dir, "my_app.desktop")

    # Launch via the system-wide launcher (installed at LINUX_LAUNCHER_PATH),
    # which handles privilege escalation and detaching. A .desktop Exec line is
    # not a shell, so it cannot use sudo/nohup/redirects/& directly.
    desktop_content = f"""[Desktop Entry]
Version=1.0
Type=Application
Name=My App
Exec=arazim_local
Terminal=true
Categories=Utility;
"""

    os.makedirs(desktop_dir, exist_ok=True)

    with open(desktop_file, "w") as f:
        f.write(desktop_content)

    os.chown(desktop_file, user_info.pw_uid, user_info.pw_gid)
    os.chmod(desktop_file, 0o755)


def add_windows(dashboard_path):
    home_dir = os.path.expanduser("~")
    desktop_dir = os.path.join(home_dir, "Desktop")
    bat_file = os.path.join(desktop_dir, "ARAZIM_LOCAL.bat")

    python_name = sys.executable

    bat_content = f"""@echo off
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

start "" "{python_name}" "{dashboard_path}"
"""

    os.makedirs(desktop_dir, exist_ok=True)
    with open(bat_file, "w", encoding="utf-8") as f:
        f.write(bat_content)


def add_desktop_icon(platform, project_dir):
    dashboard_path = os.path.join(project_dir, DASHBOARD_RELATIVE_TO_BASE_DIR)

    if platform == LINUX_OS:
        add_linux(dashboard_path)
    else:
        add_windows(dashboard_path)

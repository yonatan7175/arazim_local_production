import os
import sys
import platform
import ctypes
import re
import subprocess
import importlib.metadata as importlib_metadata


# Arazim_Local dir == one level up from this file (utils/ -> Arazim_Local/).
# The requirements files live here so the whole app stays self-contained when
# deployed (e.g. copied to /opt/Arazim_Local by install.py).
_BASE_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
)

# Per-OS requirements file living alongside the app.
_REQUIREMENTS_FILES = {
    "Windows": "requirements-windows.txt",
    "Linux": "requirements-linux.txt",
    "Darwin": "requirements-linux.txt",  # macOS shares the pure-Python deps
}

# Maps a PyPI distribution name to the module you actually import, for the rare
# cases where they differ. Anything not listed is assumed to match.
_IMPORT_NAME_OVERRIDES = {}

# Splits "scapy>=2.6.1" into ("scapy", ">=", "2.6.1"). The version part is
# optional; only the name is required.
_REQ_LINE_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9._-]+)\s*"
    r"(?P<op>==|>=|<=|~=|!=|>|<)?\s*"
    r"(?P<version>[A-Za-z0-9._-]+)?\s*$"
)


def root_check():
    # 1. Extract the OS type yourself
    this_os = platform.system()

    is_admin = False

    # 2. Perform the OS-specific check
    if this_os == "Windows":
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except AttributeError:
            is_admin = False

        if not is_admin:
            print("Requesting administrative privileges...")
            # Re-run the script with admin rights ('runas' triggers the UAC
            # prompt). UAC resets the working directory to System32, so the
            # script path must be absolute; and args must be quoted, or a space
            # in the path (e.g. a "John Smith" user profile) splits argv and the
            # elevated process fails to find the script. list2cmdline handles the
            # quoting for us.
            script = os.path.abspath(sys.argv[0])
            params = subprocess.list2cmdline([script] + sys.argv[1:])
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
            sys.exit(0)  # Exit the current non-privileged process
    else:
        # For Linux/macOS
        try:
            is_admin = os.getuid() == 0
        except AttributeError:
            is_admin = False

    # 3. Handle the result
    if not is_admin:
        privilege_name = "Administrator" if this_os == "Windows" else "root/sudo"
        print(f"[-] Error: Insufficient Permissions.")
        print(
            f"[*] This script must be run as {privilege_name} to access network interfaces."
        )
        sys.exit(1)


def _parse_requirements(path):
    """
    Parse a requirements file into a list of (name, op, version) tuples.
    Blank lines, comments and inline comments are stripped. Unrecognised lines
    are skipped rather than crashing the launcher.
    """
    requirements = []
    with open(path, "r", encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.split("#", 1)[0].strip()  # drop inline comments
            if not line:
                continue
            match = _REQ_LINE_RE.match(line)
            if not match:
                continue
            requirements.append(
                (match.group("name"), match.group("op"), match.group("version"))
            )
    return requirements


def _version_tuple(version_str):
    """
    Turn a dotted version into a comparable tuple of ints, e.g. "2.6.1" ->
    (2, 6, 1). Non-numeric trailing parts (e.g. "2.1rc1") are truncated at the
    first non-numeric chunk so the comparison stays best-effort and never raises.
    """
    parts = []
    for chunk in version_str.split("."):
        num = re.match(r"^\d+", chunk)
        if not num:
            break
        parts.append(int(num.group()))
    return tuple(parts)


def _version_satisfies(installed, op, required):
    """Best-effort check of `installed <op> required`. Only >= / > / == / <= / <
    are enforced; unknown operators are treated as satisfied (presence wins)."""
    if op is None or required is None:
        return True
    have = _version_tuple(installed)
    need = _version_tuple(required)
    if op == ">=":
        return have >= need
    if op == ">":
        return have > need
    if op == "<=":
        return have <= need
    if op == "<":
        return have < need
    if op == "==":
        return have == need
    # ~=, != and anything unexpected: don't block on it, presence is enough.
    return True


def _check_single(name, op, required):
    """
    Returns None if the requirement is satisfied, otherwise a human-readable
    reason string ("not installed" / "x.y installed, need >= a.b").
    """
    module_name = _IMPORT_NAME_OVERRIDES.get(name, name)
    try:
        installed = importlib_metadata.version(name)
    except importlib_metadata.PackageNotFoundError:
        # Fall back to an import check: some things are importable without
        # carrying standard distribution metadata.
        try:
            __import__(module_name)
            return None
        except Exception:
            return "not installed"

    if not _version_satisfies(installed, op, required):
        return f"{installed} installed, need {op}{required}"
    return None


def requirements_check():
    """
    Verify the third-party Python packages this project needs are installed for
    the *current* interpreter (``sys.executable``). If anything is missing, print
    the exact ``pip install`` command to fix it and exit; otherwise return.

    Call this AFTER root_check() so the message reflects the elevated context the
    manager actually runs in (root on Linux/macOS, Administrator on Windows).
    """
    this_os = platform.system()
    req_filename = _REQUIREMENTS_FILES.get(this_os, "requirements-linux.txt")
    req_path = os.path.join(_BASE_DIR, req_filename)

    if not os.path.isfile(req_path):
        # Don't hard-fail the whole app just because the manifest is missing;
        # warn loudly and let the imports fail later with their own errors.
        print(f"[!] Warning: requirements file not found: {req_path}")
        return

    try:
        requirements = _parse_requirements(req_path)
    except OSError as e:
        print(f"[!] Warning: could not read {req_path}: {e}")
        return

    missing = []
    for name, op, required in requirements:
        reason = _check_single(name, op, required)
        if reason is not None:
            missing.append((name, reason))

    if not missing:
        return

    # Build a clear, copy-pasteable remediation message tailored to the OS.
    print("[-] Error: Missing or outdated Python dependencies:")
    for name, reason in missing:
        print(f"      - {name} ({reason})")

    # Use sys.executable so the user installs into the SAME interpreter that runs
    # the project, not whatever `pip`/`python` happens to be on PATH.
    py = sys.executable or "python3"
    if this_os == "Windows":
        install_cmd = f'"{py}" -m pip install -r "{req_path}"'
        print("\n[*] Install them from an Administrator terminal, then relaunch:")
        print(f"      {install_cmd}")
    else:
        # The manager runs as root, so packages must be visible to root. Prefer
        # showing an explicit sudo command in case this was launched otherwise.
        install_cmd = f'sudo "{py}" -m pip install -r "{req_path}"'
        print("\n[*] Install them (as root, so the elevated manager sees them):")
        print(f"      {install_cmd}")
        print(
            "    If pip refuses on a system-managed Python, either use your "
            "distro packages\n    (e.g. apt install python3-scapy python3-psutil) "
            "or add --break-system-packages."
        )

    sys.exit(1)


# Usage in the code:
if __name__ == "__main__":
    root_check()
    requirements_check()
    print("[+] Permissions and dependencies verified. Starting NetworkStats...")

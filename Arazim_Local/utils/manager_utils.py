import os
import psutil
import json

MANAGER_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "manager")
SNIFFERS_DIR = os.path.normpath(
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "sniffers")
)
PATH_TO_RUNNING_BINARIES_FILE = os.path.join(
    MANAGER_DIR, "current_running_binaries.json"
)
PATH_TO_IS_CONNECTED_FILE = os.path.join(MANAGER_DIR, "is_connected.txt")


def _find_orphan_sniffers():
    """
    Find any process whose command line points at our sniffers directory.

    Safety net for kill_manager: if the manager spawned a sniffer in the tiny
    window before it caught SIGTERM (or was force-killed), that sniffer would
    otherwise survive as an orphan holding the TUN and tunnelling traffic while
    the dashboard reports STOPPED. Scoped to our own sniffers dir so it never
    touches unrelated processes.
    """
    found = []
    for proc in psutil.process_iter(["cmdline"]):
        try:
            cmdline = proc.info.get("cmdline") or []
            if any(
                isinstance(arg, str)
                and os.path.normpath(arg).startswith(SNIFFERS_DIR)
                for arg in cmdline
            ):
                found.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return found


def is_process_running_by_pid(pid, saved_start_time):
    """
    Checks if a process is still the same one we recorded.
    :param pid: Int from your JSON
    :param saved_start_time: Float from your JSON
    """
    try:
        # 1. Quick check: Is the PID even in the system table?
        if not psutil.pid_exists(pid):
            return False

        proc = psutil.Process(pid)
        current_start_time = proc.create_time()

        # 2. Compare the times.
        if abs(current_start_time - float(saved_start_time)) < 0.1:
            return True

        return False

    except:
        return False


def get_current_manager_info():
    with open(PATH_TO_RUNNING_BINARIES_FILE, "r") as f:
        data = f.read()
    if len(data) != 0:
        json_data = json.loads(data)
        return json_data.get("pid", None), json_data.get("start time", None)
    return None, None


def is_manager_running(update=False):
    """
    Checks if a manager is already running.
    If not, and update=True, records the current process as the active manager.
    """
    try:
        running_pid, start_time = get_current_manager_info()

        # 1. Check if the recorded process is actually alive
        if running_pid is not None and start_time is not None:
            if is_process_running_by_pid(running_pid, start_time):
                return True

        # 2. If we reach here, no manager is running.
        # If update is requested, save the current process info.
        if update:
            curr_proc = psutil.Process(os.getpid())
            data = {"pid": curr_proc.pid, "start time": curr_proc.create_time()}
            with open(PATH_TO_RUNNING_BINARIES_FILE, "w") as f:
                json.dump(data, f)

        return False

    except (psutil.Error, IOError, ValueError) as e:
        # Log error if needed: print(f"Error checking manager status: {e}")
        return False


def kill_manager():
    pid, _ = get_current_manager_info()

    if pid is None:
        print("No manager process recorded.")
        # Still sweep for orphaned sniffers in case a previous manager died
        # without recording/cleaning up.
        _reap([], _find_orphan_sniffers())
        return

    try:
        if is_manager_running():
            parent = psutil.Process(pid)

            # Snapshot children up front as a safety net.
            children = parent.children(recursive=True)

            print(f"Terminating manager (PID {pid}) and {len(children)} children...")

            # Terminate the MANAGER FIRST. Its SIGTERM handler stops the
            # watchdog loop and kills its own sniffers, so it can't respawn a
            # sniffer after we killed it - the race that used to orphan tunnels
            # when children were killed before the (still-looping) parent.
            parent.terminate()
            try:
                parent.wait(timeout=6)
            except psutil.TimeoutExpired:
                print(f"Force killing manager: {parent.pid}")
                parent.kill()

            # Reap anything the manager did not clean up itself, plus any
            # orphaned sniffer that slipped through the respawn window.
            _reap(children, _find_orphan_sniffers())

            print("Manager and all sub-processes stopped.")
        else:
            print("Manager not running.")
            _reap([], _find_orphan_sniffers())

    except psutil.NoSuchProcess:
        print("Manager process already ended.")
        _reap([], _find_orphan_sniffers())
    except Exception as e:
        print(f"Error while killing manager: {e}")


def _reap(children, orphans):
    """Terminate (then, if stubborn, kill) the given processes."""
    targets = list(children) + list(orphans)
    if not targets:
        return
    for proc in targets:
        try:
            proc.terminate()
        except psutil.NoSuchProcess:
            pass
    _, alive = psutil.wait_procs(targets, timeout=3)
    for survivor in alive:
        print(f"Force killing stubborn process: {survivor.pid}")
        try:
            survivor.kill()
        except psutil.NoSuchProcess:
            pass


def save_is_connected(is_connected):
    with open(PATH_TO_IS_CONNECTED_FILE, "w") as f:
        f.write(str(is_connected))


def load_is_connected():
    with open(PATH_TO_IS_CONNECTED_FILE, "r") as f:
        return f.read(5) == "True"
    return False

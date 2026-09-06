from subprocess import Popen
import psutil
from scapy.all import *
import time
import os
import json
from constants import *
import signal
from functools import partial

sys.path.append(os.path.join(CURRENT_DIRECTORY, ".."))
from utils import network_stats, premissions_stats
from utils.manager_utils import is_manager_running, save_is_connected


def signal_handler(scripts, signum, frame):
    # scripts == [processes, on_disconnection_scripts]. Kill our own sniffers
    # first so the manager never leaves an orphaned tunnel behind, run the
    # disconnection scripts, mark ourselves disconnected, then exit.
    for process in scripts[0]:
        kill_process(process)
    run_binaries(scripts[1])
    save_is_connected(False)
    # Keep this well under the killer's grace period (see kill_manager, 6s) so
    # we exit cleanly on SIGTERM instead of being force-killed mid-shutdown.
    time.sleep(1)
    sys.exit(0)


# NOTE: SIGTERM is registered inside main() via functools.partial once the live
# `processes` list exists - registering the bare 3-arg handler here would be
# called by the OS with only (signum, frame) and crash with a TypeError.


WAS_CONNECTED_TO_G2 = False


def is_connection_new():
    global WAS_CONNECTED_TO_G2
    if not WAS_CONNECTED_TO_G2:
        WAS_CONNECTED_TO_G2 = True
        return True
    return False


def is_disconnected_now_from_G2():
    global WAS_CONNECTED_TO_G2
    if WAS_CONNECTED_TO_G2:
        WAS_CONNECTED_TO_G2 = False
        return True
    return False


def is_subprocess_running(process):
    """
    Docstring for is_sniffer_running

    :param process: the current running process
    :return: True if there is a process running, False otherwise
    """
    # print(process)
    if process is None:
        return False
    if process.poll() is not None:
        return_code = process.returncode
        print(f"subprocess ended with return code: {return_code}")
        return False
    return True

def watchdog(binary_args, process):
    """
    Docstring for in_g2_logic

    :param binary_path: the path to the binary that needs to be run
    :param args: arguments to be passed to the binary
    :param process: the current running process
    :return: the process if it is running, otherwise starts a new process and returns it
    """
    if is_subprocess_running(process):
        return process
    else:
        process = Popen(binary_args)
        return process


def kill_process(process):
    """
    Docstring for kill_process
    :param process: the current running process
    :return: None
    """
    if process is not None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except:
            process.kill()  # give some time to terminate
    return None


def run_binaries(binaries):
    for args in binaries:
        Popen(args)


def main(
    t,
    background_binaries_to_run,
    on_connection_scripts,
    on_disconnection_scripts,
):
    if is_manager_running(update=True):
        print("MANAGER: OTHER INSTANCE EXSISTS!!!")
        return

    processes = [None for _ in background_binaries_to_run]
    # Register now that `processes` exists; the closure holds a reference to the
    # same list main() mutates in place, so the handler always sees the current
    # sniffer PIDs and can kill them on SIGTERM.
    handler_with_args = partial(signal_handler, [processes, on_disconnection_scripts])
    signal.signal(signal.SIGTERM, handler_with_args)

    while True:
        try:
            stats = network_stats.NetworkStats.get_stats()
            print(f"MANAGER: network stats are: {stats}")
            is_connected_to_g2 = (stats is not None) and (
                stats.router_mac == G2_ROUTER_MAC
            )
            save_is_connected(is_connected_to_g2)
            if is_connected_to_g2:
                # always running binaries
                new_connection = is_connection_new()
                if new_connection:
                    run_binaries(on_connection_scripts)
                for i, binary_args in enumerate(background_binaries_to_run):
                    processes[i] = watchdog(binary_args, processes[i])
            else:
                # not in G2 logic
                if is_disconnected_now_from_G2():
                    # kill all running sniffers
                    for i, process in enumerate(processes):
                        processes[i] = kill_process(process)
                    print("manager disconnecting")

                    run_binaries(on_disconnection_scripts)
            time.sleep(t)
        except KeyboardInterrupt:
            print(KEYBOARD_INTERRUPT_MESSAGE)
            signal_handler([processes, on_disconnection_scripts], 1, 1)
            break
        except Exception as ex:
            print(f"An error occurred: {ex}")


if __name__ == "__main__":
    premissions_stats.root_check()
    premissions_stats.requirements_check()
    # No-op off Windows; there it stops us before the sniffers crash-loop on a
    # missing wpcap.dll.
    premissions_stats.npcap_check()
    main(
        TIME_INTERVAL_BETWEEN_CHECKS,
        BACKGROUND_BINARIES_TO_RUN,
        ON_CONNECTION_SCRIPTS,
        ON_DISCONNECTION_SCRIPTS,
    )

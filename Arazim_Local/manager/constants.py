"""
Docstring for manager.constants
This module contains constant values used throughout the manager directory.
"""

import sys
import os
import platform

THIS_OS = platform.system()
# Constant values for get_network_properties.py
WINDOWS = "Windows"
LINUX = "Linux"
MACOS = "Darwin"
DECODE_FORMAT = "utf-8"
NETWORK_NOT_FOUND = "Network name not found (or not on Wi-Fi)"
SUBNET_NOT_FOUND = "Subnet mask not found for the given interface."
DEFAULT_GATEWAY = "0.0.0.0"
LOOPBACK_IP = "127.0.0.1"
NOT_CONNECTED_MESSAGE = "Not connected to any network"
NETWORK_NAME_KEY = "network_name"
MY_IP_KEY = "my_ip"
ROUTER_IP_KEY = "router_ip"
DEFAULT_DEVICE_KEY = "default_device"
SUBNET_MASK_KEY = "subnet_mask"
G2_ROUTER_MAC = "00:09:0f:09:00:1a"

# Constant values for manager.py
PROCESSES_ALREADY_RUNNING_MESSAGE = "Required processes are already running. Exiting."
KEYBOARD_INTERRUPT_MESSAGE = "Execution interrupted by user."

PYTHON_BINARY = sys.executable
# format: binary_path: [arg1, arg2, ...]

"""
   {
        "network_name",
        "my_ip",
        "router_ip",
        "subnet_mask",
        "loopback_device"]"""
"""

the format is a list of lists, each list is a binary to run where the first element
is the binary path and the elements after are its arguments
"""
CURRENT_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
if THIS_OS == WINDOWS:
    BACKGROUND_BINARIES_TO_RUN = [
        [
            PYTHON_BINARY,
            os.path.join(CURRENT_DIRECTORY, "..", "sniffers", THIS_OS, "in_sniffer.py"),
        ],
        [
            PYTHON_BINARY,
            os.path.join(CURRENT_DIRECTORY, "..", "sniffers", THIS_OS, "out_sniffer.py"),
        ],
        [
                PYTHON_BINARY,
                os.path.join(CURRENT_DIRECTORY, "..", "sniffers", THIS_OS, "arp_server.py"),
        ]
    ]

if THIS_OS == LINUX:
    BACKGROUND_BINARIES_TO_RUN = [
        [
            PYTHON_BINARY,
            os.path.join(CURRENT_DIRECTORY, "..", "sniffers", THIS_OS, "in_and_out_sniffers.py"),
        ]
    ]

ON_CONNECTION_SCRIPTS = [
    [
        PYTHON_BINARY,
        os.path.join(
            CURRENT_DIRECTORY, "..", "on_connection", THIS_OS, "on_connection.py"
        ),
    ]
]

ON_DISCONNECTION_SCRIPTS = [
    [
        PYTHON_BINARY,
        os.path.join(
            CURRENT_DIRECTORY, "..", "on_disconnection", THIS_OS, "on_disconnection.py"
        ),
    ]
]

TIME_INTERVAL_BETWEEN_CHECKS = 2  # time interval in seconds
PATH_TO_RUNNING_BINARIES_FILE = os.path.join(
    CURRENT_DIRECTORY, "current_running_binaries.json"
)
PID_KEY = "pid"
START_TIME_KEY = "start_time"
PAYLOAD_MAGIC = "sxsvn"

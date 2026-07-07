import os

PROGRAM_FILES_X86 = os.environ.get("PROGRAMFILES(X86)") or "C:\\Program Files (x86)"
PROGRAM_FILES_X64 = os.environ.get("PROGRAMFILES") or "C:\\Program Files"
PROGRAM_FILES_MAC = "/Applications"
PROGRAM_FILES_LINUX = "/usr/bin"
WINDOWS_X64 = "windows_x64"
WINDOWS_X86 = "windows_x86"
MAC_OS = "macos"
LINUX_OS = "linux"
UNKNOWN_OS = "unknown"

OS_TO_PROGRAM_FILES = {
    WINDOWS_X64: PROGRAM_FILES_X64,
    WINDOWS_X86: PROGRAM_FILES_X86,
    MAC_OS: PROGRAM_FILES_MAC,
    LINUX_OS: PROGRAM_FILES_LINUX,
}

RUN_SCRIPT_LINUX = "/bin/bash"

OS_TO_SCRIPT_NAME = {
    WINDOWS_X64: "windows_x64.bat",
    WINDOWS_X86: "windows_x86.bat",
    MAC_OS: "macos.sh",
    LINUX_OS: "linux.sh",
}

OS_TO_SHELL = {
    WINDOWS_X64: ["cmd", "/c"],
    WINDOWS_X86: ["cmd", "/c"],
    MAC_OS: ["bash"],
    LINUX_OS: ["bash"],
}

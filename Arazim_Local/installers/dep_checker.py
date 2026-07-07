from constants import *
import importlib.util

def get_dependencies_file(platform):
    if platform == LINUX_OS:
        return "requirements_linux.txt"
    if platform in [WINDOWS_X64, WINDOWS_X86]:
        return "requirements_windows.txt"
    raise ValueError("Invalid Platform")

def get_dependencies(file_path):
    with open(file_path, 'r') as f:
        dependencies = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return dependencies

def has_dependencies(platform) -> bool:
    try:
        dependencies_file = get_dependencies_file(platform)
    except ValueError as e:
        print(e)
        return False
    try:
        dependencies = get_dependencies(dependencies_file)
    except FileNotFoundError as e:
        print(e)
        return False
    
    missing = []
    for lib in dependencies:
        # Check if the module is installed
        spec = importlib.util.find_spec(lib.replace('-', '_')) # Packages often use underscores in code
        if spec is None:
            missing.append(lib)

    if missing:
        print(f"\nMissing the following {len(missing)} libraries: {' '.join(missing)}")
        print(f"Run: sudo python -m pip install {' '.join(missing)}")
        return False
    else:
        print("\nAll dependencies satisfied! ✨")
        return True
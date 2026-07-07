import subprocess
def enable_rst():
    enable_recv = (
        "sudo iptables -D OUTPUT "
        "-p tcp --tcp-flags RST RST "
        "-d 127.16.164.0/23 -j DROP"
    )
    subprocess.run(enable_recv, shell=True, check=True)

    enable_send = (
        "sudo iptables -D OUTPUT "
        "-s 127.16.164.0/23 "
        "-p tcp --tcp-flags RST RST -j DROP"
    )
    subprocess.run(enable_send, shell=True, check=True)

def on_connect():
    enable_rst()

if __name__ == "__main__":
    pass
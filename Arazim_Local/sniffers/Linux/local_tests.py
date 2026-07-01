"""
Local sanity tests for the Linux TUN tunnel - run these on ONE machine before
doing the real two-computer end-to-end test.

    sudo python3 local_tests.py           # run everything
    python3 local_tests.py 1              # run only test 1 (no root needed)
    sudo python3 local_tests.py 2 3       # run tests 2 and 3

Tests
  1. codec round-trip  (no root) - encapsulate a packet then decapsulate it and
     prove we get the original bytes back, checksums intact.
  2. ping over TUN     (root)    - bring up a private TUN, ping a peer address
     routed through it, and prove the out-sniffer pulls that ICMP packet off the
     TUN and wraps it correctly.
  3. clean shutdown    (root)    - start both sniffer threads on a TUN, signal
     them to stop, and prove they both exit promptly (the same mechanism the
     SIGINT/SIGTERM handlers drive).
"""

import os
import sys
import time
import queue
import select
import logging
import threading
import subprocess

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))

from scapy.all import Raw
from scapy.layers.inet import IP, ICMP
from scapy.layers.l2 import Ether

import in_sniffer
import out_sniffer
from in_sniffer import In_Sniffer
from out_sniffer import Out_Sniffer
from in_and_out_sniffers import (
    create_tun_interface,
    configure_interface,
)
from sniffers.constants import PAYLOAD_MAGIC

# quiet the sniffer loggers so test output stays readable
logging.basicConfig(level=logging.WARNING, format="    %(name)s: %(message)s")

GATEWAY = "10.9.9.254"
MY_IP = "10.9.9.1"
PEER_IP = "10.9.9.2"
TUN_CIDR = f"{MY_IP}/24"
ROUTER_MAC = "00:11:22:33:44:55"
MY_MAC = "66:77:88:99:aa:bb"


class TestFailure(AssertionError):
    pass


def check(cond, msg):
    if not cond:
        raise TestFailure(msg)


# --------------------------------------------------------------------------- #
# Test 1: encapsulate -> (serialize on the wire) -> decapsulate round trip
# --------------------------------------------------------------------------- #
def test_codec_roundtrip():
    inner = IP(src=MY_IP, dst=PEER_IP) / ICMP(type=8) / b"hello-arazim"
    inner_bytes = bytes(inner)  # forces checksum computation

    # capture whatever the out-sniffer would put on the wire
    sent = {}
    original_sendp = out_sniffer.sendp
    out_sniffer.sendp = lambda pkt, **kw: sent.setdefault("pkt", pkt)
    try:
        out = Out_Sniffer(MY_IP, "255.255.255.0", MY_IP, "lo", GATEWAY,
                          ROUTER_MAC, MY_MAC, tun_fd=-1)
        out.encapsulate_and_send(IP(inner_bytes))
    finally:
        out_sniffer.sendp = original_sendp

    wrapper = sent.get("pkt")
    check(wrapper is not None, "out-sniffer never called sendp()")
    check(Ether in wrapper and wrapper[Ether].dst == ROUTER_MAC,
          "wrapper is missing the Ethernet header addressed to the router MAC")
    check(ICMP in wrapper and wrapper[ICMP].type == 8, "wrapper is not an ICMP echo request")
    check(wrapper[IP].dst == GATEWAY, f"wrapper dst should be the gateway, got {wrapper[IP].dst}")
    check(wrapper[IP].src == PEER_IP, f"wrapper src should be the peer, got {wrapper[IP].src}")
    check(bytes(wrapper[Raw].load).startswith(PAYLOAD_MAGIC), "payload is missing the magic marker")

    # now the receiving side: re-parse from bytes (as if sniffed off the wire),
    # decapsulate, and write into a pipe standing in for the TUN fd
    read_fd, write_fd = os.pipe()
    try:
        insn = In_Sniffer(PEER_IP, GATEWAY, "lo", tun_fd=write_fd)
        # re-parse from raw bytes as the sniffer sees it on the wire (with the
        # Ethernet header), then decapsulate into the pipe standing in for TUN
        insn.decapsulate_and_inject(Ether(bytes(wrapper)))
        # guard the read so a decap failure fails loudly instead of blocking
        readable, _, _ = select.select([read_fd], [], [], 2.0)
        check(read_fd in readable, "decapsulate_and_inject wrote nothing to the TUN")
        recovered = os.read(read_fd, 65535)
    finally:
        os.close(read_fd)
        os.close(write_fd)

    check(recovered == inner_bytes,
          "recovered packet differs from the original (checksum/decap bug)")
    print(f"  recovered {len(recovered)} bytes identical to original; checksums preserved")


# --------------------------------------------------------------------------- #
# helpers for the root tests
# --------------------------------------------------------------------------- #
def _make_test_tun():
    tun_fd, name = create_tun_interface(b"arazimtest0")
    configure_interface(name, TUN_CIDR)
    return tun_fd, name


# --------------------------------------------------------------------------- #
# Test 2: a ping to a peer address is routed into the TUN and wrapped
# --------------------------------------------------------------------------- #
def test_ping_over_tun():
    tun_fd, name = _make_test_tun()
    # host route so PEER_IP is guaranteed to go via our TUN
    subprocess.run(["ip", "route", "replace", f"{PEER_IP}/32", "dev", name], check=True)

    captured = queue.Queue()
    original_sendp = out_sniffer.sendp
    out_sniffer.sendp = lambda pkt, **kw: captured.put(pkt)

    stop_event = threading.Event()
    out = Out_Sniffer(MY_IP, "255.255.255.0", MY_IP, name, GATEWAY,
                      ROUTER_MAC, MY_MAC, tun_fd)
    worker = threading.Thread(target=out.start_sniff, args=(stop_event,), name="out-test")
    worker.start()
    try:
        time.sleep(0.3)  # let the reader settle
        subprocess.run(["ping", "-c", "1", "-W", "1", PEER_IP],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        wrapper = _drain_for_peer(captured, deadline=time.time() + 3.0)
        check(wrapper is not None, "no wrapped packet for the peer showed up on the TUN")
        check(wrapper[ICMP].type == 8, "wrapped packet is not an ICMP echo request")
        check(wrapper[IP].dst == GATEWAY, "wrapper is not aimed at the gateway")

        inner = IP(bytes(wrapper[Raw].load)[len(PAYLOAD_MAGIC):])
        check(inner[IP].dst == PEER_IP, f"embedded packet dst should be peer, got {inner[IP].dst}")
        check(ICMP in inner and inner[ICMP].type == 8, "embedded packet is not the ping request")
        print(f"  ping to {PEER_IP} was read off the TUN and wrapped for the gateway")
    finally:
        stop_event.set()
        worker.join(timeout=3)
        out_sniffer.sendp = original_sendp
        subprocess.run(["ip", "route", "del", f"{PEER_IP}/32", "dev", name], check=False)
        os.close(tun_fd)


def _drain_for_peer(q, deadline):
    """Return the first captured wrapper whose embedded packet targets PEER_IP."""
    while time.time() < deadline:
        try:
            pkt = q.get(timeout=0.2)
        except queue.Empty:
            continue
        try:
            if IP not in pkt or Raw not in pkt:
                continue
            load = bytes(pkt[Raw].load)
            if not load.startswith(PAYLOAD_MAGIC):
                continue
            inner = IP(load[len(PAYLOAD_MAGIC):])
            if inner.version == 4 and inner[IP].dst == PEER_IP:
                return pkt
        except Exception:
            continue
    return None


# --------------------------------------------------------------------------- #
# Test 3: both sniffer threads stop promptly when told to (signal mechanism)
# --------------------------------------------------------------------------- #
def test_clean_shutdown():
    tun_fd, name = _make_test_tun()
    stop_event = threading.Event()

    insn = In_Sniffer(MY_IP, GATEWAY, name, tun_fd)
    out = Out_Sniffer(MY_IP, "255.255.255.0", MY_IP, name, GATEWAY,
                      ROUTER_MAC, MY_MAC, tun_fd)
    threads = [
        threading.Thread(target=insn.start_sniff, args=(stop_event,), name="in-test"),
        threading.Thread(target=out.start_sniff, args=(stop_event,), name="out-test"),
    ]
    try:
        for t in threads:
            t.start()
        time.sleep(0.5)
        check(all(t.is_alive() for t in threads), "a sniffer thread died before shutdown")

        # this is exactly what the SIGINT/SIGTERM handler does
        t0 = time.time()
        stop_event.set()
        for t in threads:
            t.join(timeout=4)
        elapsed = time.time() - t0

        check(not any(t.is_alive() for t in threads),
              "a sniffer thread did not stop within 4s of the stop event")
        print(f"  both threads stopped {elapsed:.2f}s after the stop signal")
    finally:
        stop_event.set()
        for t in threads:
            t.join(timeout=4)
        os.close(tun_fd)


# --------------------------------------------------------------------------- #
ALL_TESTS = {
    1: ("codec round-trip (no root)", test_codec_roundtrip, False),
    2: ("ping over TUN (root)", test_ping_over_tun, True),
    3: ("clean shutdown (root)", test_clean_shutdown, True),
}


def main():
    wanted = [int(a) for a in sys.argv[1:]] or list(ALL_TESTS)
    is_root = os.geteuid() == 0
    passed = failed = skipped = 0

    for num in wanted:
        name, fn, needs_root = ALL_TESTS.get(num, (None, None, None))
        if fn is None:
            print(f"[?] no such test: {num}")
            continue
        print(f"\n[test {num}] {name}")
        if needs_root and not is_root:
            print("  SKIPPED - needs root (re-run with sudo)")
            skipped += 1
            continue
        try:
            fn()
            print(f"  PASS")
            passed += 1
        except TestFailure as e:
            print(f"  FAIL: {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR: {type(e).__name__}: {e}")
            failed += 1

    print(f"\n==> {passed} passed, {failed} failed, {skipped} skipped")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

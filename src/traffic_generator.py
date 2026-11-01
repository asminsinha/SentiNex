"""
SentiNex SDN Traffic Generator & Attack Simulation Tool
Generates Benign HTTP Traffic, DoS SYN Flood Attacks, and Reconnaissance Port Scans.
Supports execution both from Mininet CLI and from an external Linux terminal (with auto-namespace routing).
"""

import sys
import os
import time
import random
import argparse
import subprocess

# Scapy packet manipulation
from scapy.all import IP, TCP, UDP, ICMP, send, conf

conf.verb = 0  # Silence Scapy default verbosity

DEFAULT_TARGET_IP = "10.0.0.2"  # Host h2 in Mininet topology

HOST_MAP = {
    'dos': 'h3',     # Attacker 1 (DoS): 10.0.0.3
    'scan': 'h4',    # Attacker 2 (Port Scan): 10.0.0.4
    'benign': 'h1'   # Normal User: 10.0.0.1
}


def find_mininet_host_pid(hostname):
    """Searches for active Mininet host namespace process in /proc."""
    try:
        cmd = f"pgrep -f 'mininet:{hostname}'"
        out = subprocess.check_output(cmd, shell=True).decode().strip()
        pids = out.split()
        if pids:
            return int(pids[0])
    except Exception:
        pass
    return None


def is_inside_host_namespace(expected_host):
    """Checks if current process is already inside a Mininet host namespace."""
    try:
        out = subprocess.check_output("ip addr", shell=True).decode()
        if f"{expected_host}-eth0" in out or "10.0.0." in out:
            return True
    except Exception:
        pass
    return False


def maybe_rerun_in_namespace(mode, explicit_host=None):
    """If running in default Linux namespace, auto-routes execution into Mininet host namespace."""
    target_host = explicit_host or HOST_MAP.get(mode, 'h3')

    # If already running inside a Mininet host, proceed directly
    if is_inside_host_namespace(target_host):
        return

    pid = find_mininet_host_pid(target_host)
    if pid:
        print(f"[*] Detected active Mininet network! Automatically routing via host [{target_host}] (PID {pid})...")
        args = ["nsenter", "-t", str(pid), "-n", sys.executable] + sys.argv
        try:
            res = subprocess.call(args)
            sys.exit(res)
        except PermissionError:
            print(f"[!] Root privileges required to enter host namespace. Please run with sudo:")
            print(f"    sudo python3 {' '.join(sys.argv)}")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Note: Could not auto-enter namespace ({e}). Running in current namespace.")


def generate_benign_traffic(target_ip=DEFAULT_TARGET_IP, duration_sec=10):
    """Simulates normal HTTP/TCP network interactions."""
    print(f"[*] Generating Benign Web Traffic towards {target_ip} for {duration_sec}s...")
    end_time = time.time() + duration_sec
    count = 0
    while time.time() < end_time:
        src_port = random.randint(1024, 65535)
        # Normal HTTP TCP Packet (Push-Ack)
        pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=80, flags="PA")/b"GET /index.html HTTP/1.1\r\nHost: 10.0.0.2\r\n\r\n"
        send(pkt, verbose=False)
        count += 1
        time.sleep(random.uniform(0.1, 0.3))
    print(f"[+] Benign Traffic Completed: {count} packets transmitted successfully.")


def generate_dos_syn_flood(target_ip=DEFAULT_TARGET_IP, count=100, delay=0.005):
    """Simulates DoS SYN Flood Attack with rapid burst transmission."""
    print(f"\n[!] ===========================================================")
    print(f"[!] Launching DoS SYN Flood Attack ({count} packets) -> {target_ip}")
    print(f"[!] High-frequency SYN burst designed to exhaust SDN state buffers")
    print(f"[!] ===========================================================\n")

    sent = 0
    start_time = time.time()
    for i in range(1, count + 1):
        src_port = random.randint(1024, 65535)
        pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=80, flags="S", seq=random.randint(1000, 90000))
        send(pkt, verbose=False)
        sent += 1
        if i % 25 == 0 or i == count:
            print(f"  -> Sent {i}/{count} SYN flood packets...")
        time.sleep(delay)

    total_time = max(0.001, time.time() - start_time)
    print(f"\n[+] DoS Attack Completed: {sent} packets sent in {total_time:.2f}s ({sent/total_time:.1f} pkts/s).")
    print(f"[*] Check the Ryu Controller terminal for real-time XAI alert and mitigation logs!\n")


def generate_port_scan(target_ip=DEFAULT_TARGET_IP):
    """Simulates Reconnaissance Port Scan Attack across critical network ports."""
    print(f"\n[!] ===========================================================")
    print(f"[!] Launching Port Scan Attack against {target_ip}...")
    print(f"[!] Probing target service endpoints...")
    print(f"[!] ===========================================================\n")

    target_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]
    for p in target_ports:
        src_port = random.randint(1024, 65535)
        pkt = IP(dst=target_ip)/TCP(sport=src_port, dport=p, flags="S")
        send(pkt, verbose=False)
        print(f"  -> Probed Port: {p}")
        time.sleep(0.05)

    print(f"\n[+] Port Scan Completed: Probed {len(target_ports)} service ports.")
    print(f"[*] Check the Ryu Controller terminal for real-time XAI alert and mitigation logs!\n")


def main():
    parser = argparse.ArgumentParser(description="SentiNex SDN Traffic Generator")
    parser.add_argument("mode", choices=["benign", "dos", "scan"], help="Traffic mode to generate")
    parser.add_argument("--target", default=DEFAULT_TARGET_IP, help=f"Target IP address (default: {DEFAULT_TARGET_IP})")
    parser.add_argument("--count", type=int, default=100, help="Number of packets for DoS attack (default: 100)")
    parser.add_argument("--duration", type=int, default=10, help="Duration for benign traffic in seconds (default: 10)")
    parser.add_argument("--host", default=None, help="Force specific Mininet host (e.g. h1, h3, h5)")

    args = parser.parse_args()

    # Automatically enter host namespace if running in WSL root namespace
    maybe_rerun_in_namespace(args.mode, args.host)

    if args.mode == "benign":
        generate_benign_traffic(target_ip=args.target, duration_sec=args.duration)
    elif args.mode == "dos":
        generate_dos_syn_flood(target_ip=args.target, count=args.count)
    elif args.mode == "scan":
        generate_port_scan(target_ip=args.target)


if __name__ == "__main__":
    main()
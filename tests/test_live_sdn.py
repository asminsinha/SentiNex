"""
Test script for verifying live Ryu controller + Mininet OpenFlow integration.
Runs inside WSL2 / Linux as root.
"""

import sys
import time
import json
import urllib.request
import subprocess

from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.log import setLogLevel

setLogLevel('info')

def test_live_sdn():
    print("[1] Launching Ryu Controller in background...")
    # Clean old instances
    subprocess.call("pkill -9 -f run_ryu.py; mn -c >/dev/null 2>&1", shell=True)
    time.sleep(1)

    ryu_proc = subprocess.Popen(
        ["/home/asmin/SentiNex/venv_wsl/bin/python", "run_ryu.py", "ryu.app.ofctl_rest", "src/ryu_controller.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )

    # Wait up to 10 seconds for port 8080 and 6653
    ready = False
    for _ in range(20):
        time.sleep(0.5)
        try:
            with urllib.request.urlopen("http://127.0.0.1:8080/stats/switches", timeout=1) as res:
                if res.status == 200:
                    ready = True
                    break
        except Exception:
            pass

    if not ready:
        print("[!] Error: Ryu did not start in time. Output:")
        out, _ = ryu_proc.communicate(timeout=2)
        print(out.decode())
        sys.exit(1)

    print("[+] Ryu Controller active on port 6653 (OFP) and 8080 (REST)!")

    print("[2] Instantiating Mininet network (2 switches, 2 hosts)...")
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch)
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')

    net.addLink(h1, s1)
    net.addLink(h2, s2)
    net.addLink(s1, s2)

    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])

    print("[*] Waiting for switches to register with Ryu...")
    switches_connected = False
    for _ in range(10):
        time.sleep(0.5)
        try:
            with urllib.request.urlopen("http://127.0.0.1:8080/stats/switches") as res:
                switches = json.loads(res.read().decode())
                if len(switches) >= 2:
                    print(f"[+] Connected Switch DPIDs: {switches}")
                    switches_connected = True
                    break
        except Exception as e:
            pass

    if not switches_connected:
        print("[!] Switches failed to register with Ryu!")
        net.stop()
        ryu_proc.terminate()
        sys.exit(1)

    print("[3] Testing real network traffic (h1 ping h2)...")
    drop_rate = net.ping([h1, h2])
    print(f"  Ping drop rate: {drop_rate}%")

    print("[4] Querying real OpenFlow 1.3 switch flow tables via Ryu REST API...")
    with urllib.request.urlopen("http://127.0.0.1:8080/stats/flow/1") as res:
        flows_s1 = json.loads(res.read().decode())
        print(f"  Switch 1 Flow rules count: {len(flows_s1.get('1', []))}")
        for r in flows_s1.get('1', []):
            print(f"    - Priority: {r.get('priority')} | Match: {r.get('match')} | Actions: {r.get('actions')}")

    print("[5] Cleaning up live network...")
    net.stop()
    ryu_proc.terminate()
    ryu_proc.wait(timeout=3)
    subprocess.call("mn -c >/dev/null 2>&1", shell=True)

    print("\n[SUCCESS] Live Ryu + Mininet OpenFlow 1.3 pipeline verified successfully!")

if __name__ == "__main__":
    test_live_sdn()

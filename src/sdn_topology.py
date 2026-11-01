"""
SentiNex SDN Topology Script (Mininet)
Supports baseline 4-host topology and dynamic configurable topologies
(linear, tree, star, mesh) with configurable host counts.
Runs inside Linux environment (WSL2 / Ubuntu / Mininet VM).
"""

import sys
import argparse

try:
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSKernelSwitch
    from mininet.cli import CLI
    from mininet.log import setLogLevel, info
    HAS_MININET = True
except ImportError:
    HAS_MININET = False
    print("[!] Warning: Mininet libraries not found in this environment. Script requires Linux/WSL2.")


def create_sentinex_topo():
    """Baseline 4-host, 2-switch SentiNex topology for backward compatibility."""
    if not HAS_MININET:
        print("[!] Cannot launch Mininet: dependencies unavailable.")
        return

    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch)

    info('*** Adding Controller ***\n')
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    info('*** Adding Switches ***\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')

    info('*** Adding Hosts ***\n')
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01') # Normal Traffic Generator
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02') # Target Server / Victim
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03') # Attacker (DoS / SYN Flood)
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04') # Attacker (Port Scanner)

    info('*** Creating Links ***\n')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s2)
    net.addLink(h4, s2)
    net.addLink(s1, s2) # Inter-switch trunk link

    info('*** Starting Network ***\n')
    net.build()
    c0.start()
    s1.start([c0])
    s2.start([c0])

    info('*** Running Mininet CLI ***\n')
    CLI(net)

    info('*** Stopping Network ***\n')
    net.stop()


def create_dynamic_topo(topo_type="linear", host_count=4, c_ip='127.0.0.1', c_port=6653):
    """
    Creates dynamic Mininet topologies (linear, tree, star, mesh) with configurable host count.
    Safe maximum for full OS Mininet instantiation is 64 hosts.
    """
    if not HAS_MININET:
        print("[!] Cannot launch Mininet: dependencies unavailable.")
        return

    if host_count > 64:
        print(f"[!] Warning: Configured host count ({host_count}) exceeds safe Linux OS network interface limit (max 64).")
        print("[*] Clamping to 64 real Mininet hosts to prevent OS kernel exhaustion.")
        host_count = 64

    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch)

    info(f'*** Adding Remote Controller ({c_ip}:{c_port}) ***\n')
    c0 = net.addController('c0', controller=RemoteController, ip=c_ip, port=c_port)

    # Calculate switches
    if topo_type == "star":
        num_sw = 1
    elif topo_type == "tree":
        num_sw = max(2, min(8, 1 + (host_count + 3) // 4))
    elif topo_type == "mesh":
        num_sw = max(4, min(8, 2 + (host_count + 5) // 6))
    else:  # linear
        num_sw = max(2, min(10, (host_count + 3) // 4))

    info(f'*** Creating {num_sw} OpenFlow 1.3 Switches ({topo_type}) ***\n')
    switches = []
    for i in range(1, num_sw + 1):
        sw = net.addSwitch(f's{i}', protocols='OpenFlow13')
        switches.append(sw)

    # Inter-switch links
    if topo_type == "tree":
        root = switches[0]
        for sw in switches[1:]:
            net.addLink(root, sw)
    elif topo_type == "mesh":
        for i in range(len(switches)):
            for j in range(i + 1, min(i + 3, len(switches))):
                net.addLink(switches[i], switches[j])
    elif topo_type == "linear":
        for i in range(len(switches) - 1):
            net.addLink(switches[i], switches[i+1])

    info(f'*** Creating {host_count} Mininet Hosts ***\n')
    hosts = []
    for i in range(1, host_count + 1):
        ip = f"10.0.{i // 254}.{(i % 254) + 1}/24"
        mac = f"00:00:00:{i >> 16 & 0xff:02x}:{i >> 8 & 0xff:02x}:{i & 0xff:02x}"
        h = net.addHost(f'h{i}', ip=ip, mac=mac)
        hosts.append(h)

        assigned_sw = switches[(i - 1) % len(switches)]
        net.addLink(h, assigned_sw)

    info('*** Building Network ***\n')
    net.build()
    c0.start()
    for sw in switches:
        sw.start([c0])

    info(f'*** Mininet Ready: {len(switches)} switches, {len(hosts)} hosts connected to SentiNex Controller ***\n')
    CLI(net)

    info('*** Stopping Network ***\n')
    net.stop()


def main():
    parser = argparse.ArgumentParser(description="SentiNex SDN Mininet Topology Launcher")
    parser.add_argument("--topo", choices=["linear", "tree", "star", "mesh"], default="linear", help="Topology layout")
    parser.add_argument("--hosts", type=int, default=4, help="Total host count (max 64 for real Mininet)")
    parser.add_argument("--controller", default="127.0.0.1", help="Controller IP")
    parser.add_argument("--port", type=int, default=6653, help="Controller OpenFlow port")
    parser.add_argument("--legacy", action="store_true", help="Launch original 4-host baseline topology")

    args = parser.parse_args()
    setLogLevel('info')

    if args.legacy:
        create_sentinex_topo()
    else:
        create_dynamic_topo(topo_type=args.topo, host_count=args.hosts, c_ip=args.controller, c_port=args.port)


if __name__ == '__main__':
    main()
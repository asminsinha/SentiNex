"""
SentiNex Mininet REST Daemon.
Runs inside WSL2 / Linux as root.
Provides real network namespace management, topology reconfiguration, and Scapy injection.
"""

import sys
import os
import json
import time
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
src_dir = os.path.join(BASE_DIR, "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

try:
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSKernelSwitch
    from mininet.log import setLogLevel
    HAS_MININET = True
except ImportError:
    HAS_MININET = False

class MininetManager:
    def __init__(self):
        self.net = None
        self.topo_type = "linear"
        self.host_count = 0
        self.switches = []
        self.hosts = []
        self.running = False

    def clean(self):
        try:
            if self.net:
                self.net.stop()
        except Exception:
            pass
        self.net = None
        self.running = False
        self.switches = []
        self.hosts = []
        self.host_count = 0
        subprocess.call("mn -c >/dev/null 2>&1", shell=True)

    def start_topo(self, topo_type="linear", host_count=4, controller_ip="127.0.0.1", controller_port=6653):
        self.clean()
        if not HAS_MININET:
            raise RuntimeError("Mininet not available in this Python environment")

        host_count = max(2, min(int(host_count), 64))
        self.topo_type = topo_type
        self.host_count = host_count

        net = Mininet(controller=RemoteController, switch=OVSKernelSwitch)
        c0 = net.addController('c0', controller=RemoteController, ip=controller_ip, port=controller_port)

        if topo_type == "star":
            num_sw = 1
        elif topo_type == "tree":
            num_sw = max(2, min(8, 1 + (host_count + 3) // 4))
        elif topo_type == "mesh":
            num_sw = max(4, min(8, 2 + (host_count + 5) // 6))
        else:  # linear
            num_sw = max(2, min(10, (host_count + 3) // 4))

        switches = []
        for i in range(1, num_sw + 1):
            sw = net.addSwitch(f's{i}', protocols='OpenFlow13')
            switches.append(sw)

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

        hosts = []
        for i in range(1, host_count + 1):
            ip = f"10.0.{i // 254}.{(i % 254) + 1}/24"
            mac = f"00:00:00:{i >> 16 & 0xff:02x}:{i >> 8 & 0xff:02x}:{i & 0xff:02x}"
            h = net.addHost(f'h{i}', ip=ip, mac=mac)
            hosts.append(h)
            assigned_sw = switches[(i - 1) % len(switches)]
            net.addLink(h, assigned_sw)

        net.build()
        c0.start()
        for sw in switches:
            sw.start([c0])

        self.net = net
        self.switches = [sw.name for sw in switches]
        self.hosts = [h.name for h in hosts]
        self.running = True

        return {
            'status': 'started',
            'topo_type': self.topo_type,
            'host_count': len(self.hosts),
            'switch_count': len(self.switches),
            'switches': self.switches,
            'hosts': self.hosts
        }

    def get_status(self):
        if not self.running or not self.net:
            return {
                'running': False,
                'host_count': 0,
                'switch_count': 0,
                'switches': [],
                'hosts': []
            }
        return {
            'running': True,
            'topo_type': self.topo_type,
            'host_count': len(self.hosts),
            'switch_count': len(self.switches),
            'switches': self.switches,
            'hosts': self.hosts
        }

    def inject_traffic(self, traffic_type, src_host, target_host="h2", count=10):
        if not self.running or not self.net:
            raise RuntimeError("Mininet is not currently active")

        src = self.net.get(src_host)
        dst = self.net.get(target_host)
        if not src or not dst:
            raise ValueError(f"Host {src_host} or {target_host} not found in Mininet")

        dst_ip = dst.IP()
        script_path = os.path.join(BASE_DIR, "src", "traffic_generator.py")
        cmd = f"python3 {script_path} --mode {traffic_type} --target {dst_ip} --count {count} --host {src_host}"
        res = src.cmd(cmd)
        return {'success': True, 'output': res}


manager = MininetManager()

class MininetHandler(BaseHTTPRequestHandler):
    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        if self.path == '/status':
            self._send_json(manager.get_status())
        else:
            self._send_json({'error': 'Not found'}, 404)

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode() if length > 0 else '{}'
        try:
            params = json.loads(body)
        except Exception:
            params = {}

        if self.path == '/start':
            try:
                topo = params.get('topo_type', 'linear')
                hosts = params.get('host_count', 4)
                res = manager.start_topo(topo_type=topo, host_count=hosts)
                self._send_json(res)
            except Exception as e:
                self._send_json({'error': str(e)}, 500)

        elif self.path == '/stop':
            manager.clean()
            self._send_json({'status': 'stopped'})

        elif self.path == '/inject':
            try:
                t_type = params.get('traffic_type', 'benign')
                s_host = params.get('src_host', 'h1')
                d_host = params.get('target_host', 'h2')
                count = int(params.get('count', 10))
                res = manager.inject_traffic(t_type, s_host, d_host, count)
                self._send_json(res)
            except Exception as e:
                self._send_json({'error': str(e)}, 500)

        else:
            self._send_json({'error': 'Not found'}, 404)

def run_server(port=8081):
    server = HTTPServer(('0.0.0.0', port), MininetHandler)
    print(f"[+] SentiNex Mininet Daemon listening on port {port}...")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        manager.clean()
        server.server_close()

if __name__ == '__main__':
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    run_server(port)


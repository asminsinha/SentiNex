# SentiNex: Explainable AI for Intrusion Detection in Software-Defined Networks
## Complete Operator & Execution Guide (Windows / WSL2)

SentiNex is an Explainable AI (XAI) Intrusion Detection and Dynamic Mitigation platform for Software-Defined Networks (SDN). This guide provides copy-paste-ready instructions for executing the web application, running tests, launching the Ryu SDN controller, building dynamic Mininet topologies, and injecting traffic.

---

### 1. Architectural Architecture & Execution Modes

SentiNex supports two distinct, transparently distinguished operational modes:

| Mode | Environment | Host Support | Characteristics |
| :--- | :--- | :--- | :--- |
| **Scalable Logical SDN Emulation** | Native Windows or Linux / WSL2 | **2 to 1,000+ Hosts** | High-performance full OpenFlow 1.3 flow-table simulation, direct integration with the ML & SHAP/LIME pipeline. Does not exhaust Linux network namespaces or kernel interfaces. |
| **Real Mininet Mode** | Ubuntu / WSL2 / Linux VM | **2 to 64 Hosts** | Full network namespace isolation per host with Open vSwitch (OVS) kernel datapath, connected to Ryu SDN Controller via OpenFlow 1.3 (TCP 6653). |

> **Scalability Disclosure:** Linux OS network namespaces and Open vSwitch interface allocations become resource-constrained above 64 hosts on typical developer workstations. SentiNex enforces a maximum of 64 fully instantiated Mininet hosts while seamlessly supporting up to 1,000+ hosts in Scalable Logical Emulation mode without browser freezing or memory exhaustion.

---

### 2. Supported Threat Taxonomy & Feature Attribution

SentiNex evaluates network traffic across **42 flow features** (UNSW-NB15 / CICIDS2018 standards) and classifies events into three natively distinguished threat classes plus benign traffic:

1. **Denial of Service (DoS / DDoS SYN Flood)**
   - *Characteristics:* High transmission rate (`rate > 40 pkts/s`), high packet volume (`spkts >= 10`), concentrated SYN flags.
   - *SDN Action:* Dynamic Priority 100 OpenFlow `DROP` flow rule installed across all switches for `ipv4_src`.
2. **Reconnaissance (Port Scan / Probe)**
   - *Characteristics:* Repeated access to distinct destination ports (`port_count >= 3`), elevated `ct_dst_sport_ltm` and `ct_src_dport_ltm`.
   - *SDN Action:* Dynamic Priority 100 OpenFlow `DROP` flow rule installed on switches.
3. **Protocol Spoofing / State Disruption**
   - *Characteristics:* Mismatched state-to-TTL correlation (`ct_state_ttl`, abnormal `sttl`/`dttl`).
   - *SDN Action:* Dynamic Priority 100 OpenFlow `DROP` rule.
4. **Benign Normal Traffic**
   - *Characteristics:* Standard HTTP/TCP transactions with normal rates, window sizes, and TTL.
   - *SDN Action:* Standard L2 OpenFlow forwarding.

---

### 3. Quick Start (Windows — Web Application & Scalable Lab)


#### Step 3.1: Launch SentiNex Web Application
```powershell

.\start_sentinex.ps1
```
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

### 4. Running the Integration Test Suite

To verify model inference, feature extraction, SHAP/LIME calculation, dynamic topologies, and REST/SSE APIs:
```powershell
.\venv\Scripts\python.exe tests/test_sentinex_integration.py
```
Expected output:
```
Ran 10 tests in 26.3s
OK
```

---

### 5. Running with Real Ryu SDN Controller & Mininet (WSL2 / Linux)

When running inside WSL2 (Ubuntu) with Open vSwitch and Ryu:

#### Step 5.1: Start Open vSwitch in WSL2
```bash
sudo service openvswitch-switch start
sudo ovs-vsctl show
```

#### Step 5.2: Launch the SentiNex Ryu Controller
```bash
cd /mnt/c/Users/asmin/SentiNex
python3 run_ryu.py src/ryu_controller.py
```
*The controller will listen on TCP port `6653` for OpenFlow switches and TCP port `8080` for the REST API.*

#### Step 5.3: Start Dynamic Mininet Topology
In a second terminal:
```bash
sudo python3 src/sdn_topology.py --topo linear --hosts 4
```
Supported topology choices:
- `--topo linear --hosts 4` (Linear trunk switches)
- `--topo tree --hosts 8` (Hierarchical root/edge switches)
- `--topo star --hosts 6` (Central switch)
- `--topo mesh --hosts 8` (Redundant mesh)

#### Step 5.4: Generate Traffic from Mininet CLI
Inside the `mininet>` prompt:
```bash
# Generate Benign Web traffic from h1 to h2
mininet> h1 python3 src/traffic_generator.py benign --target 10.0.0.2

# Generate DoS SYN flood attack from h3 to h2
mininet> h3 python3 src/traffic_generator.py dos --target 10.0.0.2 --count 50

# Generate Reconnaissance Port Scan from h4 to h2
mininet> h4 python3 src/traffic_generator.py scan --target 10.0.0.2
```

---

### 6. Using the Multi-Page Operations Application

#### Page 1: Live Operations (`#operations`)
- **Health Indicators:** Displays real connection state of Ryu SDN controller, active model (RF/MLP), execution mode, and SSE delivery latency.
- **Interactive Topology:** Live SVG map of switches and hosts with zoom/pan controls. Clicking any node opens the **Node Inspector** showing IP, MAC, switch port, and quarantine status.
- **Security Event Stream:** Sub-second live event cards showing incoming traffic observations, model predictions, confidence percentages, and a one-click **"Inspect XAI"** button.

#### Page 2: Traffic Lab & Simulation (`#traffic-lab`)
- **Topology Builder:** Configure topology type (Linear, Tree, Star, Mesh), host count (from 4 up to 1,000+), threat-host ratio, and experiment seed.
- **Manual Injection Console:** Select source host, target server, packet burst count, and traffic type (Benign, DoS, Port Scan, Spoofing). View ground-truth vs model prediction results.
- **Automated Simulation Mode:** Toggle continuous background traffic with adjustable pace (0.5s to 5.0s per event). Supports Start, Pause, Stop, and Reset.

#### Page 3: Incidents & Flow Inspector (`#incidents`)
- **Incident Audit Log:** Searchable and filterable table of all detected security threats.
- **Pipeline Stage Tracer:** Real measured timing breakdown:
  $$\text{Total Time} = \text{Extraction ms} + \text{Inference ms} + \text{XAI ms} + \text{Mitigation ms}$$
- **Plain-English Layman Explanation:** Clear operator translation explaining which parameters pushed the model towards the threat decision.
- **SHAP & LIME Visual Attributions:** Divergent horizontal bar charts showing exact positive (pushing towards attack) and negative (pushing towards benign) contributions.
- **OpenFlow Switch Flow Tables:** Real-time inspection of flow rules for switches `s1`, `s2`, etc., including Table ID, Priority 100 `DROP` rules, match criteria, actions, and timeouts.
- **Quarantine Manager:** One-click **"Release / Unblock Host"** button that safely deletes drop rules from switch flow tables and restores host connectivity.

---

### 7. Troubleshooting & FAQ

- **Port 5000 already in use:**
  ```powershell
  $env:SENTINEX_PORT = "5050"
  python dashboard/app.py
  ```
- **Switching between Random Forest and Deep Learning MLP:**
  ```powershell
  # For Random Forest (ultra-fast inference ~15ms):
  $env:SENTINEX_MODEL = "rf"
  # For Deep Learning Keras Neural Network:
  $env:SENTINEX_MODEL = "mlp"
  ```
- **"Ryu OF 1.3: Emulated" vs "Ryu Connected":**
  When Ryu is running on port 6653 or 8080, the dashboard automatically transitions to green `Ryu Connected`. When running on Windows without a local Ryu instance, SentiNex runs in `OF 1.3 Emulated` mode, providing genuine OpenFlow 1.3 flow-table tracking and mitigation without fake data.

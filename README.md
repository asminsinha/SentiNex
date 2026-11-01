

\# SentiNex

\### Explainable AI for Intrusion Detection and Dynamic Mitigation in Software-Defined Networks



SentiNex is an Explainable Artificial Intelligence (XAI) powered Intrusion Detection System (IDS) designed for Software-Defined Networks (SDNs). It combines machine learning-based traffic classification, explainable threat analysis, OpenFlow-based mitigation, and interactive network monitoring into a unified security operations platform.



The system analyzes network flow characteristics, identifies potentially malicious traffic, explains its predictions using SHAP and LIME, and supports dynamic mitigation through SDN flow rules.



SentiNex provides two execution environments: scalable logical SDN emulation for large experiments and real Mininet-based network emulation for Linux/WSL2 environments.



\---



\## 1. Key Features



\- \*\*Machine Learning-Based Intrusion Detection:\*\* Random Forest and Multi-Layer Perceptron (MLP) models for network traffic classification.

\- \*\*Explainable AI:\*\* SHAP and LIME feature attribution to explain why traffic is classified as malicious or benign.

\- \*\*Dynamic SDN Mitigation:\*\* OpenFlow 1.3-based traffic filtering and host quarantine through dynamically installed flow rules.

\- \*\*Scalable Network Emulation:\*\* Configurable logical topologies supporting 1,000+ hosts.

\- \*\*Real Mininet Integration:\*\* Network namespace-based emulation with Open vSwitch and a Ryu SDN controller.

\- \*\*Interactive Operations Dashboard:\*\* Live network topology, security event monitoring, incident investigation, and flow-table inspection.

\- \*\*Traffic Simulation:\*\* Benign traffic, DoS attacks, port scanning, and protocol spoofing scenarios.

\- \*\*Model Selection:\*\* Switch between Random Forest and MLP inference models.

\- \*\*Operational Monitoring:\*\* Controller connectivity, model status, event streaming, and pipeline timing information.



\---



\## 2. Architecture and Execution Modes



SentiNex supports two operational modes.



| Capability | Scalable Logical SDN Emulation | Real Mininet Mode |

|---|---|---|

| Environment | Windows, Linux, WSL2 | Ubuntu, WSL2, Linux VM |

| Host capacity | 2–1,000+ | 2–64 |

| OpenFlow representation | Logical flow-table simulation | Open vSwitch flow tables |

| Network isolation | Logical emulation | Linux network namespaces |

| Controller integration | Integrated emulation pipeline | Ryu SDN controller |

| Primary purpose | Large-scale experiments | Realistic network emulation |



\### Scalable Logical SDN Emulation



The logical emulation environment supports large network experiments without requiring an individual Linux network namespace and kernel interface for every host.



It integrates with the machine learning inference and explainability pipeline, enabling configurable topologies, traffic injection, event monitoring, and logical OpenFlow flow-table tracking.



\### Real Mininet Mode



Real Mininet mode creates isolated virtual hosts and switches using Linux network namespaces and Open vSwitch.



Switches communicate with the Ryu controller using OpenFlow 1.3 over TCP port `6653`. The controller also exposes a REST interface on port `8080`.



\*\*Scalability consideration:\*\* Real Mininet mode is limited to 64 instantiated hosts in the current configuration. Larger experiments should use scalable logical emulation, which supports 1,000+ hosts without creating an equivalent number of operating-system network namespaces.



\---



\## 3. Intrusion Detection and Threat Classification



SentiNex evaluates network traffic using 42 flow features aligned with the CICIDS2018 and UNSW-NB15 feature conventions.



The classification pipeline distinguishes four traffic categories:



| Traffic Category | Detection Characteristics | Mitigation / Handling |

|---|---|---|

| Denial of Service (DoS/DDoS) | Elevated packet rates, packet volume, and concentrated SYN activity | Priority 100 OpenFlow DROP rules |

| Reconnaissance | Repeated connections to distinct destination ports and scanning-related flow characteristics | Priority 100 OpenFlow DROP rules |

| Protocol Spoofing / State Disruption | Abnormal state-to-TTL relationships and inconsistent protocol characteristics | Priority 100 OpenFlow DROP rules |

| Benign Traffic | Normal network communication patterns | Standard Layer 2 forwarding |



\### Detection Characteristics



\*\*Denial of Service\*\*

\- Elevated packet transmission rates.

\- High packet counts.

\- Concentrated SYN flag activity.



\*\*Reconnaissance\*\*

\- Repeated attempts to access different destination ports.

\- Elevated connection tracking and port activity.



\*\*Protocol Spoofing / State Disruption\*\*

\- Abnormal relationships between connection state and TTL-related features.

\- Inconsistent source and destination TTL characteristics.



\### Dynamic Mitigation



For identified malicious traffic, the SDN mitigation pipeline can install high-priority OpenFlow DROP rules matching the relevant source address.



In real Mininet mode, these rules are applied through the controller to the connected Open vSwitch infrastructure. The logical emulation environment maintains its corresponding logical flow-table state.



Benign traffic continues through standard forwarding behaviour.



\---



\## 4. Technology Stack



| Component | Technologies |

|---|---|

| Programming Language | Python |

| Machine Learning | Scikit-learn, TensorFlow / Keras |

| Explainable AI | SHAP, LIME |

| SDN Controller | Ryu |

| Network Emulation | Mininet, Open vSwitch |

| Network Protocol | OpenFlow 1.3 |

| Backend | Flask, Python REST APIs |

| Frontend | HTML, CSS, JavaScript |

| Real-Time Communication | Server-Sent Events (SSE) |

| Data Processing | NumPy, Pandas |

| Operating Environments | Windows, WSL2, Ubuntu / Linux |



\---



\## 5. Application Interface



SentiNex provides a multi-page security operations interface.



\### Live Operations



\- Connection status of the Ryu SDN controller.

\- Active machine learning model and execution mode.

\- Interactive SVG network topology with zoom and pan controls.

\- Host and switch inspection, including IP, MAC, port, and quarantine information.

\- Live security event stream with model predictions and confidence scores.

\- Direct access to explainability information for detected events.



\### Traffic Lab and Simulation



\- Configurable Linear, Tree, Star, and Mesh topologies.

\- Host count and threat-host ratio configuration.

\- Experiment seed configuration.

\- Manual traffic injection with configurable source, destination, packet count, and traffic type.

\- Ground-truth versus model-prediction comparison.

\- Automated traffic generation with Start, Pause, Stop, and Reset controls.

\- Adjustable simulation pace.



\### Incidents and Flow Inspector



\- Searchable and filterable security incident records.

\- Pipeline execution timing across extraction, inference, explainability, and mitigation.

\- Plain-English explanations of model predictions.

\- SHAP and LIME feature-attribution visualizations.

\- OpenFlow switch flow-table inspection.

\- Visibility into priority, match criteria, actions, and timeouts.

\- Host quarantine management with release/unblock functionality.



\---



\## 6. Quick Start — Windows



The recommended way to launch the web application and scalable emulation environment is through the supplied PowerShell startup script.



\### Prerequisites



\- Windows 10/11

\- Python environment configured for the project

\- Project dependencies installed



\### Launch the application



Open PowerShell in the project directory:



```powershell

.\\start\_sentinex.ps1

```



Once the application starts, open:



```text

http://127.0.0.1:5000

```



\### Running the integration tests



From the project root, execute:



```powershell

.\\venv\\Scripts\\python.exe tests/test\_sentinex\_integration.py

```



The integration suite covers model inference, feature extraction, explainability calculations, topology functionality, and application APIs.



\---



\## 7. Real SDN Execution — WSL2 / Linux



Real Mininet execution requires an Ubuntu/WSL2 or Linux environment with Open vSwitch, Mininet, and Ryu configured.



\### Step 1: Start Open vSwitch



```bash

sudo service openvswitch-switch start

sudo ovs-vsctl show

```



\### Step 2: Launch the Ryu controller



Navigate to the SentiNex project directory inside WSL2:



```bash

cd /mnt/c/Users/<windows-user>/SentiNex

```



Launch the controller:



```bash

python3 run\_ryu.py src/ryu\_controller.py

```



The controller uses:



\- OpenFlow 1.3: TCP port `6653`

\- REST API: TCP port `8080`



\### Step 3: Create a Mininet topology



Open a second WSL2 terminal:



```bash

cd /mnt/c/Users/<windows-user>/SentiNex

sudo python3 src/sdn\_topology.py --topo linear --hosts 4

```



Supported topology configurations:



```bash

\# Linear topology

sudo python3 src/sdn\_topology.py --topo linear --hosts 4



\# Tree topology

sudo python3 src/sdn\_topology.py --topo tree --hosts 8



\# Star topology

sudo python3 src/sdn\_topology.py --topo star --hosts 6



\# Mesh topology

sudo python3 src/sdn\_topology.py --topo mesh --hosts 8

```



\### Step 4: Generate traffic



From the Mininet CLI:



```bash

\# Generate benign web traffic

mininet> h1 python3 src/traffic\_generator.py benign --target 10.0.0.2



\# Generate a DoS SYN flood

mininet> h3 python3 src/traffic\_generator.py dos --target 10.0.0.2 --count 50



\# Generate reconnaissance / port-scan traffic

mininet> h4 python3 src/traffic\_generator.py scan --target 10.0.0.2

```



These scenarios allow the detection and mitigation pipeline to be evaluated against different traffic behaviours.



\---



\## 8. Model Configuration



SentiNex supports switching between the Random Forest and MLP models through the `SENTINEX\_MODEL` environment variable.



\### Random Forest



```powershell

$env:SENTINEX\_MODEL = "rf"

python dashboard/app.py

```



\### Multi-Layer Perceptron



```powershell

$env:SENTINEX\_MODEL = "mlp"

python dashboard/app.py

```



The default model selection can be configured through the application environment.



\---



\## 9. Troubleshooting



\### Port 5000 is already in use



Choose another application port:



```powershell

$env:SENTINEX\_PORT = "5050"

python dashboard/app.py

```



The application will then be available at:



```text

http://127.0.0.1:5050

```



\### Ryu OF 1.3 Emulated vs. Ryu Connected



These statuses distinguish the execution environments:



\- \*\*OF 1.3 Emulated:\*\* The application is operating with its logical OpenFlow 1.3 emulation pipeline without a connected real Ryu controller.

\- \*\*Ryu Connected:\*\* The application has detected the configured Ryu controller connection.



Logical emulation provides a separate execution environment; it should not be confused with a live Mininet network.



\### Mininet host limitations



Real Mininet mode is capped at 64 hosts in the current implementation due to operating-system network namespace and interface resource constraints.



For larger experiments, use scalable logical emulation.



\---



\## 10. Repository Structure



```text

SentiNex/

│

├── dashboard/          # Web application and frontend

├── data/               # Dataset and processed-data directories

├── models/              # Trained ML models and feature artifacts

├── notebooks/           # Experimentation and analysis notebooks

├── src/                 # Detection, SDN, and traffic-generation modules

├── tests/               # Integration and application tests

│

├── run\_ryu.py           # Ryu controller launcher

├── start\_sentinex.ps1   # Windows application startup script

├── RUN\_GUIDE.md         # Detailed operator and execution guide

├── README.md            # Project overview and quick-start documentation

└── .gitignore

```



\---



\## 11. Datasets and Model Artifacts



SentiNex uses traffic feature conventions associated with:



\- CICIDS2018

\- UNSW-NB15



The project includes trained model artifacts for Random Forest, MLP, and additional tree-based classifiers, along with supporting feature and preprocessing artifacts.



Raw and processed datasets are excluded from the standard Git repository through `.gitignore` rules. Users should obtain datasets from their respective sources and follow the project's preprocessing requirements when reproducing experiments.



Large model artifacts may be maintained using Git Large File Storage (Git LFS).



\---



\## 12. Detailed Documentation



For the complete operator instructions, including Windows/WSL2 setup, controller execution, topology creation, traffic injection, application operation, and troubleshooting, refer to:



\*\*\[RUN\_GUIDE.md](RUN\_GUIDE.md)\*\*



\---



\## 13. Project Scope



SentiNex brings together machine learning-based network intrusion detection, explainable predictions, and SDN-based dynamic mitigation in an interactive experimentation and monitoring environment.



Its dual-mode architecture supports both large-scale logical network experiments and isolated Mininet-based network emulation, providing a flexible environment for exploring explainable network security and programmable network defence.



\---




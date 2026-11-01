/**
 * SentiNex SDN Operations Control Center — Main Frontend Application Controller
 * Handles SSE live updates, REST interactions, tab switching, and incident inspection.
 */

class SentiNexApp {
    constructor() {
        this.status = null;
        this.topology = null;
        this.incidents = [];
        this.selectedIncident = null;
        this.activeFlowSwitch = null;

        this.initRouting();
        this.initDOM();
        this.initSSE();
        this.loadInitialData();
    }

    initRouting() {
        // Handle Hash Navigation (#operations, #traffic-lab, #incidents)
        const updateFromHash = () => {
            const hash = window.location.hash.replace('#', '') || 'operations';
            const tabMap = {
                'operations': 'tab-operations',
                'traffic-lab': 'tab-traffic-lab',
                'incidents': 'tab-incidents'
            };
            const targetId = tabMap[hash] || 'tab-operations';
            this.switchTab(targetId, false);
        };

        window.addEventListener('hashchange', updateFromHash);
        // Initial tab check
        setTimeout(updateFromHash, 50);
    }

    switchTab(tabId, updateHash = true) {
        document.querySelectorAll('.nav-tab').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabId);
        });
        document.querySelectorAll('.tab-content').forEach(pane => {
            pane.classList.toggle('active', pane.id === tabId);
        });

        if (updateHash) {
            const hashMap = {
                'tab-operations': 'operations',
                'tab-traffic-lab': 'traffic-lab',
                'tab-incidents': 'incidents'
            };
            window.location.hash = hashMap[tabId] || 'operations';
        }

        if (tabId === 'tab-operations' && window.topologyInstance) {
            setTimeout(() => window.topologyInstance.render(), 100);
        }
    }

    initDOM() {
        // Tab Navigation Clicks
        document.querySelectorAll('.nav-tab').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.switchTab(e.currentTarget.dataset.tab);
            });
        });

        // "Configure Network" button on Operations page
        const btnGoLab = document.getElementById('btn-switch-traffic-lab');
        if (btnGoLab) {
            btnGoLab.addEventListener('click', () => this.switchTab('tab-traffic-lab'));
        }

        // Host count slider update
        const hostSlider = document.getElementById('cfg-host-count');
        const hostLbl = document.getElementById('lbl-host-count');
        if (hostSlider && hostLbl) {
            hostSlider.addEventListener('input', (e) => {
                hostLbl.innerText = e.target.value;
            });
        }

        // Range Preset Chips
        document.querySelectorAll('.btn-chip').forEach(chip => {
            chip.addEventListener('click', (e) => {
                const count = e.target.dataset.hosts;
                if (hostSlider && hostLbl) {
                    hostSlider.value = count;
                    hostLbl.innerText = count;
                }
            });
        });

        // Threat ratio slider
        const threatSlider = document.getElementById('cfg-threat-ratio');
        const threatLbl = document.getElementById('lbl-threat-ratio');
        if (threatSlider && threatLbl) {
            threatSlider.addEventListener('input', (e) => {
                threatLbl.innerText = `${e.target.value}%`;
            });
        }

        // Packet count slider
        const injCount = document.getElementById('inj-count');
        const lblInjCount = document.getElementById('lbl-inj-count');
        if (injCount && lblInjCount) {
            injCount.addEventListener('input', (e) => {
                lblInjCount.innerText = e.target.value;
            });
        }

        // Delay slider
        const injDelay = document.getElementById('inj-delay');
        const lblInjDelay = document.getElementById('lbl-inj-delay');
        if (injDelay && lblInjDelay) {
            injDelay.addEventListener('input', (e) => {
                lblInjDelay.innerText = `${e.target.value} ms`;
            });
        }

        // Simulation pace slider
        const simPace = document.getElementById('sim-pace');
        const lblSimPace = document.getElementById('lbl-sim-pace');
        if (simPace && lblSimPace) {
            simPace.addEventListener('input', (e) => {
                lblSimPace.innerText = `${(e.target.value / 10).toFixed(1)}s`;
            });
        }

        // Topology Configuration Form Submit
        const formTopo = document.getElementById('form-topo-config');
        if (formTopo) {
            formTopo.addEventListener('submit', (e) => {
                e.preventDefault();
                this.submitTopologyConfig();
            });
        }

        // Traffic Injection Form Submit
        const formInject = document.getElementById('form-traffic-inject');
        if (formInject) {
            formInject.addEventListener('submit', (e) => {
                e.preventDefault();
                this.submitTrafficInject();
            });
        }

        // Automated Simulation Controls
        const btnStart = document.getElementById('btn-sim-start');
        const btnPause = document.getElementById('btn-sim-pause');
        const btnStop = document.getElementById('btn-sim-stop');
        const btnReset = document.getElementById('btn-sim-reset');
        const btnResetNet = document.getElementById('btn-reset-net');

        if (btnStart) btnStart.addEventListener('click', () => this.startSimulation());
        if (btnPause) btnPause.addEventListener('click', () => this.pauseSimulation());
        if (btnStop) btnStop.addEventListener('click', () => this.stopSimulation());
        if (btnReset) btnReset.addEventListener('click', () => this.resetSimulation());
        if (btnResetNet) btnResetNet.addEventListener('click', () => this.resetSimulation());

        // Refresh Incidents Button
        const btnRefInc = document.getElementById('btn-refresh-incidents');
        if (btnRefInc) btnRefInc.addEventListener('click', () => this.loadIncidents());

        // Global Model Switcher
        const selModel = document.getElementById('select-global-model');
        if (selModel) {
            selModel.addEventListener('change', async (e) => {
                const targetModel = e.target.value;
                try {
                    const res = await fetch('/api/model/select', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ model: targetModel })
                    });
                    const resData = await res.json();
                    if (resData.success) {
                        this.showToast(`Backend model switched to: ${resData.model}`, 'success');
                        this.loadStatus();
                    } else {
                        this.showToast(`Model switch failed: ${resData.message}`, 'danger');
                    }
                } catch (err) {
                    this.showToast(`Error switching model: ${err.message}`, 'danger');
                }
            });
        }

        // Initialize Topology Canvas Object
        window.topologyInstance = new SentiNexTopology('topo-svg');
    }

    initSSE() {
        const streamUrl = '/api/stream';
        console.log(`[*] Connecting to SentiNex SSE Stream: ${streamUrl}`);
        const eventSource = new EventSource(streamUrl);

        eventSource.addEventListener('connected', (e) => {
            const data = JSON.parse(e.data);
            console.log('[+] SSE Connected:', data.message);
            this.showToast('SDN Stream Connected', 'success');
        });

        eventSource.addEventListener('ping', () => {
            // Heartbeat
        });

        eventSource.addEventListener('threat_detected', (e) => {
            const event = JSON.parse(e.data);
            this.handleThreatEvent(event);
        });

        eventSource.addEventListener('benign_observed', (e) => {
            const event = JSON.parse(e.data);
            this.handleBenignEvent(event);
        });

        eventSource.addEventListener('host_unblocked', (e) => {
            const event = JSON.parse(e.data);
            this.showToast(`Host ${event.ip} unblocked (${event.rules_removed} rules removed)`, 'success');
            this.loadInitialData();
        });

        eventSource.addEventListener('topology_rebuilt', (e) => {
            const event = JSON.parse(e.data);
            this.showToast(`Topology rebuilt: ${event.topo_type} (${event.host_count} hosts)`, 'success');
            this.loadTopology();
        });

        eventSource.addEventListener('simulation_started', () => {
            this.updateSimStatus('RUNNING');
        });

        eventSource.addEventListener('simulation_paused', () => {
            this.updateSimStatus('PAUSED');
        });

        eventSource.addEventListener('simulation_stopped', () => {
            this.updateSimStatus('STOPPED');
        });

        eventSource.addEventListener('network_reset', () => {
            this.showToast('Network state cleanly reset', 'warning');
            this.loadInitialData();
        });

        eventSource.onerror = (err) => {
            console.warn('[!] SSE Stream disconnected. Reconnecting...');
            document.getElementById('dot-sse').className = 'status-dot dot-yellow';
            document.getElementById('val-sse-latency').innerText = 'Reconnecting';
        };
    }

    handleThreatEvent(event) {
        // Measure delivery latency
        if (event.emitted_at) {
            const deliveryMs = Math.max(1, Math.round((Date.now() / 1000 - event.emitted_at) * 1000));
            document.getElementById('val-sse-latency').innerText = `${deliveryMs} ms`;
            document.getElementById('dot-sse').className = 'status-dot dot-green';
        }

        // Increment telemetry KPI counters
        const kpiThreats = document.getElementById('kpi-threats');
        if (kpiThreats) kpiThreats.innerText = parseInt(kpiThreats.innerText || 0) + 1;

        const kpiQuarantined = document.getElementById('kpi-quarantined');
        if (kpiQuarantined) kpiQuarantined.innerText = parseInt(kpiQuarantined.innerText || 0) + 1;

        const kpiPackets = document.getElementById('kpi-packets');
        if (kpiPackets) kpiPackets.innerText = parseInt(kpiPackets.innerText || 0) + 1;

        // Update latency meters
        if (event.inference_ms) document.getElementById('kpi-infer-lat').innerText = `${event.inference_ms.toFixed(1)} ms`;
        if (event.xai_ms) document.getElementById('kpi-xai-lat').innerText = `${event.xai_ms.toFixed(1)} ms`;

        // Append to Event Feed
        const feed = document.getElementById('event-feed');
        if (feed) {
            const card = document.createElement('div');
            card.className = 'event-card threat';
            card.innerHTML = `
                <div class="event-header">
                    <span>${event.iso_time}</span>
                    <span class="event-threat-badge">INTRUSION DETECTED</span>
                </div>
                <div class="event-title">${event.threat_category}</div>
                <div class="event-meta">
                    <span>Src: <strong>${event.src_ip}</strong> → Dst: ${event.dst_ip}</span>
                    <span>Action: <strong>${event.mitigation_status}</strong></span>
                </div>
                <div style="margin-top: 6px; display:flex; justify-content: space-between; align-items:center;">
                    <span style="font-size:0.7rem; color:#94a3b8;">Confidence: ${(event.confidence * 100).toFixed(1)}% | Infer: ${event.inference_ms}ms</span>
                    <button class="btn btn-secondary btn-sm" onclick="window.appInstance.inspectIncident('${event.incident_id}')">Inspect XAI</button>
                </div>
            `;
            if (feed.querySelector('.empty-state')) feed.innerHTML = '';
            feed.insertBefore(card, feed.firstChild);
        }

        // Update topology host state
        if (this.topology && this.topology.hosts) {
            const h = this.topology.hosts.find(x => x.ip === event.src_ip);
            if (h) {
                h.state = 'blocked';
                window.topologyInstance.updateData(this.topology);
            }
        }

        // Reload incidents audit list
        this.loadIncidents();
    }

    handleBenignEvent(event) {
        if (event.emitted_at) {
            const deliveryMs = Math.max(1, Math.round((Date.now() / 1000 - event.emitted_at) * 1000));
            document.getElementById('val-sse-latency').innerText = `${deliveryMs} ms`;
        }

        const kpiBenign = document.getElementById('kpi-benign');
        if (kpiBenign) kpiBenign.innerText = parseInt(kpiBenign.innerText || 0) + 1;

        const kpiPackets = document.getElementById('kpi-packets');
        if (kpiPackets) kpiPackets.innerText = parseInt(kpiPackets.innerText || 0) + 1;

        if (event.inference_ms) document.getElementById('kpi-infer-lat').innerText = `${event.inference_ms.toFixed(1)} ms`;

        const feed = document.getElementById('event-feed');
        if (feed) {
            const card = document.createElement('div');
            card.className = 'event-card benign';
            card.innerHTML = `
                <div class="event-header">
                    <span>${event.iso_time}</span>
                    <span style="color:#10b981; font-weight:bold;">BENIGN FLOW</span>
                </div>
                <div class="event-title">${event.threat_category}</div>
                <div class="event-meta">
                    <span>Src: <strong>${event.src_ip}</strong> → Dst: ${event.dst_ip}</span>
                    <span>Action: <strong>FORWARDED</strong></span>
                </div>
            `;
            if (feed.querySelector('.empty-state')) feed.innerHTML = '';
            feed.insertBefore(card, feed.firstChild);
            // Limit feed length
            while (feed.children.length > 30) feed.removeChild(feed.lastChild);
        }
    }

    async loadInitialData() {
        await Promise.all([
            this.loadStatus(),
            this.loadTopology(),
            this.loadIncidents(),
            this.loadFlows()
        ]);
    }

    async loadStatus() {
        try {
            const res = await fetch('/api/status');
            const data = await res.json();
            this.status = data;

            // System diagnostic badges
            const ctrl = data.controller || {};
            const dotCtrl = document.getElementById('dot-controller');
            const valCtrl = document.getElementById('val-controller');
            if (ctrl.controller_connected && ctrl.live_dpids && ctrl.live_dpids.length > 0) {
                dotCtrl.className = 'status-dot dot-green';
                valCtrl.innerText = `Ryu Live (${ctrl.live_dpids.length} SW)`;
            } else if (ctrl.controller_connected) {
                dotCtrl.className = 'status-dot dot-yellow';
                valCtrl.innerText = 'Ryu Ready (0 SW)';
            } else {
                dotCtrl.className = 'status-dot dot-red';
                valCtrl.innerText = 'Ryu Offline';
            }

            const activeModel = (data.backend_model || 'RF').toLowerCase();
            const selModel = document.getElementById('select-global-model');
            if (selModel && selModel.value !== activeModel) {
                selModel.value = activeModel;
            }

            const valMode = document.getElementById('val-mode');
            if (data.topology?.mode === 'mininet') {
                const verifiedHosts = ctrl.verified_mininet_hosts || data.topology.instantiated_mininet_hosts || 0;
                valMode.innerText = `Mininet (${verifiedHosts} Hosts)`;
            } else {
                valMode.innerText = 'Logical Emulation';
            }

            // Telemetry KPIs
            const tel = data.telemetry || {};
            document.getElementById('kpi-packets').innerText = tel.total_packets_observed || 0;
            document.getElementById('kpi-flows').innerText = `Flows Tracked: ${tel.total_flows_tracked || 0}`;
            document.getElementById('kpi-threats').innerText = tel.threat_count || 0;
            document.getElementById('kpi-benign').innerText = tel.benign_count || 0;
            document.getElementById('kpi-quarantined').innerText = tel.active_quarantined_hosts || 0;

            const bdown = tel.threats_by_category || {};
            document.getElementById('kpi-threat-breakdown').innerText = 
                `DoS: ${bdown['Denial of Service (DoS / DDoS SYN Flood)'] || 0} | Scan: ${bdown['Reconnaissance (Port Scan / Probe)'] || 0}`;

            // Latencies
            const lats = data.latencies || {};
            document.getElementById('kpi-infer-lat').innerText = `${(lats.inference_latency_ms || 0).toFixed(1)} ms`;
            document.getElementById('kpi-xai-lat').innerText = `${(lats.xai_latency_ms || 0).toFixed(1)} ms`;

            // Simulation status
            const sim = data.simulation || {};
            if (sim.running) {
                this.updateSimStatus(sim.paused ? 'PAUSED' : 'RUNNING');
            } else {
                this.updateSimStatus('STOPPED');
            }

        } catch (e) {
            console.error('Failed to load status:', e);
        }
    }

    async loadTopology() {
        try {
            const res = await fetch('/api/topology');
            const data = await res.json();
            this.topology = data;

            // Update Topology Meta text
            const metaText = `${data.topo_type.toUpperCase()} Topology | ${data.configured_host_count} Hosts (${data.execution_mode.toUpperCase()}) | ${data.switches.length} Switches`;
            document.getElementById('topo-meta-text').innerText = metaText;

            // Render Topology
            if (window.topologyInstance) {
                window.topologyInstance.updateData(data);
            }

            // Populate Host Injection Dropdowns
            this.populateHostDropdowns(data.hosts || []);

        } catch (e) {
            console.error('Failed to load topology:', e);
        }
    }

    populateHostDropdowns(hosts) {
        const selSrc = document.getElementById('inj-src');
        const selDst = document.getElementById('inj-dst');
        if (!selSrc || !selDst) return;

        selSrc.innerHTML = '';
        selDst.innerHTML = '';

        hosts.forEach(h => {
            const opt1 = document.createElement('option');
            opt1.value = h.id;
            opt1.innerText = `${h.id} (${h.ip} - ${h.role || 'Host'})`;
            selSrc.appendChild(opt1);

            const opt2 = document.createElement('option');
            opt2.value = h.id;
            opt2.innerText = `${h.id} (${h.ip} - ${h.role || 'Host'})`;
            selDst.appendChild(opt2);
        });

        // Set default selections
        if (hosts.length >= 3) {
            selSrc.value = hosts[2].id; // h3 attacker
            selDst.value = hosts[1].id; // h2 victim server
        }
    }

    selectInjectSource(hostId) {
        const selSrc = document.getElementById('inj-src');
        if (selSrc) selSrc.value = hostId;
    }

    async submitTopologyConfig() {
        const topoType = document.getElementById('cfg-topo-type').value;
        const hostCount = parseInt(document.getElementById('cfg-host-count').value);
        const mode = document.getElementById('cfg-exec-mode').value;
        const threatRatio = parseFloat(document.getElementById('cfg-threat-ratio').value) / 100.0;
        const seed = parseInt(document.getElementById('cfg-seed').value);

        try {
            const res = await fetch('/api/topology/configure', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    topo_type: topoType,
                    host_count: hostCount,
                    mode: mode,
                    threat_ratio: threatRatio,
                    seed: seed
                })
            });
            const data = await res.json();
            if (data.success) {
                this.showToast('Network Topology Reconfigured', 'success');
                this.loadInitialData();
            } else {
                this.showToast(data.message || 'Configuration error', 'danger');
            }
        } catch (e) {
            this.showToast(`Error: ${e.message}`, 'danger');
        }
    }

    async submitTrafficInject() {
        const trafficType = document.getElementById('inj-type').value;
        const srcHost = document.getElementById('inj-src').value;
        const dstHost = document.getElementById('inj-dst').value;
        const count = parseInt(document.getElementById('inj-count').value);
        const delay = parseFloat(document.getElementById('inj-delay').value) / 1000.0;

        const btn = document.getElementById('btn-inject-now');
        btn.disabled = true;
        btn.innerText = 'Injecting...';

        try {
            const res = await fetch('/api/traffic/inject', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    traffic_type: trafficType,
                    src_host: srcHost,
                    target_host: dstHost,
                    count: count,
                    delay: delay
                })
            });
            const data = await res.json();

            // Display Feedback Card
            const fbCard = document.getElementById('inj-feedback');
            if (fbCard) {
                document.getElementById('fb-gt').innerText = data.ground_truth || trafficType;
                document.getElementById('fb-pkts').innerText = data.packets_sent || count;
                document.getElementById('fb-pred').innerText = data.detected_threat || 'Unknown';
                document.getElementById('fb-pred').className = `badge ${data.is_malicious ? 'badge-danger' : 'badge-live'}`;
                document.getElementById('fb-mit').innerText = data.mitigation_status || 'FORWARDED';
                fbCard.style.display = 'block';
            }

            this.showToast(`Injected ${count} packets from ${srcHost}`, data.is_malicious ? 'warning' : 'success');
            this.loadInitialData();

        } catch (e) {
            this.showToast(`Injection failed: ${e.message}`, 'danger');
        } finally {
            btn.disabled = false;
            btn.innerText = 'Inject Traffic';
        }
    }

    async startSimulation() {
        const paceVal = parseFloat(document.getElementById('sim-pace').value) / 10.0;
        const seedVal = document.getElementById('sim-seed').value;

        try {
            const res = await fetch('/api/simulation/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pace_sec: paceVal, seed: seedVal })
            });
            const data = await res.json();
            if (data.success) {
                this.updateSimStatus('RUNNING');
                this.showToast('Automated Simulation Started', 'success');
            }
        } catch (e) {
            this.showToast(`Error: ${e.message}`, 'danger');
        }
    }

    async pauseSimulation() {
        try {
            const res = await fetch('/api/simulation/pause', { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                this.updateSimStatus('PAUSED');
                this.showToast('Simulation Paused (Monitoring Active)', 'warning');
            }
        } catch (e) {
            this.showToast(`Error: ${e.message}`, 'danger');
        }
    }

    async stopSimulation() {
        try {
            const res = await fetch('/api/simulation/stop', { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                this.updateSimStatus('STOPPED');
                this.showToast('Simulation Stopped', 'warning');
            }
        } catch (e) {
            this.showToast(`Error: ${e.message}`, 'danger');
        }
    }

    async resetSimulation() {
        try {
            const res = await fetch('/api/simulation/reset', { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                this.updateSimStatus('STOPPED');
                this.showToast('SDN State & Simulation Cleanly Reset', 'warning');
                this.loadInitialData();
            }
        } catch (e) {
            this.showToast(`Error: ${e.message}`, 'danger');
        }
    }

    updateSimStatus(state) {
        const badge = document.getElementById('sim-status-badge');
        const btnStart = document.getElementById('btn-sim-start');
        const btnPause = document.getElementById('btn-sim-pause');
        const btnStop = document.getElementById('btn-sim-stop');

        if (badge) {
            badge.innerText = state;
            if (state === 'RUNNING') badge.className = 'badge badge-live';
            else if (state === 'PAUSED') badge.className = 'badge badge-warning';
            else badge.className = 'badge badge-neutral';
        }

        if (btnStart) btnStart.disabled = (state === 'RUNNING');
        if (btnPause) btnPause.disabled = (state !== 'RUNNING');
        if (btnStop) btnStop.disabled = (state === 'STOPPED');
    }

    async loadIncidents() {
        try {
            const res = await fetch('/api/incidents');
            const data = await res.json();
            this.incidents = data || [];

            // Update badge counter
            document.getElementById('nav-incident-count').innerText = this.incidents.length;

            this.renderIncidentsTable(this.incidents);

            // Auto-select first incident if none selected
            if (this.incidents.length > 0 && !this.selectedIncident) {
                this.inspectIncident(this.incidents[0].id);
            }
        } catch (e) {
            console.error('Failed to load incidents:', e);
        }
    }

    renderIncidentsTable(list) {
        const tbody = document.getElementById('incidents-tbody');
        if (!tbody) return;

        if (list.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center" style="padding: 24px; color:#64748b;">No security incidents recorded yet.</td></tr>`;
            return;
        }

        tbody.innerHTML = list.map(inc => `
            <tr onclick="window.appInstance.inspectIncident('${inc.id}')">
                <td><code style="color:#38bdf8; font-weight:bold;">${inc.id}</code></td>
                <td>${inc.iso_time}</td>
                <td><strong style="color:#ef4444;">${inc.src_ip}</strong></td>
                <td>${inc.threat_category}</td>
                <td><span class="badge" style="background:#1e3a5f; color:#38bdf8;">${inc.confidence_pct || ((inc.confidence || 1)*100).toFixed(0) + '%'}</span></td>
                <td><span class="badge ${inc.mitigation?.confirmed ? 'badge-purple' : 'badge-danger'}" style="background:#7e22ce; color:#fff;">${inc.mitigation?.status || 'BLOCKED'}</span></td>
                <td><button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); window.appInstance.inspectIncident('${inc.id}')">Inspect</button></td>
            </tr>
        `).join('');
    }

    filterIncidents() {
        const query = (document.getElementById('inc-search').value || '').toLowerCase();
        const cat = document.getElementById('inc-filter-cat').value;

        const filtered = this.incidents.filter(inc => {
            const matchesQuery = !query || 
                inc.id.toLowerCase().includes(query) ||
                inc.src_ip.toLowerCase().includes(query) ||
                inc.threat_category.toLowerCase().includes(query);

            const matchesCat = !cat || inc.threat_category.toLowerCase().includes(cat.toLowerCase());
            return matchesQuery && matchesCat;
        });

        this.renderIncidentsTable(filtered);
    }

    async inspectIncident(incidentId) {
        try {
            const res = await fetch(`/api/incidents/${incidentId}`);
            if (!res.ok) return;
            const inc = await res.json();
            this.selectedIncident = inc;

            document.getElementById('detail-empty-view').style.display = 'none';
            document.getElementById('detail-content-view').style.display = 'block';

            // Switch to Incidents tab
            this.switchTab('tab-incidents');

            // Header titles
            document.getElementById('detail-title').innerText = `Incident ${inc.id} (${inc.threat_category})`;
            document.getElementById('detail-sub').innerText = `Recorded ${inc.iso_time} | Attacker: ${inc.src_ip} → Victim: ${inc.dst_ip}`;

            // Unblock button
            const unblockWrap = document.getElementById('detail-unblock-wrapper');
            const btnUnblock = document.getElementById('btn-detail-unblock');
            if (unblockWrap && btnUnblock) {
                unblockWrap.style.display = 'block';
                btnUnblock.onclick = () => this.unblockHost(inc.src_ip);
            }

            // Timings
            const timings = inc.timings || {};
            document.getElementById('trace-extract').innerText = `${timings.extract_ms || 0.5} ms`;
            document.getElementById('trace-infer').innerText = `${timings.infer_ms || 30.0} ms`;
            document.getElementById('trace-xai').innerText = `${timings.xai_ms || 1800} ms`;
            document.getElementById('trace-mit').innerText = `${timings.mitigate_ms || 0.2} ms`;
            document.getElementById('trace-total').innerText = `${timings.total_pipeline_ms || 1830} ms`;

            // Attributes
            document.getElementById('det-id').innerText = inc.id;
            document.getElementById('det-src').innerText = inc.src_ip;
            document.getElementById('det-dst').innerText = inc.dst_ip;
            document.getElementById('det-conf').innerText = inc.confidence_pct || `${((inc.confidence || 1) * 100).toFixed(1)}%`;
            document.getElementById('det-gt').innerText = inc.ground_truth || 'Simulated Injection';
            document.getElementById('det-mit').innerText = inc.mitigation?.action || 'DROP_FLOW_RULE (Priority 100)';

            // Layman plain-English explanation
            const laymanEl = document.getElementById('layman-text');
            if (laymanEl && window.XAICharts) {
                laymanEl.innerHTML = window.XAICharts.generateLaymanExplanation(inc);
            }

            // Render SHAP & LIME Divergent Bar Charts
            if (window.XAICharts) {
                window.XAICharts.renderDivergentBarChart('shap-chart', inc.shap_scores, true);
                window.XAICharts.renderDivergentBarChart('lime-chart', inc.lime_explanations, false);
            }

            // Load Flow Tables for inspector
            this.loadFlows();

        } catch (e) {
            console.error('Failed to inspect incident:', e);
        }
    }

    async loadFlows() {
        try {
            const res = await fetch('/api/flows');
            const flows = await res.json();

            const tabContainer = document.getElementById('flow-switch-tabs');
            const tbody = document.getElementById('flows-tbody');
            if (!tabContainer || !tbody) return;

            const switchKeys = Object.keys(flows);
            if (switchKeys.length === 0) return;

            if (!this.activeFlowSwitch || !flows[this.activeFlowSwitch]) {
                this.activeFlowSwitch = switchKeys[0];
            }

            // Render Switch Tabs
            tabContainer.innerHTML = switchKeys.map(k => `
                <button class="flow-tab-btn ${k === this.activeFlowSwitch ? 'active' : ''}" 
                        onclick="window.appInstance.selectFlowSwitch('${k}')">
                    Switch ${k.toUpperCase()} (${flows[k].rule_count} Rules)
                </button>
            `).join('');

            // Render active switch rules
            const activeRules = flows[this.activeFlowSwitch]?.rules || [];
            tbody.innerHTML = activeRules.map(r => `
                <tr>
                    <td><code>${r.table_id}</code></td>
                    <td><strong style="color:${r.priority >= 100 ? '#ef4444' : '#38bdf8'}">${r.priority}</strong></td>
                    <td><code>${JSON.stringify(r.match)}</code></td>
                    <td><span class="badge" style="background:${r.actions.includes('DROP') ? '#7e22ce' : '#1e3a5f'}">${r.actions.join(', ')}</span></td>
                    <td>${r.idle_timeout}s / ${r.hard_timeout}s</td>
                    <td>${r.installed_at || '-'}</td>
                </tr>
            `).join('');

        } catch (e) {
            console.error('Failed to load flows:', e);
        }
    }

    selectFlowSwitch(swKey) {
        this.activeFlowSwitch = swKey;
        this.loadFlows();
    }

    async unblockHost(hostOrIp) {
        try {
            const res = await fetch('/api/mitigation/unblock', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ host_or_ip: hostOrIp })
            });
            const data = await res.json();
            if (data.success) {
                this.showToast(`Host ${hostOrIp} unblocked successfully!`, 'success');
                this.loadInitialData();
            } else {
                this.showToast(data.message || 'Unblock failed', 'danger');
            }
        } catch (e) {
            this.showToast(`Error unblocking host: ${e.message}`, 'danger');
        }
    }

    showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        if (!container) return;

        const iconSvg = type === 'success' 
            ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>'
            : (type === 'danger'
                ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>'
                : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line></svg>');

        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.innerHTML = `
            <span class="toast-icon">${iconSvg}</span>
            <span>${message}</span>
        `;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            setTimeout(() => toast.remove(), 200);
        }, 3500);
    }
}

// Instantiate Global App Controller
window.addEventListener('DOMContentLoaded', () => {
    window.appInstance = new SentiNexApp();
});

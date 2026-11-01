/**
 * SentiNex SDN Interactive Topology Renderer
 * High-performance SVG topology visualizer with dynamic clustering for 1,000+ hosts,
 * zoom/pan controls, and live state updates.
 */

class SentiNexTopology {
    constructor(svgId) {
        this.svg = document.getElementById(svgId);
        this.viewport = document.getElementById('topo-viewport');
        this.data = { switches: [], hosts: [], links: [] };
        
        this.scale = 1.0;
        this.panX = 0;
        this.panY = 0;
        this.isPanning = false;
        this.startX = 0;
        this.startY = 0;

        this.selectedNode = null;
        this.nodePositions = new Map();

        this.initEvents();
    }

    initEvents() {
        if (!this.viewport) return;

        // Mouse Pan
        this.viewport.addEventListener('mousedown', (e) => {
            if (e.target.tagName === 'circle' || e.target.tagName === 'rect' || e.target.closest('g.node-group')) {
                return; // Clicking a node
            }
            this.isPanning = true;
            this.startX = e.clientX - this.panX;
            this.startY = e.clientY - this.panY;
        });

        window.addEventListener('mousemove', (e) => {
            if (!this.isPanning) return;
            this.panX = e.clientX - this.startX;
            this.panY = e.clientY - this.startY;
            this.updateTransform();
        });

        window.addEventListener('mouseup', () => {
            this.isPanning = false;
        });

        // Wheel Zoom
        this.viewport.addEventListener('wheel', (e) => {
            e.preventDefault();
            const zoomFactor = e.deltaY < 0 ? 1.15 : 0.85;
            this.scale = Math.min(Math.max(0.3, this.scale * zoomFactor), 4.0);
            this.updateTransform();
        });

        // Reset View Button
        const btnReset = document.getElementById('btn-zoom-reset');
        if (btnReset) {
            btnReset.addEventListener('click', () => this.resetView());
        }

        // Close Inspector Button
        const btnClose = document.getElementById('insp-close');
        if (btnClose) {
            btnClose.addEventListener('click', () => {
                document.getElementById('node-inspector').style.display = 'none';
                this.selectedNode = null;
            });
        }
    }

    resetView() {
        this.scale = 1.0;
        this.panX = 0;
        this.panY = 0;
        this.updateTransform();
    }

    updateTransform() {
        const rootGroup = this.svg.getElementById('topo-root');
        if (rootGroup) {
            rootGroup.setAttribute('transform', `translate(${this.panX}, ${this.panY}) scale(${this.scale})`);
        }
    }

    updateData(topologyData) {
        if (!topologyData) return;
        this.data = topologyData;
        this.render();
    }

    render() {
        if (!this.svg) return;
        const width = this.viewport.clientWidth || 800;
        const height = this.viewport.clientHeight || 500;

        const switches = this.data.switches || [];
        const hosts = this.data.hosts || [];
        const hostCount = hosts.length;

        // Calculate positions
        this.nodePositions.clear();
        const swCount = switches.length;
        const swY = height * 0.42;

        // Position Switches evenly horizontally
        switches.forEach((sw, idx) => {
            const spacing = width / (swCount + 1);
            const x = spacing * (idx + 1);
            const y = swY;
            this.nodePositions.set(sw.id, { x, y, type: 'switch', data: sw });
        });

        // Determine rendering mode: Detailed (<=64 hosts) or Clustered Pods (>64 hosts)
        const isClustered = hostCount > 64;

        let linksSvg = '';
        let nodesSvg = '';

        if (!isClustered) {
            // Position individual hosts around their connected switches
            const hostsPerSw = new Map();
            hosts.forEach(h => {
                const sw = h.switch || switches[0]?.id;
                if (!hostsPerSw.has(sw)) hostsPerSw.set(sw, []);
                hostsPerSw.get(sw).push(h);
            });

            hostsPerSw.forEach((hList, swId) => {
                const swPos = this.nodePositions.get(swId) || { x: width / 2, y: swY };
                const count = hList.length;
                const radius = Math.min(130, Math.max(70, count * 15));

                hList.forEach((h, idx) => {
                    // Spread hosts below or above switches in fan arc
                    const angle = Math.PI * 0.2 + (Math.PI * 0.6 * (idx / Math.max(1, count - 1)));
                    const hX = swPos.x + radius * Math.cos(angle);
                    const hY = swPos.y + radius * Math.sin(angle);

                    this.nodePositions.set(h.id, { x: hX, y: hY, type: 'host', data: h });

                    // Host to Switch Link
                    linksSvg += `<line x1="${swPos.x}" y1="${swPos.y}" x2="${hX}" y2="${hY}" stroke="#243247" stroke-width="1.5"></line>`;
                });
            });

            // Switch to Switch Links
            (this.data.links || []).forEach(link => {
                if (link.type === 'switch-switch') {
                    const p1 = this.nodePositions.get(link.source);
                    const p2 = this.nodePositions.get(link.target);
                    if (p1 && p2) {
                        linksSvg += `<line x1="${p1.x}" y1="${p1.y}" x2="${p2.x}" y2="${p2.y}" stroke="#38bdf8" stroke-width="3" stroke-dasharray="4,2"></line>`;
                    }
                }
            });

            // Render Host Nodes
            hosts.forEach(h => {
                const pos = this.nodePositions.get(h.id);
                if (!pos) return;

                let fillColor = '#10b981'; // benign
                let strokeColor = '#059669';
                let pulseClass = '';

                if (h.state === 'threat_detected') {
                    fillColor = '#ef4444';
                    strokeColor = '#dc2626';
                    pulseClass = 'class="pulse-threat"';
                } else if (h.state === 'blocked') {
                    fillColor = '#a855f7';
                    strokeColor = '#7e22ce';
                } else if (h.state === 'mitigation_failed') {
                    fillColor = '#f59e0b';
                    strokeColor = '#d97706';
                } else if (h.state === 'recovering') {
                    fillColor = '#06b6d4';
                    strokeColor = '#0891b2';
                }

                nodesSvg += `
                    <g class="node-group" style="cursor: pointer;" onclick="window.topologyInstance.inspectNode('${h.id}')">
                        <circle cx="${pos.x}" cy="${pos.y}" r="11" fill="${fillColor}" stroke="${strokeColor}" stroke-width="2" ${pulseClass}>
                            <title>${h.id} (${h.ip}) - Status: ${h.state}</title>
                        </circle>
                        <text x="${pos.x}" y="${pos.y + 22}" fill="#94a3b8" font-size="10" text-anchor="middle" font-family="'JetBrains Mono', monospace">
                            ${h.id}
                        </text>
                    </g>
                `;
            });

        } else {
            // CLUSTERED SCALABLE MODE for 65 to 1,000+ hosts
            // Renders aggregated host cluster pods per switch to keep DOM fast
            switches.forEach((sw, idx) => {
                const swPos = this.nodePositions.get(sw.id);
                if (!swPos) return;

                const attachedHosts = hosts.filter(h => h.switch === sw.id);
                const blockedInSw = attachedHosts.filter(h => h.state === 'blocked').length;
                const threatsInSw = attachedHosts.filter(h => h.state === 'threat_detected').length;

                const podY = swPos.y + 110;
                const podColor = threatsInSw > 0 ? '#ef4444' : (blockedInSw > 0 ? '#a855f7' : '#10b981');

                linksSvg += `<line x1="${swPos.x}" y1="${swPos.y}" x2="${swPos.x}" y2="${podY}" stroke="#334155" stroke-width="3"></line>`;

                nodesSvg += `
                    <g class="node-group" style="cursor: pointer;" onclick="window.topologyInstance.inspectCluster('${sw.id}', ${attachedHosts.length}, ${blockedInSw})">
                        <rect x="${swPos.x - 60}" y="${podY - 25}" width="120" height="50" rx="8" fill="#131d2e" stroke="${podColor}" stroke-width="2.5"></rect>
                        <text x="${swPos.x}" y="${podY - 5}" fill="#f8fafc" font-size="11" font-weight="bold" text-anchor="middle">
                            Host Pod (${attachedHosts.length} Hosts)
                        </text>
                        <text x="${swPos.x}" y="${podY + 12}" fill="${blockedInSw > 0 ? '#a855f7' : '#94a3b8'}" font-size="9.5" text-anchor="middle">
                            ${blockedInSw > 0 ? `[Quarantined: ${blockedInSw}]` : 'All Benign / Normal'}
                        </text>
                    </g>
                `;
            });

            // Switch to Switch Links
            (this.data.links || []).forEach(link => {
                if (link.type === 'switch-switch') {
                    const p1 = this.nodePositions.get(link.source);
                    const p2 = this.nodePositions.get(link.target);
                    if (p1 && p2) {
                        linksSvg += `<line x1="${p1.x}" y1="${p1.y}" x2="${p2.x}" y2="${p2.y}" stroke="#38bdf8" stroke-width="3" stroke-dasharray="4,2"></line>`;
                    }
                }
            });
        }

        // Render Switch Nodes (Top priority)
        switches.forEach(sw => {
            const pos = this.nodePositions.get(sw.id);
            if (!pos) return;

            nodesSvg += `
                <g class="node-group" style="cursor: pointer;" onclick="window.topologyInstance.inspectSwitch('${sw.id}')">
                    <rect x="${pos.x - 24}" y="${pos.y - 24}" width="48" height="48" rx="8" fill="#1e293b" stroke="#38bdf8" stroke-width="2.5"></rect>
                    <text x="${pos.x}" y="${pos.y + 5}" fill="#38bdf8" font-size="12" font-weight="bold" text-anchor="middle" font-family="'JetBrains Mono', monospace">
                        ${sw.id.toUpperCase()}
                    </text>
                    <text x="${pos.x}" y="${pos.y - 30}" fill="#94a3b8" font-size="10" text-anchor="middle">
                        Flows: ${sw.flow_count || 1}
                    </text>
                </g>
            `;
        });

        // Set Inner SVG with root group transform
        this.svg.innerHTML = `
            <g id="topo-root" transform="translate(${this.panX}, ${this.panY}) scale(${this.scale})">
                ${linksSvg}
                ${nodesSvg}
            </g>
        `;
    }

    inspectNode(hostId) {
        const host = (this.data.hosts || []).find(h => h.id === hostId);
        if (!host) return;

        this.selectedNode = host;
        const inspector = document.getElementById('node-inspector');
        if (!inspector) return;

        document.getElementById('insp-title').innerText = `Host ${host.id} (${host.ip})`;
        document.getElementById('insp-ip').innerText = host.ip;
        document.getElementById('insp-mac').innerText = host.mac;
        document.getElementById('insp-sw').innerText = host.switch;
        document.getElementById('insp-role').innerText = host.role || 'Client';
        document.getElementById('insp-pkts').innerText = host.packets_sent || 0;

        const statusEl = document.getElementById('insp-status');
        statusEl.innerText = host.state.toUpperCase();
        statusEl.className = `badge ${host.state === 'blocked' ? 'badge-danger' : 'badge-live'}`;

        const btnUnblock = document.getElementById('btn-insp-unblock');
        if (host.state === 'blocked') {
            btnUnblock.style.display = 'inline-block';
            btnUnblock.onclick = () => window.appInstance.unblockHost(host.ip);
        } else {
            btnUnblock.style.display = 'none';
        }

        const btnInject = document.getElementById('btn-insp-inject');
        btnInject.onclick = () => {
            window.appInstance.selectInjectSource(host.id);
            window.appInstance.switchTab('tab-traffic-lab');
        };

        inspector.style.display = 'block';
    }

    inspectSwitch(swId) {
        const sw = (this.data.switches || []).find(s => s.id === swId);
        if (!sw) return;

        const inspector = document.getElementById('node-inspector');
        if (!inspector) return;

        document.getElementById('insp-title').innerText = `OpenFlow Switch ${sw.id.toUpperCase()}`;
        document.getElementById('insp-ip').innerText = `DPID: ${sw.dpid}`;
        document.getElementById('insp-mac').innerText = `OpenFlow 1.3 (OFP 0x04)`;
        document.getElementById('insp-sw').innerText = `Ports Active: 4`;
        document.getElementById('insp-role').innerText = `Core SDN Forwarder`;
        document.getElementById('insp-pkts').innerText = `Flow Rules: ${sw.flow_count || 1}`;

        const statusEl = document.getElementById('insp-status');
        statusEl.innerText = "ACTIVE";
        statusEl.className = "badge badge-live";

        document.getElementById('btn-insp-unblock').style.display = 'none';
        inspector.style.display = 'block';
    }

    inspectCluster(swId, count, blocked) {
        const inspector = document.getElementById('node-inspector');
        if (!inspector) return;

        document.getElementById('insp-title').innerText = `Switch ${swId.toUpperCase()} Host Pod`;
        document.getElementById('insp-ip').innerText = `Subnet: 10.0.0.0/24`;
        document.getElementById('insp-mac').innerText = `Clustered Virtual Interface`;
        document.getElementById('insp-sw').innerText = swId.toUpperCase();
        document.getElementById('insp-role').innerText = `Aggregated Hosts (${count} Total)`;
        document.getElementById('insp-pkts').innerText = `Quarantined: ${blocked}`;

        const statusEl = document.getElementById('insp-status');
        statusEl.innerText = blocked > 0 ? "ATTACK MITIGATED" : "HEALTHY";
        statusEl.className = `badge ${blocked > 0 ? 'badge-danger' : 'badge-live'}`;

        document.getElementById('btn-insp-unblock').style.display = 'none';
        inspector.style.display = 'block';
    }
}

window.SentiNexTopology = SentiNexTopology;

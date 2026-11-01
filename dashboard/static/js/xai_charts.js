/**
 * SentiNex XAI Visualization & Layman Explanation Generator
 * Renders SVG horizontal bar charts for SHAP & LIME and provides plain-English summaries.
 */

const XAICharts = {
    // Dictionary of feature layman definitions
    featureGlossary: {
        'rate': { name: 'Transmission Rate', desc: 'Packets transmitted per second. High rate indicates automated volumetric flooding (DoS).' },
        'sbytes': { name: 'Source Bytes', desc: 'Total payload bytes sent by source. Large volume signals flooding or exfiltration.' },
        'spkts': { name: 'Source Packet Count', desc: 'Number of packets generated in this flow.' },
        'dur': { name: 'Flow Duration', desc: 'Total connection lifetime in seconds.' },
        'sttl': { name: 'Source TTL', desc: 'Time-To-Live hop limit. Deviations from standard (64/128) indicate OS spoofing.' },
        'dttl': { name: 'Destination TTL', desc: 'Time-To-Live of response traffic.' },
        'ct_dst_sport_ltm': { name: 'Distinct Destination Ports', desc: 'Count of unique service ports probed. High count indicates Port Scanning.' },
        'ct_src_dport_ltm': { name: 'Source to Destination Port Concentration', desc: 'Concentration of connections to target destination port.' },
        'ct_srv_dst': { name: 'Same Service Endpoint Access', desc: 'Frequency of connections to same service in 100-connection window.' },
        'ct_state_ttl': { name: 'State-to-TTL Consistency', desc: 'Correlation between TCP state flags and hop limit.' },
        'sload': { name: 'Source Bits/Sec (Load)', desc: 'Bitrate transmitted by sender.' },
        'sloss': { name: 'Source Packet Loss', desc: 'Unacknowledged packets dropped by network.' },
        'swin': { name: 'Source TCP Window', desc: 'Advertised TCP buffer window.' },
        'proto': { name: 'Protocol Type', desc: 'Transport layer protocol (TCP=6, UDP=17).' }
    },

    cleanFeatureName(rawName) {
        // Remove threshold comparisons like '-0.75 < dttl <= 1.48' or 'rate > 40.0'
        const parts = rawName.split(/[\s<>=!]+/);
        for (const p of parts) {
            const clean = p.trim().toLowerCase();
            if (this.featureGlossary[clean]) {
                return clean;
            }
        }
        return parts[0] || rawName;
    },

    generateLaymanExplanation(incident) {
        if (!incident) return "No incident details available.";
        
        const cat = incident.threat_category || "Anomaly";
        const lime = incident.lime_explanations || [];
        const shap = incident.shap_scores || {};
        const flow = incident.flow_stats || {};

        let explanation = "";

        if (cat.includes("Denial of Service") || cat.includes("DoS")) {
            explanation = `<strong>Threat Summary:</strong> A high-rate volumetric SYN flood was identified originating from IP <code>${incident.src_ip}</code> targeting <code>${incident.dst_ip}</code>.<br><br>`;
            explanation += `<strong>Why the AI flagged this:</strong> The flow tracker detected a rapid surge in transmission rate (<code>${flow.rate || 'High'} pkts/s</code>) with repeated TCP SYN requests. `;
            if (lime.length > 0) {
                explanation += `In the local LIME explanation, the top feature pushing the prediction towards attack was <code>${lime[0][0]}</code> (impact: <strong>${lime[0][1] > 0 ? '+' : ''}${lime[0][1].toFixed(4)}</strong>). `;
            }
            explanation += `This signature is characteristic of an attempt to exhaust the SDN controller buffer and switch flow tables, triggering automated OpenFlow drop rules.`;
        } else if (cat.includes("Port Scan") || cat.includes("Reconnaissance")) {
            explanation = `<strong>Threat Summary:</strong> Reconnaissance port probing was detected from IP <code>${incident.src_ip}</code> scanning multiple services on <code>${incident.dst_ip}</code>.<br><br>`;
            explanation += `<strong>Why the AI flagged this:</strong> The model observed repeated connection attempts to distinct destination ports within a short observation window. `;
            if (shap && Object.keys(shap).length > 0) {
                const topShapKey = Object.keys(shap)[0];
                const topShapVal = shap[topShapKey];
                explanation += `Global SHAP feature attribution identified <code>${topShapKey}</code> (Shapley score: <strong>${topShapVal > 0 ? '+' : ''}${topShapVal.toFixed(4)}</strong>) as the primary contributor distinguishing this probe from legitimate traffic. `;
            }
            explanation += `Early detection allows the SDN controller to isolate the reconnaissance scanner before vulnerability exploitation occurs.`;
        } else {
            explanation = `<strong>Threat Summary:</strong> Anomalous traffic behavior detected from IP <code>${incident.src_ip}</code>.<br><br>`;
            explanation += `<strong>Why the AI flagged this:</strong> The combination of observed flow parameters significantly diverged from baseline benign web activity. `;
            if (lime.length > 0) {
                explanation += `The most influential factor was <code>${lime[0][0]}</code> (weight: <strong>${lime[0][1].toFixed(4)}</strong>).`;
            }
        }

        return explanation;
    },

    renderDivergentBarChart(containerId, dataItems, isShap = false) {
        const container = document.getElementById(containerId);
        if (!container) return;

        if (!dataItems || dataItems.length === 0) {
            container.innerHTML = `<div class="empty-state" style="padding: 20px;">No attribution data available.</div>`;
            return;
        }

        // Format items: { label, value }
        let items = [];
        if (Array.isArray(dataItems)) {
            items = dataItems.map(d => ({ label: String(d[0]), value: parseFloat(d[1]) }));
        } else if (typeof dataItems === 'object') {
            items = Object.entries(dataItems).map(([k, v]) => ({ label: String(k), value: parseFloat(v) }));
        }

        // Find max absolute value for symmetric scaling
        let maxAbs = 0.001;
        items.forEach(d => {
            if (Math.abs(d.value) > maxAbs) maxAbs = Math.abs(d.value);
        });

        // Generate clean SVG markup
        const height = Math.max(160, items.length * 32);
        const width = 450;
        const midX = width / 2;
        const maxBarW = (width / 2) - 80;

        let svgHtml = `
            <svg width="100%" height="${height}" viewBox="0 0 ${width} ${height}" style="overflow: visible; font-family: 'JetBrains Mono', monospace; font-size: 11px;">
                <!-- Center Baseline Axis -->
                <line x1="${midX}" y1="10" x2="${midX}" y2="${height - 10}" stroke="#475569" stroke-width="1.5" stroke-dasharray="2,2"></line>
                <text x="${midX - 10}" y="12" fill="#94a3b8" text-anchor="end" font-size="9">← Benign</text>
                <text x="${midX + 10}" y="12" fill="#94a3b8" text-anchor="start" font-size="9">Attack →</text>
        `;

        items.forEach((item, idx) => {
            const y = 26 + (idx * 30);
            const barW = Math.max(2, (Math.abs(item.value) / maxAbs) * maxBarW);
            const isPositive = item.value >= 0;
            const barColor = isPositive ? '#ef4444' : '#10b981';
            const barX = isPositive ? midX : (midX - barW);

            // Clean display label
            const displayLabel = item.label.length > 22 ? item.label.substring(0, 20) + '...' : item.label;

            svgHtml += `
                <g class="xai-bar-group">
                    <!-- Feature Name Label -->
                    <text x="${isPositive ? midX - 8 : midX + 8}" y="${y + 12}" fill="#e2e8f0" 
                          text-anchor="${isPositive ? 'end' : 'start'}" font-size="10.5">
                        ${displayLabel}
                    </text>

                    <!-- Attribution Bar -->
                    <rect x="${barX}" y="${y}" width="${barW}" height="16" rx="3" fill="${barColor}" opacity="0.85">
                        <title>${item.label}: ${item.value > 0 ? '+' : ''}${item.value.toFixed(4)}</title>
                    </rect>

                    <!-- Value Label -->
                    <text x="${isPositive ? barX + barW + 6 : barX - 6}" y="${y + 12}" 
                          fill="${barColor}" text-anchor="${isPositive ? 'start' : 'end'}" font-weight="bold" font-size="10">
                        ${item.value > 0 ? '+' : ''}${item.value.toFixed(3)}
                    </text>
                </g>
            `;
        });

        svgHtml += `</svg>`;
        container.innerHTML = svgHtml;
    }
};

window.XAICharts = XAICharts;

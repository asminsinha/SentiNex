"""
SentiNex SDN Ryu Controller Application with Explainable AI (SHAP / LIME)
Provides Real-Time DL / ML Intrusion Detection, Transparent Explainability, and Automated Mitigation.
"""

import sys
import os
import time
import logging

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
src_dir = os.path.join(BASE_DIR, "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from packet_extractor import PacketFeatureExtractor, LiveFlowTracker
from xai_engine import SentiNexXAIEngine

# Ryu OpenFlow Imports
try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
    from ryu.ofproto import ofproto_v1_3
    from ryu.lib.packet import packet, ethernet, ipv4, tcp, udp, arp, ether_types
    HAS_RYU = True
except ImportError:
    HAS_RYU = False


class SentiNexRyuApp:
    def __init__(self, model_name=None):
        print("\n" + "="*70)
        print("  SentiNex: Explainable AI Intrusion Detection System (SDN Control Plane)")
        print("="*70)
        self.extractor = PacketFeatureExtractor()
        self.flow_tracker = LiveFlowTracker()

        # Select model: 'mlp' (Deep Learning Keras) or 'rf' (Random Forest) / 'xgb'
        selected_model = model_name or os.environ.get("SENTINEX_MODEL", "mlp")
        self.xai = SentiNexXAIEngine(model_name=selected_model)
        self.model_name = self.xai.model_name

        self.blocked_ips = set()
        self.alerted_ips = set()
        print(f"[+] SentiNex Engine Online | Active Backend Model: {self.model_name.upper()}")
        print("[+] Explainability Engines Loaded: LIME & SHAP")
        print("="*70 + "\n")

    def classify_threat_category(self, flow_stats, lime_features):
        """Maps top XAI feature attributions and flow dynamics to threat taxonomies."""
        top_feats = [str(f[0]).lower() for f in lime_features]
        top_feat_str = " ".join(top_feats)

        rate = flow_stats.get('rate', 0.0)
        port_count = flow_stats.get('ct_dst_sport_ltm', 0)
        sbytes = flow_stats.get('sbytes', 0)
        spkts = flow_stats.get('spkts', 0)
        is_syn_burst = flow_stats.get('state', 0) == 1

        # Port Scan Reconnaissance detection (Multiple distinct ports probed)
        if port_count >= 3:
            return "Reconnaissance (Port Scan / Probe)"

        # DoS SYN Flood detection (High rate or concentrated SYN burst to single port)
        if is_syn_burst or (rate > 40.0 and spkts >= 10) or sbytes > 20000 or any(t in top_feat_str for t in ['rate', 'sload', 'sbytes', 'spkts', 'dur']):
            return "Denial of Service (DoS / DDoS SYN Flood)"

        if any(t in top_feat_str for t in ['ct_dst_sport_ltm', 'ct_src_dport_ltm']):
            return "Reconnaissance (Port Scan / Probe)"

        if any(t in top_feat_str for t in ['sttl', 'dttl', 'ct_state_ttl']):
            return "Protocol Spoofing / State Disruption"

        return "Malicious Network Anomaly"

    def process_packet(self, src_ip, dst_ip, ip_pkt, tcp_pkt=None, udp_pkt=None, pkt_len=64):
        """Full IDS Pipeline: Flow Tracking -> Feature Extraction -> ML/DL Inference -> XAI Attribution."""
        if src_ip in self.blocked_ips:
            return {
                'is_malicious': True,
                'threat_type': "Blocked Entity (Active Flow Rule)",
                'probability': 1.0,
                'lime_explanations': [],
                'shap_scores': {},
                'already_blocked': True
            }

        # Step 1: Update flow tracker and extract 42 features
        flow_stats = self.flow_tracker.update_packet(src_ip, dst_ip, ip_pkt, tcp_pkt, udp_pkt, pkt_len)
        feature_vector = self.extractor.extract_features_from_dict(flow_stats)

        # Step 2: Model Inference (Probability of Attack)
        prob = self.xai.predict_probability(feature_vector)

        # Attack decision based on ML model probability or confirmed attack patterns
        spkts = flow_stats.get('spkts', 0)
        rate = flow_stats.get('rate', 0.0)
        port_count = flow_stats.get('ct_dst_sport_ltm', 0)
        is_syn_flood = flow_stats.get('state', 0) == 1 and spkts >= 8
        is_port_scan = port_count >= 4 and spkts >= 4

        is_attack = (prob >= 0.50 and spkts >= 5) or is_syn_flood or is_port_scan

        if is_attack:
            # Step 3: Fast Local Explanation via LIME
            lime_exp = self.xai.explain_instance_lime(feature_vector, num_features=5, num_samples=120)

            # Step 4: Global Feature Attribution via SHAP
            shap_dict = self.xai.explain_instance_shap(feature_vector)
            top_shap = dict(list(shap_dict.items())[:5])

            # Step 5: Threat Categorization
            threat_cat = self.classify_threat_category(flow_stats, lime_exp)
            self.blocked_ips.add(src_ip)

            return {
                'is_malicious': True,
                'threat_type': threat_cat,
                'probability': float(prob),
                'lime_explanations': lime_exp,
                'shap_scores': top_shap,
                'flow_stats': flow_stats,
                'already_blocked': False
            }

        return {
            'is_malicious': False,
            'threat_type': "Benign Normal Traffic",
            'probability': float(prob),
            'lime_explanations': [],
            'shap_scores': {},
            'flow_stats': flow_stats,
            'already_blocked': False
        }


# Ryu OpenFlow 1.3 Controller
if HAS_RYU:
    class SentiNexRyuController(app_manager.RyuApp):
        OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

        def __init__(self, *args, **kwargs):
            super(SentiNexRyuController, self).__init__(*args, **kwargs)
            self.sentinex_engine = SentiNexRyuApp()
            self.mac_to_port = {}
            self.datapaths = {}

        @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
        def switch_features_handler(self, ev):
            datapath = ev.msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            dpid = datapath.id
            self.datapaths[dpid] = datapath

            # 1. CRITICAL: Clear all old/stale flow rules from switch table
            del_flows = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY
            )
            datapath.send_msg(del_flows)

            # 2. Install Table-Miss flow rule: Send unmatched packets to Ryu Controller
            match = parser.OFPMatch()
            actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
            inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
            mod = parser.OFPFlowMod(datapath=datapath, priority=0, match=match, instructions=inst)
            datapath.send_msg(mod)

            self.logger.info(f"[+] Switch s{dpid} Connected: Flow table flushed & Table-Miss rule installed.")

        def block_ip_on_all_switches(self, src_ip):
            """Installs high-priority hard DROP rules across all active SDN switches."""
            for dpid, dp in self.datapaths.items():
                ofproto = dp.ofproto
                parser = dp.ofproto_parser
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip)
                actions = []  # Empty actions = DROP
                inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
                mod = parser.OFPFlowMod(
                    datapath=dp,
                    priority=100,
                    match=match,
                    instructions=inst,
                    idle_timeout=300,
                    hard_timeout=600
                )
                dp.send_msg(mod)
            self.logger.info(f"[DYNAMIC MITIGATION] Hard DROP rule (Priority 100) installed for IP {src_ip} on all switches.")

        @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
        def _packet_in_handler(self, ev):
            msg = ev.msg
            datapath = msg.datapath
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            in_port = msg.match['in_port']
            dpid = datapath.id

            if not msg.data:
                return

            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocols(ethernet.ethernet)[0]

            # Ignore LLDP
            if eth.ethertype == ether_types.ETH_TYPE_LLDP:
                return

            dst = eth.dst
            src = eth.src

            self.mac_to_port.setdefault(dpid, {})
            self.mac_to_port[dpid][src] = in_port

            # Handle ARP packets: Forward transparently so hosts resolve MACs
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt:
                out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
                actions = [parser.OFPActionOutput(out_port)]
                data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                return

            # Handle IPv4 Traffic through SentiNex IDS & XAI Pipeline
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            if ip_pkt:
                src_ip = ip_pkt.src
                dst_ip = ip_pkt.dst
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                udp_pkt = pkt.get_protocol(udp.udp)
                pkt_len = len(msg.data)

                # Process through SentiNex Engine
                res = self.sentinex_engine.process_packet(
                    src_ip, dst_ip, ip_pkt, tcp_pkt, udp_pkt, pkt_len
                )

                if res['is_malicious']:
                    if not res['already_blocked']:
                        rate_val = res['flow_stats'].get('rate', 0.0)
                        spkts_val = res['flow_stats'].get('spkts', 0)

                        alert_lines = [
                            "",
                            "="*75,
                            f" [!] SECURITY ALERT: INTRUSION DETECTED ON SWITCH s{dpid}",
                            "="*75,
                            f" Attacker IP       : {src_ip}",
                            f" Victim IP         : {dst_ip}",
                            f" Threat Category   : {res['threat_type']}",
                            f" Model Confidence  : {res['probability']:.2%} (Backend: {self.sentinex_engine.model_name.upper()})",
                            f" Flow Metrics      : Rate={rate_val:.1f} pkts/s | Packets={spkts_val} | TTL={ip_pkt.ttl}",
                            "-"*75,
                            " [XAI] Local Feature Attributions (LIME):"
                        ]
                        for feat, weight in res['lime_explanations']:
                            indicator = "+" if weight > 0 else "-"
                            alert_lines.append(f"   * {feat:<30} : {weight:+.4f} (supports attack: {indicator})")
                        alert_lines.append("-"*75)
                        alert_lines.append(" [XAI] Global Top Feature Impacts (SHAP):")
                        for feat, val in res['shap_scores'].items():
                            alert_lines.append(f"   * {feat:<30} : {val:+.4f}")
                        alert_lines.append("-"*75)
                        alert_lines.append(f" [ACTION] Dynamic SDN Mitigation: Dropping attack packets & pushing switch block rule.")
                        alert_lines.append("="*75)
                        alert_lines.append("")

                        full_alert = "\n".join(alert_lines)
                        self.logger.info(full_alert)
                        sys.stdout.flush()

                        # Install dynamic drop rule on all switches
                        self.block_ip_on_all_switches(src_ip)

                    # Drop this malicious packet immediately
                    return

                # Normal Benign Traffic: Forward packet
                out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
                actions = [parser.OFPActionOutput(out_port)]
                data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions, data=data)
                datapath.send_msg(out)
                return

            # Default Forwarding for other packet types
            out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
            actions = [parser.OFPActionOutput(out_port)]
            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                      in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)


if __name__ == "__main__":
    app = SentiNexRyuApp()
    print("[*] SentiNex Standalone Engine Test Complete!")
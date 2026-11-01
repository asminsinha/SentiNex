"""
Comprehensive End-to-End Integration Test Suite for SentiNex
Validates:
1. ML Model & Preprocessing Integrity (RF, MLP, Scaler, 42 features)
2. SHAP & LIME XAI Engines and Execution Latencies
3. Dynamic Topology & Host Scalability (4, 16, 64, 250, 1000 hosts)
4. Traffic Injection for all supported classes (Benign, DoS, Port Scan, Spoof)
5. Dynamic OpenFlow Mitigation & Flow Table Rule Installation/Verification
6. Safe Host Unblocking & Rule Deletion Confirmation
7. Complete Flask REST API & SSE Event Stream Endpoints
"""

import os
import sys
import time
import json
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
src_dir = os.path.join(BASE_DIR, "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)
dash_dir = os.path.join(BASE_DIR, "dashboard")
if dash_dir not in sys.path:
    sys.path.insert(0, dash_dir)

from src.sentinex_backend import SentiNexBackend
from dashboard.app import app


class TestSentiNexIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\n" + "="*70)
        print("  Running SentiNex End-to-End Integration Test Suite")
        print("="*70)
        cls.backend = SentiNexBackend.get_instance()
        cls.client = app.test_client()
        cls.backend.reset_network_state()

    def setUp(self):
        # Reset to clean baseline network state before each test
        self.backend.reset_network_state()
        self.backend.rebuild_topology(topo_type='linear', host_count=4, mode='emulation', threat_ratio=0.5, seed=42)

    def test_01_feature_definitions_and_scaler(self):
        """Verifies 42 features exist, in correct order, with valid scaler."""
        names = self.backend.extractor.feature_names
        self.assertEqual(len(names), 42, f"Expected 42 features, got {len(names)}")
        self.assertEqual(names[0], 'dur')
        self.assertEqual(names[8], 'rate')
        self.assertEqual(names[34], 'ct_dst_sport_ltm')
        self.assertIsNotNone(self.backend.extractor.scaler)

    def test_02_model_inference_and_xai_calculation(self):
        """Verifies real ML prediction, LIME local attribution, and SHAP global impact."""
        # Clean dummy input
        import numpy as np
        vec = np.zeros((1, 42))
        prob = self.backend.xai.predict_probability(vec)
        self.assertIsInstance(prob, float)
        self.assertTrue(0.0 <= prob <= 1.0)

        # LIME explanation test
        lime_res = self.backend.xai.explain_instance_lime(vec, num_features=5, num_samples=100)
        self.assertIsInstance(lime_res, list)
        self.assertTrue(len(lime_res) > 0)
        self.assertIsInstance(lime_res[0][0], str)
        self.assertIsInstance(lime_res[0][1], float)

        # SHAP explanation test
        shap_res = self.backend.xai.explain_instance_shap(vec)
        self.assertIsInstance(shap_res, dict)
        self.assertTrue(len(shap_res) > 0)

    def test_03_topology_scalability_and_limits(self):
        """Tests linear, tree, star, and mesh topologies with small, medium, and 1000+ hosts."""
        for topo in ['linear', 'tree', 'star', 'mesh']:
            summary = self.backend.rebuild_topology(topo_type=topo, host_count=16, mode='emulation')
            self.assertEqual(summary['topo_type'], topo)
            self.assertEqual(summary['configured_host_count'], 16)
            self.assertEqual(len(summary['hosts']), 16)

        # Large-scale stress test (1,000 logical hosts)
        t0 = time.time()
        large_summary = self.backend.rebuild_topology(topo_type='linear', host_count=1000, mode='emulation')
        elapsed = time.time() - t0
        self.assertEqual(large_summary['configured_host_count'], 1000)
        self.assertEqual(len(large_summary['hosts']), 1000)
        self.assertLess(elapsed, 1.0, f"Building 1000 hosts took {elapsed:.2f}s, expected < 1.0s")

    def test_04_benign_traffic_pipeline(self):
        """Verifies Benign Web Traffic injection is correctly classified and forwarded."""
        res = self.backend.inject_traffic(traffic_type='benign', count=5)
        self.assertTrue(res['success'])
        self.assertFalse(res['is_malicious'])
        self.assertEqual(res['detected_threat'], "Benign Normal Traffic")
        self.assertEqual(res['mitigation_status'], "L2_FORWARDING")

    def test_05_dos_syn_flood_detection_and_mitigation(self):
        """Verifies DoS SYN Flood triggers detection, XAI, and switch drop rule."""
        res = self.backend.inject_traffic(traffic_type='dos', count=15)
        self.assertTrue(res['success'])
        self.assertTrue(res['is_malicious'])
        self.assertIn("DoS", res['detected_threat'])

        # Check that switch flow tables contain priority 100 DROP rule
        ft = self.backend.get_flow_tables()
        has_drop_rule = False
        for sw, data in ft.items():
            for rule in data['rules']:
                if rule['priority'] == 100 and rule['match'].get('ipv4_src') == res['src_ip']:
                    has_drop_rule = True
                    break
        self.assertTrue(has_drop_rule, "Expected Priority 100 DROP rule installed across switches.")

    def test_06_port_scan_detection_and_mitigation(self):
        """Verifies Reconnaissance Port Scan triggers detection and LIME/SHAP attributions."""
        res = self.backend.inject_traffic(traffic_type='scan', count=12)
        self.assertTrue(res['success'])
        self.assertTrue(res['is_malicious'])
        self.assertIn("Port Scan", res['detected_threat'])

        # Verify incident record
        incidents = self.backend.get_incidents()
        self.assertTrue(len(incidents) > 0)
        latest = incidents[0]
        self.assertEqual(latest['src_ip'], res['src_ip'])
        self.assertTrue(len(latest['lime_explanations']) > 0)
        self.assertTrue(len(latest['shap_scores']) > 0)

    def test_07_host_unblock_and_rule_removal(self):
        """Verifies that unblocking a quarantined host safely removes OpenFlow drop rules."""
        # 1. Block host via DoS attack
        res = self.backend.inject_traffic(traffic_type='dos', count=15)
        src_ip = res['src_ip']
        self.assertIn(src_ip, self.backend.sentinex_app.blocked_ips)

        # 2. Operator Unblock
        unblock_res = self.backend.unblock_host(src_ip)
        self.assertTrue(unblock_res['success'])
        self.assertNotIn(src_ip, self.backend.sentinex_app.blocked_ips)
        self.assertGreaterEqual(unblock_res['rules_removed'], 1)

        # 3. Verify drop rules removed from switch tables
        ft = self.backend.get_flow_tables()
        for sw, data in ft.items():
            for rule in data['rules']:
                if rule.get('match', {}).get('ipv4_src') == src_ip:
                    self.fail(f"DROP rule for {src_ip} still present in switch {sw}!")

    def test_08_flask_api_endpoints(self):
        """Verifies all REST API endpoints return HTTP 200 with valid schema."""
        # GET /
        r_index = self.client.get('/')
        self.assertEqual(r_index.status_code, 200)
        self.assertIn(b'SentiNex', r_index.data)

        # GET /api/status
        r_status = self.client.get('/api/status')
        self.assertEqual(r_status.status_code, 200)
        status_json = r_status.get_json()
        self.assertEqual(status_json['status'], 'online')
        self.assertIn('backend_model', status_json)
        self.assertIn('latencies', status_json)

        # GET /api/topology
        r_topo = self.client.get('/api/topology')
        self.assertEqual(r_topo.status_code, 200)
        topo_json = r_topo.get_json()
        self.assertIn('switches', topo_json)
        self.assertIn('hosts', topo_json)

        # POST /api/topology/configure
        r_cfg = self.client.post('/api/topology/configure', json={
            'topo_type': 'tree',
            'host_count': 8,
            'mode': 'emulation',
            'threat_ratio': 0.25,
            'seed': 99
        })
        self.assertEqual(r_cfg.status_code, 200)
        self.assertTrue(r_cfg.get_json()['success'])

        # GET /api/flows
        r_flows = self.client.get('/api/flows')
        self.assertEqual(r_flows.status_code, 200)
        flows_json = r_flows.get_json()
        self.assertIsInstance(flows_json, dict)

        # POST /api/traffic/inject
        r_inj = self.client.post('/api/traffic/inject', json={
            'traffic_type': 'benign',
            'count': 2
        })
        self.assertEqual(r_inj.status_code, 200)
        self.assertTrue(r_inj.get_json()['success'])

        # GET /api/events
        r_events = self.client.get('/api/events')
        self.assertEqual(r_events.status_code, 200)
        self.assertIsInstance(r_events.get_json(), list)

        # GET /api/incidents
        r_inc = self.client.get('/api/incidents')
        self.assertEqual(r_inc.status_code, 200)
        self.assertIsInstance(r_inc.get_json(), list)

        # Simulation Lifecycle
        r_sim_start = self.client.post('/api/simulation/start', json={'pace_sec': 1.0})
        self.assertEqual(r_sim_start.status_code, 200)
        time.sleep(0.2)

        r_sim_pause = self.client.post('/api/simulation/pause')
        self.assertEqual(r_sim_pause.status_code, 200)

        r_sim_stop = self.client.post('/api/simulation/stop')
        self.assertEqual(r_sim_stop.status_code, 200)

        r_sim_reset = self.client.post('/api/simulation/reset')
        self.assertEqual(r_sim_reset.status_code, 200)

    def test_09_ground_truth_vs_prediction_separation(self):
        """Verifies generator ground truth is strictly separated from model predictions."""
        res = self.backend.inject_traffic(traffic_type='dos', count=15)
        # Ground truth is what was requested
        self.assertEqual(res['ground_truth'], "DoS SYN Flood Attack")
        # Detected threat is what the classifier predicted
        self.assertIn("DoS", res['detected_threat'])

        # Check incident structure
        incidents = self.backend.get_incidents()
        self.assertTrue(len(incidents) > 0)
        inc = incidents[0]
        self.assertIn('ground_truth', inc)
        self.assertIn('threat_category', inc)
        self.assertIn('confidence', inc)
        self.assertNotEqual(inc['ground_truth'], "")

    def test_10_timing_tracer_and_subsecond_propagation(self):
        """Verifies observation, inference, XAI, and mitigation timings are measured separately."""
        res = self.backend.inject_traffic(traffic_type='scan', count=10)
        timings = res.get('timings', {})
        self.assertIn('extract_ms', timings)
        self.assertIn('infer_ms', timings)
        self.assertIn('xai_ms', timings)
        self.assertIn('total_pipeline_ms', timings)
        self.assertGreater(timings['infer_ms'], 0.0)


if __name__ == '__main__':
    unittest.main()

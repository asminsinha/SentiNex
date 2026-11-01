"""
SentiNex Web Dashboard & SDN Operations Control Center
Flask backend exposing real REST endpoints and Server-Sent Events (SSE)
bridged directly to the SentiNex detection and XAI engine.
"""

import os
import sys
import time
import json
import queue
from datetime import datetime
from flask import Flask, render_template, jsonify, request, Response

# Ensure project root and src are on sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)
src_dir = os.path.join(BASE_DIR, "src")
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from sentinex_backend import SentiNexBackend

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "dashboard", "templates"),
    static_folder=os.path.join(BASE_DIR, "dashboard", "static")
)

# Acquire singleton backend instance
backend = SentiNexBackend.get_instance()


@app.route('/')
def index():
    """Serves the SentiNex SDN Operations Multi-Page Application."""
    return render_template('index.html')


# ============================================================================
# REST API Endpoints
# ============================================================================

@app.route('/api/status', methods=['GET'])
def get_status():
    """Returns application health, controller status, telemetry and latencies."""
    try:
        data = backend.get_status_summary()
        return jsonify(data)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/topology', methods=['GET'])
def get_topology():
    """Returns the current active topology (switches, hosts, links, mode)."""
    try:
        data = backend.get_topology_summary()
        return jsonify(data)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/model/select', methods=['POST'])
def select_model():
    """Dynamically switches active model between 'rf' and 'mlp'."""
    try:
        body = request.get_json() or {}
        model_name = body.get('model', 'rf')
        res = backend.set_model(model_name)
        return jsonify(res)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400


@app.route('/api/topology/configure', methods=['POST'])
def configure_topology():
    """Reconfigures topology type, host count, execution mode, threat ratio, seed."""
    try:
        body = request.get_json() or {}
        topo_type = body.get('topo_type', 'linear')
        host_count = int(body.get('host_count', 4))
        mode = body.get('mode', 'emulation')
        threat_ratio = float(body.get('threat_ratio', 0.5))
        seed = int(body.get('seed', 42))

        summary = backend.rebuild_topology(
            topo_type=topo_type,
            host_count=host_count,
            mode=mode,
            threat_ratio=threat_ratio,
            seed=seed
        )
        return jsonify({'success': True, 'topology': summary})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400


@app.route('/api/flows', methods=['GET'])
def get_flows():
    """Returns active OpenFlow 1.3 switch flow tables."""
    try:
        flows = backend.get_flow_tables()
        return jsonify(flows)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/events', methods=['GET'])
def get_events():
    """Returns recent structured event history."""
    try:
        limit = int(request.args.get('limit', 100))
        events = backend.get_events(limit=limit)
        return jsonify(events)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/incidents', methods=['GET'])
def get_incidents():
    """Returns recent threat incident audit records."""
    try:
        limit = int(request.args.get('limit', 50))
        incidents = backend.get_incidents(limit=limit)
        return jsonify(incidents)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/api/incidents/<incident_id>', methods=['GET'])
def get_incident(incident_id):
    """Returns deep-dive incident detail (SHAP, LIME, flow features, mitigation)."""
    try:
        inc = backend.get_incident_by_id(incident_id)
        if inc:
            return jsonify(inc)
        return jsonify({'error': 'Incident not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/traffic/inject', methods=['POST'])
def inject_traffic():
    """Manual traffic injection endpoint."""
    try:
        body = request.get_json() or {}
        traffic_type = body.get('traffic_type', 'benign')
        src_host = body.get('src_host')
        target_host = body.get('target_host')
        count = int(body.get('count', 10))
        delay = float(body.get('delay', 0.01))

        res = backend.inject_traffic(
            traffic_type=traffic_type,
            src_host=src_host,
            target_host=target_host,
            count=count,
            delay=delay
        )
        return jsonify(res)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400


@app.route('/api/simulation/start', methods=['POST'])
def start_simulation():
    """Starts the automated background simulation."""
    try:
        body = request.get_json() or {}
        pace_sec = float(body.get('pace_sec', 2.0))
        seed = body.get('seed')
        res = backend.start_automated_simulation(pace_sec=pace_sec, seed=seed)
        return jsonify(res)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400


@app.route('/api/simulation/pause', methods=['POST'])
def pause_simulation():
    """Pauses the automated simulation."""
    try:
        res = backend.pause_automated_simulation()
        return jsonify(res)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400


@app.route('/api/simulation/stop', methods=['POST'])
def stop_simulation():
    """Stops the automated simulation and returns to manual mode."""
    try:
        res = backend.stop_automated_simulation()
        return jsonify(res)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 400


@app.route('/api/simulation/reset', methods=['POST'])
def reset_simulation():
    """Resets network state, clears flow drop rules, resets telemetry."""
    try:
        res = backend.reset_network_state()
        return jsonify(res)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


@app.route('/api/mitigation/unblock', methods=['POST'])
def unblock_host():
    """Operator action: Unblocks a quarantined host and removes switch drop rules."""
    try:
        body = request.get_json() or {}
        host_or_ip = body.get('host_or_ip')
        if not host_or_ip:
            return jsonify({'success': False, 'message': 'host_or_ip required'}), 400

        res = backend.unblock_host(host_or_ip)
        return jsonify(res)
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# ============================================================================
# Server-Sent Events (SSE) Stream
# ============================================================================

@app.route('/api/stream')
def sse_stream():
    """
    Sub-second real-time event stream.
    Pushes observation, inference, XAI, mitigation, and topology changes.
    """
    client_queue = backend.register_sse_client()

    def event_generator():
        # Emit initial greeting and ping
        yield f"event: connected\ndata: {json.dumps({'message': 'SSE Connected to SentiNex Control Plane', 'time': time.time()})}\n\n"
        try:
            while True:
                try:
                    event = client_queue.get(timeout=15.0)
                    yield f"event: {event.get('type', 'message')}\ndata: {json.dumps(event)}\n\n"
                except queue.Empty:
                    # Keep-alive heartbeat
                    yield f"event: ping\ndata: {json.dumps({'time': time.time()})}\n\n"
        except GeneratorExit:
            backend.unregister_sse_client(client_queue)
        except Exception as e:
            backend.unregister_sse_client(client_queue)

    return Response(
        event_generator(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive',
            'Access-Control-Allow-Origin': '*'
        }
    )


if __name__ == '__main__':
    port = int(os.environ.get("SENTINEX_PORT", 5000))
    print(f"\n[+] SentiNex SDN Operations Web Server Starting on http://127.0.0.1:{port}")
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)

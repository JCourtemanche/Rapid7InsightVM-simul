"""
Scan endpoints (top-level, not under a site).
  GET  /api/3/scans                 - nexpose-get-scans
  GET  /api/3/scans/<id>            - nexpose-get-scan
  POST /api/3/scans/<id>/stop       - nexpose-stop-scan
  POST /api/3/scans/<id>/pause      - nexpose-pause-scan
  POST /api/3/scans/<id>/resume     - nexpose-resume-scan
  POST /api/3/scans                 - nexpose-start-assets-scan (body: {name, hosts})
Also serves /scan_engines.
"""
from flask import Blueprint, jsonify, request

from auth import require_basic_auth
from generators.base import page_envelope
from generators.catalog import ENGINES, SCAN_STORE

from ._helpers import get_pagination


scans_bp = Blueprint('scans', __name__, url_prefix='/api/3')


@scans_bp.route('/scans', methods=['GET'])
@require_basic_auth
def list_scans():
    page, size = get_pagination()
    return jsonify(page_envelope(SCAN_STORE.all(), page, size, '/api/3/scans')), 200


@scans_bp.route('/scans/<int:scan_id>', methods=['GET'])
@require_basic_auth
def get_scan(scan_id):
    scan = SCAN_STORE.get(scan_id)
    if scan is None:
        return jsonify({'status': 404, 'message': f'Scan {scan_id} not found'}), 404
    return jsonify(scan), 200


@scans_bp.route('/scans', methods=['POST'])
@require_basic_auth
def start_scan():
    body = request.get_json(silent=True) or {}
    hosts = body.get('hosts') or []
    scan = SCAN_STORE.create(
        site_id=body.get('siteId') or 1,
        name=body.get('name') or 'Assets scan',
        asset_ids=hosts,
    )
    return jsonify(scan), 201


@scans_bp.route('/scans/<int:scan_id>/stop', methods=['POST'])
@require_basic_auth
def stop_scan(scan_id):
    scan = SCAN_STORE.stop(scan_id)
    if scan is None:
        return jsonify({'status': 404, 'message': f'Scan {scan_id} not found'}), 404
    return jsonify(scan), 200


@scans_bp.route('/scans/<int:scan_id>/pause', methods=['POST'])
@require_basic_auth
def pause_scan(scan_id):
    scan = SCAN_STORE.pause(scan_id)
    if scan is None:
        return jsonify({'status': 404, 'message': f'Scan {scan_id} not found'}), 404
    return jsonify(scan), 200


@scans_bp.route('/scans/<int:scan_id>/resume', methods=['POST'])
@require_basic_auth
def resume_scan(scan_id):
    scan = SCAN_STORE.resume(scan_id)
    if scan is None:
        return jsonify({'status': 404, 'message': f'Scan {scan_id} not found'}), 404
    return jsonify(scan), 200


@scans_bp.route('/scan_engines', methods=['GET'])
@require_basic_auth
def list_scan_engines():
    page, size = get_pagination()
    return jsonify(page_envelope(ENGINES, page, size, '/api/3/scan_engines')), 200

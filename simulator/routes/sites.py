"""
Site endpoints under /api/3/sites.
  GET/POST/DELETE /sites, /sites/<id>
  GET/POST /sites/<id>/assets
  GET/POST /sites/<id>/scans
  GET/POST /sites/<id>/site_credentials + PUT/DELETE /site_credentials/<cid>
  POST /sites/<id>/shared_credentials
  PUT /sites/<id>/shared_credentials/<cid>/enabled
  GET/POST /sites/<id>/scan_schedules + PUT/DELETE /scan_schedules/<sid>
  GET/POST/DELETE /sites/<id>/included_targets and /excluded_targets and /*_asset_groups
"""
from flask import Blueprint, jsonify, request

from auth import require_basic_auth
from generators.assets import asset_summary
from generators.base import created_response, iso_z, page_envelope
from generators.catalog import ASSETS, SITES, SITES_BY_ID, SCAN_STORE, assets_in_site

from ._helpers import get_pagination


sites_bp = Blueprint('sites', __name__, url_prefix='/api/3/sites')


# ---------------------------------------------------------------------------
# /sites and /sites/<id>
# ---------------------------------------------------------------------------

@sites_bp.route('', methods=['GET'])
@require_basic_auth
def list_sites():
    page, size = get_pagination()
    return jsonify(page_envelope(SITES, page, size, '/api/3/sites')), 200


@sites_bp.route('', methods=['POST'])
@require_basic_auth
def create_site():
    body = request.get_json(silent=True) or {}
    new_id = max((s['id'] for s in SITES), default=0) + 1
    SITES.append({
        'id': new_id,
        'name': body.get('name') or f'Site {new_id}',
        'description': body.get('description') or '',
        'type': body.get('type') or 'static',
        'importance': body.get('importance') or 'normal',
        'riskScore': 0.0,
        'assets': 0,
        'vulnerabilities': {'critical': 0, 'severe': 0, 'moderate': 0, 'total': 0},
        'scanTemplate': body.get('scanTemplate') or 'full-audit',
        'scanEngine': body.get('engineId') or 1,
        'lastScanTime': None,
        'connectionType': 'authenticated',
        'links': [{'href': f'/api/3/sites/{new_id}', 'rel': 'self'}],
    })
    SITES_BY_ID[new_id] = SITES[-1]
    return jsonify(created_response(new_id)), 201


@sites_bp.route('/<int:site_id>', methods=['GET'])
@require_basic_auth
def get_site(site_id):
    s = SITES_BY_ID.get(site_id)
    if s is None:
        return jsonify({'status': 404, 'message': f'Site {site_id} not found'}), 404
    return jsonify(s), 200


@sites_bp.route('/<int:site_id>', methods=['DELETE'])
@require_basic_auth
def delete_site(site_id):
    s = SITES_BY_ID.pop(site_id, None)
    if s is None:
        return jsonify({'status': 404, 'message': f'Site {site_id} not found'}), 404
    SITES.remove(s)
    return jsonify({'status': 200, 'message': f'Site {site_id} deleted'}), 200


# ---------------------------------------------------------------------------
# /sites/<id>/assets
# ---------------------------------------------------------------------------

@sites_bp.route('/<int:site_id>/assets', methods=['GET'])
@require_basic_auth
def list_site_assets(site_id):
    if site_id not in SITES_BY_ID:
        return jsonify({'status': 404, 'message': f'Site {site_id} not found'}), 404
    items = [asset_summary(a) for a in assets_in_site(site_id)]
    page, size = get_pagination()
    return jsonify(page_envelope(items, page, size, f'/api/3/sites/{site_id}/assets')), 200


@sites_bp.route('/<int:site_id>/assets', methods=['POST'])
@require_basic_auth
def create_site_asset(site_id):
    body = request.get_json(silent=True) or {}
    new_id = max((a['id'] for a in ASSETS), default=0) + 1
    return jsonify({
        'id': new_id,
        'ip': body.get('ip') or '10.10.10.10',
        'hostName': body.get('hostName') or f'asset-{new_id}',
        'links': [{'href': f'/api/3/assets/{new_id}', 'rel': 'self'}],
    }), 201


# ---------------------------------------------------------------------------
# /sites/<id>/scans (list + start)
# ---------------------------------------------------------------------------

@sites_bp.route('/<int:site_id>/scans', methods=['GET'])
@require_basic_auth
def list_site_scans(site_id):
    items = SCAN_STORE.for_site(site_id)
    page, size = get_pagination()
    return jsonify(page_envelope(items, page, size, f'/api/3/sites/{site_id}/scans')), 200


@sites_bp.route('/<int:site_id>/scans', methods=['POST'])
@require_basic_auth
def start_site_scan(site_id):
    body = request.get_json(silent=True) or {}
    scan = SCAN_STORE.create(
        site_id=site_id,
        name=body.get('name') or f'Ad-hoc scan on site {site_id}',
        asset_ids=body.get('hosts') or [],
    )
    return jsonify(scan), 201


# ---------------------------------------------------------------------------
# /sites/<id>/site_credentials (list + create + update + delete)
# ---------------------------------------------------------------------------

_SITE_CREDS_STORE: dict[int, list] = {}
_NEXT_SITE_CRED_ID = 800


@sites_bp.route('/<int:site_id>/site_credentials', methods=['GET'])
@require_basic_auth
def list_site_credentials(site_id):
    items = _SITE_CREDS_STORE.get(site_id, [])
    page, size = get_pagination()
    return jsonify(page_envelope(items, page, size, f'/api/3/sites/{site_id}/site_credentials')), 200


@sites_bp.route('/<int:site_id>/site_credentials', methods=['POST'])
@require_basic_auth
def create_site_credential(site_id):
    global _NEXT_SITE_CRED_ID
    body = request.get_json(silent=True) or {}
    _NEXT_SITE_CRED_ID += 1
    cid = _NEXT_SITE_CRED_ID
    cred = {
        'id': cid,
        'name': body.get('name') or f'Site {site_id} cred {cid}',
        'description': body.get('description') or '',
        'account': body.get('account') or {'service': 'ssh', 'username': 'ubuntu'},
        'enabled': True,
        'links': [{'href': f'/api/3/sites/{site_id}/site_credentials/{cid}', 'rel': 'self'}],
    }
    _SITE_CREDS_STORE.setdefault(site_id, []).append(cred)
    return jsonify(created_response(cid)), 201


@sites_bp.route('/<int:site_id>/site_credentials/<int:cred_id>', methods=['PUT'])
@require_basic_auth
def update_site_credential(site_id, cred_id):
    creds = _SITE_CREDS_STORE.get(site_id, [])
    cred = next((c for c in creds if c['id'] == cred_id), None)
    if cred is None:
        return jsonify({'status': 404, 'message': f'Site credential {cred_id} not found'}), 404
    cred.update(request.get_json(silent=True) or {})
    return jsonify({'status': 200, 'message': 'Site credential updated'}), 200


@sites_bp.route('/<int:site_id>/site_credentials/<int:cred_id>', methods=['DELETE'])
@require_basic_auth
def delete_site_credential(site_id, cred_id):
    creds = _SITE_CREDS_STORE.get(site_id, [])
    before = len(creds)
    _SITE_CREDS_STORE[site_id] = [c for c in creds if c['id'] != cred_id]
    if len(_SITE_CREDS_STORE[site_id]) == before:
        return jsonify({'status': 404, 'message': f'Site credential {cred_id} not found'}), 404
    return jsonify({'status': 200, 'message': 'Site credential deleted'}), 200


# ---------------------------------------------------------------------------
# /sites/<id>/shared_credentials
# ---------------------------------------------------------------------------

@sites_bp.route('/<int:site_id>/shared_credentials', methods=['POST'])
@require_basic_auth
def assign_shared_credential(site_id):
    body = request.get_json(silent=True) or []
    if not isinstance(body, list):
        body = [body]
    return jsonify({'status': 200, 'message': f'Assigned {len(body)} shared credentials to site {site_id}'}), 200


@sites_bp.route('/<int:site_id>/shared_credentials/<int:shared_id>/enabled', methods=['PUT'])
@require_basic_auth
def enable_shared_credential(site_id, shared_id):
    return jsonify({
        'status': 200,
        'message': f'Shared credential {shared_id} enabled/disabled on site {site_id}',
    }), 200


# ---------------------------------------------------------------------------
# /sites/<id>/scan_schedules (list + create + update + delete)
# ---------------------------------------------------------------------------

_SCHEDULES_STORE: dict[int, list] = {}
_NEXT_SCHEDULE_ID = 700


@sites_bp.route('/<int:site_id>/scan_schedules', methods=['GET'])
@require_basic_auth
def list_scan_schedules(site_id):
    items = _SCHEDULES_STORE.get(site_id, [])
    page, size = get_pagination()
    return jsonify(page_envelope(items, page, size, f'/api/3/sites/{site_id}/scan_schedules')), 200


@sites_bp.route('/<int:site_id>/scan_schedules', methods=['POST'])
@require_basic_auth
def create_scan_schedule(site_id):
    global _NEXT_SCHEDULE_ID
    body = request.get_json(silent=True) or {}
    _NEXT_SCHEDULE_ID += 1
    sched = {
        'id': _NEXT_SCHEDULE_ID,
        'enabled': body.get('enabled', True),
        'start': body.get('start') or iso_z(),
        'duration': body.get('duration') or 'PT2H',
        'repeat': body.get('repeat') or {'every': 'week', 'interval': 1, 'dayOfWeek': 'monday'},
        'onScanRepeat': body.get('onScanRepeat') or 'restart-scan',
        'links': [{'href': f'/api/3/sites/{site_id}/scan_schedules/{_NEXT_SCHEDULE_ID}', 'rel': 'self'}],
    }
    _SCHEDULES_STORE.setdefault(site_id, []).append(sched)
    return jsonify(created_response(_NEXT_SCHEDULE_ID)), 201


@sites_bp.route('/<int:site_id>/scan_schedules/<int:sched_id>', methods=['PUT'])
@require_basic_auth
def update_scan_schedule(site_id, sched_id):
    schedules = _SCHEDULES_STORE.get(site_id, [])
    sched = next((s for s in schedules if s['id'] == sched_id), None)
    if sched is None:
        return jsonify({'status': 404, 'message': f'Scan schedule {sched_id} not found'}), 404
    sched.update(request.get_json(silent=True) or {})
    return jsonify({'status': 200, 'message': 'Scan schedule updated'}), 200


@sites_bp.route('/<int:site_id>/scan_schedules/<int:sched_id>', methods=['DELETE'])
@require_basic_auth
def delete_scan_schedule(site_id, sched_id):
    schedules = _SCHEDULES_STORE.get(site_id, [])
    before = len(schedules)
    _SCHEDULES_STORE[site_id] = [s for s in schedules if s['id'] != sched_id]
    if len(_SCHEDULES_STORE[site_id]) == before:
        return jsonify({'status': 404, 'message': f'Scan schedule {sched_id} not found'}), 404
    return jsonify({'status': 200, 'message': 'Scan schedule deleted'}), 200


# ---------------------------------------------------------------------------
# Included / excluded targets and asset groups (list + add + remove)
# ---------------------------------------------------------------------------

_INCLUDED_TARGETS: dict[int, list] = {}
_EXCLUDED_TARGETS: dict[int, list] = {}
_INCLUDED_GROUPS: dict[int, list] = {}
_EXCLUDED_GROUPS: dict[int, list] = {}


def _targets_endpoint(store, key, site_id, method, resource):
    if method == 'GET':
        items = [{'address': t} for t in store.get(site_id, [])]
        page, size = get_pagination()
        return jsonify(page_envelope(items, page, size, f'/api/3/sites/{site_id}/{resource}')), 200
    body = request.get_json(silent=True) or []
    if isinstance(body, str):
        body = [body]
    if method == 'POST':
        store.setdefault(site_id, []).extend(body)
        return jsonify({'status': 200, 'message': f'Added {len(body)} {resource}'}), 200
    if method == 'DELETE':
        store[site_id] = [t for t in store.get(site_id, []) if t not in body]
        return jsonify({'status': 200, 'message': f'Removed {len(body)} {resource}'}), 200


@sites_bp.route('/<int:site_id>/included_targets', methods=['GET', 'POST', 'DELETE'])
@require_basic_auth
def included_targets(site_id):
    return _targets_endpoint(_INCLUDED_TARGETS, 'targets', site_id, request.method, 'included_targets')


@sites_bp.route('/<int:site_id>/excluded_targets', methods=['GET', 'POST', 'DELETE'])
@require_basic_auth
def excluded_targets(site_id):
    return _targets_endpoint(_EXCLUDED_TARGETS, 'targets', site_id, request.method, 'excluded_targets')


@sites_bp.route('/<int:site_id>/included_asset_groups', methods=['GET', 'POST', 'DELETE'])
@require_basic_auth
def included_groups(site_id):
    return _targets_endpoint(_INCLUDED_GROUPS, 'groups', site_id, request.method, 'included_asset_groups')


@sites_bp.route('/<int:site_id>/excluded_asset_groups', methods=['GET', 'POST', 'DELETE'])
@require_basic_auth
def excluded_groups(site_id):
    return _targets_endpoint(_EXCLUDED_GROUPS, 'groups', site_id, request.method, 'excluded_asset_groups')

"""
Asset group endpoints.
  GET/POST /api/3/asset_groups
  GET/PUT/DELETE /api/3/asset_groups/<id>
"""
from flask import Blueprint, jsonify, request

from auth import require_basic_auth
from generators.base import created_response, page_envelope

from ._helpers import get_pagination


asset_groups_bp = Blueprint('asset_groups', __name__, url_prefix='/api/3/asset_groups')


_STORE: dict[int, dict] = {}
_NEXT_ID = 400


for _i, _name in enumerate(['Corporate Windows', 'Corporate Linux', 'PCI-scoped', 'Cloud Servers'], start=1):
    _NEXT_ID += 1
    _STORE[_NEXT_ID] = {
        'id': _NEXT_ID,
        'name': _name,
        'description': f'Auto-populated group: {_name}',
        'type': 'dynamic',
        'assets': 5,
        'riskScore': 5000.0,
        'searchCriteria': {'match': 'all', 'filters': [{'field': 'os', 'operator': 'contains', 'value': 'Windows'}]},
        'links': [{'href': f'/api/3/asset_groups/{_NEXT_ID}', 'rel': 'self'}],
    }


@asset_groups_bp.route('', methods=['GET'])
@require_basic_auth
def list_asset_groups():
    page, size = get_pagination()
    return jsonify(page_envelope(list(_STORE.values()), page, size, '/api/3/asset_groups')), 200


@asset_groups_bp.route('', methods=['POST'])
@require_basic_auth
def create_asset_group():
    global _NEXT_ID
    body = request.get_json(silent=True) or {}
    _NEXT_ID += 1
    _STORE[_NEXT_ID] = {
        'id': _NEXT_ID,
        'name': body.get('name') or f'Group {_NEXT_ID}',
        'description': body.get('description') or '',
        'type': body.get('type') or 'static',
        'assets': 0,
        'riskScore': 0.0,
        'searchCriteria': body.get('searchCriteria'),
        'links': [{'href': f'/api/3/asset_groups/{_NEXT_ID}', 'rel': 'self'}],
    }
    return jsonify(created_response(_NEXT_ID)), 201


@asset_groups_bp.route('/<int:group_id>', methods=['GET'])
@require_basic_auth
def get_asset_group(group_id):
    g = _STORE.get(group_id)
    if g is None:
        return jsonify({'status': 404, 'message': f'Asset group {group_id} not found'}), 404
    return jsonify(g), 200


@asset_groups_bp.route('/<int:group_id>', methods=['PUT'])
@require_basic_auth
def update_asset_group(group_id):
    g = _STORE.get(group_id)
    if g is None:
        return jsonify({'status': 404, 'message': f'Asset group {group_id} not found'}), 404
    g.update(request.get_json(silent=True) or {})
    return jsonify({'status': 200, 'message': 'Asset group updated'}), 200


@asset_groups_bp.route('/<int:group_id>', methods=['DELETE'])
@require_basic_auth
def delete_asset_group(group_id):
    if _STORE.pop(group_id, None) is None:
        return jsonify({'status': 404, 'message': f'Asset group {group_id} not found'}), 404
    return jsonify({'status': 200, 'message': 'Asset group deleted'}), 200

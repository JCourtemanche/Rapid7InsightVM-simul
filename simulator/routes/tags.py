"""
Tag endpoints.
  GET/POST /api/3/tags
  GET/PUT/DELETE /api/3/tags/<id>
  PUT /api/3/tags/<id>/search_criteria
  GET/POST/DELETE /api/3/tags/<id>/assets
  GET/POST/DELETE /api/3/tags/<id>/asset_groups
"""
from flask import Blueprint, jsonify, request

from auth import require_basic_auth
from generators.base import created_response, page_envelope

from ._helpers import get_pagination


tags_bp = Blueprint('tags', __name__, url_prefix='/api/3/tags')


_STORE: dict[int, dict] = {}
_TAG_ASSETS: dict[int, list] = {}
_TAG_GROUPS: dict[int, list] = {}
_NEXT_ID = 300


for _i, (_name, _type) in enumerate([
    ('Business Corp', 'custom'),
    ('PCI', 'custom'),
    ('Critical', 'criticality'),
    ('Paris', 'location'),
    ('Web Servers', 'custom'),
], start=1):
    _NEXT_ID += 1
    _STORE[_NEXT_ID] = {
        'id': _NEXT_ID,
        'name': _name,
        'type': _type,
        'color': 'red' if _type == 'criticality' else 'blue',
        'searchCriteria': None,
        'links': [{'href': f'/api/3/tags/{_NEXT_ID}', 'rel': 'self'}],
    }


@tags_bp.route('', methods=['GET'])
@require_basic_auth
def list_tags():
    page, size = get_pagination()
    return jsonify(page_envelope(list(_STORE.values()), page, size, '/api/3/tags')), 200


@tags_bp.route('', methods=['POST'])
@require_basic_auth
def create_tag():
    global _NEXT_ID
    body = request.get_json(silent=True) or {}
    _NEXT_ID += 1
    _STORE[_NEXT_ID] = {
        'id': _NEXT_ID,
        'name': body.get('name') or f'Tag {_NEXT_ID}',
        'type': body.get('type') or 'custom',
        'color': body.get('color') or 'blue',
        'searchCriteria': body.get('searchCriteria'),
        'links': [{'href': f'/api/3/tags/{_NEXT_ID}', 'rel': 'self'}],
    }
    return jsonify(created_response(_NEXT_ID)), 201


@tags_bp.route('/<int:tag_id>', methods=['GET'])
@require_basic_auth
def get_tag(tag_id):
    t = _STORE.get(tag_id)
    if t is None:
        return jsonify({'status': 404, 'message': f'Tag {tag_id} not found'}), 404
    return jsonify(t), 200


@tags_bp.route('/<int:tag_id>', methods=['PUT'])
@require_basic_auth
def update_tag(tag_id):
    t = _STORE.get(tag_id)
    if t is None:
        return jsonify({'status': 404, 'message': f'Tag {tag_id} not found'}), 404
    t.update(request.get_json(silent=True) or {})
    return jsonify({'status': 200, 'message': 'Tag updated'}), 200


@tags_bp.route('/<int:tag_id>', methods=['DELETE'])
@require_basic_auth
def delete_tag(tag_id):
    if _STORE.pop(tag_id, None) is None:
        return jsonify({'status': 404, 'message': f'Tag {tag_id} not found'}), 404
    return jsonify({'status': 200, 'message': 'Tag deleted'}), 200


@tags_bp.route('/<int:tag_id>/search_criteria', methods=['PUT'])
@require_basic_auth
def update_search_criteria(tag_id):
    t = _STORE.get(tag_id)
    if t is None:
        return jsonify({'status': 404, 'message': f'Tag {tag_id} not found'}), 404
    t['searchCriteria'] = request.get_json(silent=True) or {}
    return jsonify({'status': 200, 'message': 'Search criteria updated'}), 200


def _members(store, tag_id, method, resource):
    if method == 'GET':
        items = [{'id': m} for m in store.get(tag_id, [])]
        page, size = get_pagination()
        return jsonify(page_envelope(items, page, size, f'/api/3/tags/{tag_id}/{resource}')), 200
    body = request.get_json(silent=True) or []
    if isinstance(body, (int, str)):
        body = [body]
    ids = [int(x) for x in body]
    if method == 'POST':
        for i in ids:
            if i not in store.setdefault(tag_id, []):
                store[tag_id].append(i)
        return jsonify({'status': 200, 'message': f'Added {len(ids)} {resource} to tag {tag_id}'}), 200
    if method == 'DELETE':
        store[tag_id] = [x for x in store.get(tag_id, []) if x not in ids]
        return jsonify({'status': 200, 'message': f'Removed {len(ids)} {resource} from tag {tag_id}'}), 200


@tags_bp.route('/<int:tag_id>/assets', methods=['GET', 'POST', 'DELETE'])
@require_basic_auth
def tag_assets(tag_id):
    return _members(_TAG_ASSETS, tag_id, request.method, 'assets')


@tags_bp.route('/<int:tag_id>/asset_groups', methods=['GET', 'POST', 'DELETE'])
@require_basic_auth
def tag_asset_groups(tag_id):
    return _members(_TAG_GROUPS, tag_id, request.method, 'asset_groups')


@tags_bp.route('/<int:tag_id>/assets/<int:asset_id>', methods=['PUT', 'DELETE'])
@require_basic_auth
def tag_single_asset(tag_id, asset_id):
    if request.method == 'PUT':
        if asset_id not in _TAG_ASSETS.setdefault(tag_id, []):
            _TAG_ASSETS[tag_id].append(asset_id)
        return jsonify({'status': 200, 'message': f'Asset {asset_id} added to tag {tag_id}'}), 200
    _TAG_ASSETS[tag_id] = [a for a in _TAG_ASSETS.get(tag_id, []) if a != asset_id]
    return jsonify({'status': 200, 'message': f'Asset {asset_id} removed from tag {tag_id}'}), 200


@tags_bp.route('/<int:tag_id>/asset_groups/<int:group_id>', methods=['PUT', 'DELETE'])
@require_basic_auth
def tag_single_group(tag_id, group_id):
    if request.method == 'PUT':
        if group_id not in _TAG_GROUPS.setdefault(tag_id, []):
            _TAG_GROUPS[tag_id].append(group_id)
        return jsonify({'status': 200, 'message': f'Asset group {group_id} added to tag {tag_id}'}), 200
    _TAG_GROUPS[tag_id] = [g for g in _TAG_GROUPS.get(tag_id, []) if g != group_id]
    return jsonify({'status': 200, 'message': f'Asset group {group_id} removed from tag {tag_id}'}), 200

"""
Shared credential endpoints.
  GET/POST /api/3/shared_credentials
  GET/PUT/DELETE /api/3/shared_credentials/<id>
"""
from flask import Blueprint, jsonify, request

from auth import require_basic_auth
from generators.base import created_response, page_envelope

from ._helpers import get_pagination


shared_creds_bp = Blueprint('shared_creds', __name__, url_prefix='/api/3/shared_credentials')


_STORE: dict[int, dict] = {}
_NEXT_ID = 900


def _seed():
    global _NEXT_ID
    for i, (name, service, username) in enumerate([
        ('Domain Admin',   'cifs',  'BUSINESS\\Administrator'),
        ('Linux Root',     'ssh',   'root'),
        ('Postgres Admin', 'postgres', 'postgres'),
    ], start=1):
        cid = _NEXT_ID + i
        _STORE[cid] = {
            'id': cid,
            'name': name,
            'description': f'Shared {service} credential',
            'account': {'service': service, 'username': username},
            'enabled': True,
            'sites': [1, 2, 3],
            'links': [{'href': f'/api/3/shared_credentials/{cid}', 'rel': 'self'}],
        }
    _NEXT_ID = max(_STORE)


_seed()


@shared_creds_bp.route('', methods=['GET'])
@require_basic_auth
def list_shared():
    page, size = get_pagination()
    return jsonify(page_envelope(list(_STORE.values()), page, size, '/api/3/shared_credentials')), 200


@shared_creds_bp.route('', methods=['POST'])
@require_basic_auth
def create_shared():
    global _NEXT_ID
    body = request.get_json(silent=True) or {}
    _NEXT_ID += 1
    cid = _NEXT_ID
    _STORE[cid] = {
        'id': cid,
        'name': body.get('name') or f'Shared cred {cid}',
        'description': body.get('description') or '',
        'account': body.get('account') or {'service': 'ssh', 'username': 'user'},
        'enabled': True,
        'sites': body.get('sites') or [],
        'links': [{'href': f'/api/3/shared_credentials/{cid}', 'rel': 'self'}],
    }
    return jsonify(created_response(cid)), 201


@shared_creds_bp.route('/<int:cred_id>', methods=['GET'])
@require_basic_auth
def get_shared(cred_id):
    c = _STORE.get(cred_id)
    if c is None:
        return jsonify({'status': 404, 'message': f'Shared credential {cred_id} not found'}), 404
    return jsonify(c), 200


@shared_creds_bp.route('/<int:cred_id>', methods=['PUT'])
@require_basic_auth
def update_shared(cred_id):
    c = _STORE.get(cred_id)
    if c is None:
        return jsonify({'status': 404, 'message': f'Shared credential {cred_id} not found'}), 404
    c.update(request.get_json(silent=True) or {})
    return jsonify({'status': 200, 'message': 'Shared credential updated'}), 200


@shared_creds_bp.route('/<int:cred_id>', methods=['DELETE'])
@require_basic_auth
def delete_shared(cred_id):
    if _STORE.pop(cred_id, None) is None:
        return jsonify({'status': 404, 'message': f'Shared credential {cred_id} not found'}), 404
    return jsonify({'status': 200, 'message': 'Shared credential deleted'}), 200
